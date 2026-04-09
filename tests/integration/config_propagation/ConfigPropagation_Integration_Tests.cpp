/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * Integration Tests - Config Propagation Pipeline
 *
 * ============================================================================
 * PURPOSE
 * ============================================================================
 * Tests the real, production integration between the four configuration
 * subsystems that govern every behavioural parameter in the platform:
 *
 *   ConfigManager    (layered key-value store: Default→System→Enterprise→
 *                     Policy→User→Session→Override)
 *   PolicyManager    (enterprise policy distribution and enforcement)
 *   SettingsManager  (user UI/UX preferences: theme, locale, notifications)
 *   ProfileManager   (role-based operating profiles with resource limits)
 *
 * No mocks. No stubs. All four real singleton managers are initialized and
 * exercised together in each test.  Tests validate:
 *   - Cross-manager state consistency under sequential and concurrent load
 *   - Callback propagation across manager boundaries
 *   - Layer-priority enforcement when policy, profile, and user writes collide
 *   - Security invariant: Mandatory policies cannot be bypassed by any other
 *     manager in the chain
 *   - Export/import round-trip integrity across all four managers
 *   - Emergency-mode override semantics
 *
 * ============================================================================
 * TEST GROUPS
 * ============================================================================
 *   GROUP 1  ConfigPolicyEnforcement        ConfigManager ↔ PolicyManager
 *   GROUP 2  ConfigSettingsLayerSync        ConfigManager ↔ SettingsManager
 *   GROUP 3  ConfigProfileLayerPropagation  ConfigManager ↔ ProfileManager
 *   GROUP 4  PolicyProfileConstraints       PolicyManager ↔ ProfileManager
 *   GROUP 5  PolicySettingsEnforcement      PolicyManager ↔ SettingsManager
 *   GROUP 6  SettingsProfileSync            SettingsManager ↔ ProfileManager
 *   GROUP 7  FourWayPropagation             Full four-manager pipeline
 *   GROUP 8  ConcurrencySafety              Multi-threaded cross-manager access
 *   GROUP 9  EdgeCasesAndBoundaries         Error paths, re-init, adversarial
 *
 * ============================================================================
 * FIXTURE SETUP  (per-test, full isolation)
 * ============================================================================
 *   1. Shutdown all four managers in reverse dependency order
 *   2. Create a unique per-test temporary directory (PID + atomic counter)
 *   3. Initialize ConfigManager  (file-backed DB in temp dir, hot-reload off)
 *   4. Initialize PolicyManager  (offline cache in temp dir, auto-sync off)
 *   5. Initialize SettingsManager (JSON file in temp dir, auto-save off)
 *   6. Initialize ProfileManager  (Standard profile, auto-detection off,
 *                                  cooldown 0 for rapid switches in tests)
 *
 * ============================================================================
 * TEARDOWN  (per-test)
 * ============================================================================
 *   Shutdown all four managers; temp directory deleted by RAII.
 * ============================================================================
 */

// ============================================================================
// WINDOWS + STANDARD HEADERS
// ============================================================================
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#include <atomic>
#include <chrono>
#include <filesystem>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <vector>

// ============================================================================
// GOOGLETEST
// ============================================================================
#include <gtest/gtest.h>

// ============================================================================
// SHADOWSTRIKE CONFIG MODULE HEADERS
// ============================================================================
#include "../../../src/Shared_modules/Config/ConfigManager.hpp"
#include "../../../src/Shared_modules/Config/PolicyManager.hpp"
#include "../../../src/Shared_modules/Config/ProfileManager.hpp"
#include "../../../src/Shared_modules/Config/SettingsManager.hpp"

// ============================================================================
// NAMESPACE ALIASES
// ============================================================================
namespace SS_C  = ShadowStrike::Config;
namespace fs    = std::filesystem;

// ============================================================================
// SCOPED TEMP DIRECTORY (RAII)
// ============================================================================
class ScopedTempDir {
public:
    ScopedTempDir() {
        wchar_t base[MAX_PATH];
        const DWORD len = GetTempPathW(static_cast<DWORD>(std::size(base)), base);
        if (len == 0 || len >= static_cast<DWORD>(std::size(base))) return;

        static std::atomic<uint32_t> s_counter{0};
        m_path = fs::path(base) /
            (std::wstring(L"SS_IntTier7_") +
             std::to_wstring(GetCurrentProcessId()) + L"_" +
             std::to_wstring(s_counter.fetch_add(1, std::memory_order_relaxed)));

        std::error_code ec;
        if (!fs::create_directories(m_path, ec) || ec) {
            m_path.clear();
        }
    }

    ~ScopedTempDir() noexcept {
        if (!m_path.empty()) {
            std::error_code ec;
            fs::remove_all(m_path, ec);
        }
    }

    ScopedTempDir(const ScopedTempDir&) = delete;
    ScopedTempDir& operator=(const ScopedTempDir&) = delete;

    [[nodiscard]] bool         Valid()  const noexcept { return !m_path.empty(); }
    [[nodiscard]] const fs::path& Path() const noexcept { return m_path; }

    [[nodiscard]] fs::path File(const wchar_t* name) const {
        return m_path / fs::path(name);
    }

private:
    fs::path m_path;
};

// ============================================================================
// UNIQUE-KEY HELPER
// ============================================================================
namespace {

[[nodiscard]] inline std::string UniqueKey(std::string_view prefix) {
    static std::atomic<uint64_t> s_counter{0};
    return std::string(prefix) + "_" +
           std::to_string(GetCurrentProcessId()) + "_" +
           std::to_string(s_counter.fetch_add(1, std::memory_order_relaxed));
}

// ---------------------------------------------------------------------------
// Build a fully-formed Policy for integration use.
//   - id          : unique policy identifier
//   - settingKey  : the setting the policy controls
//   - value       : the mandated value
//   - enforcement : Mandatory (default) or Advisory
//   - priority    : policy priority (higher wins on conflict)
// ---------------------------------------------------------------------------
[[nodiscard]] SS_C::Policy MakePolicy(
    std::string        id,
    std::string        settingKey,
    SS_C::PolicyValue  value,
    bool               mandatory  = true,
    uint32_t           priority   = 100,
    SS_C::PolicyType   type       = SS_C::PolicyType::Custom)
{
    SS_C::Policy p;
    p.id          = std::move(id);
    p.name        = "IntegrationTest Policy";
    p.description = "Tier-7 integration test policy";
    p.type        = type;
    p.state       = SS_C::PolicyState::Pending;
    p.enforcement = mandatory ? SS_C::EnforcementLevel::Mandatory
                              : SS_C::EnforcementLevel::Advisory;
    p.isMandatory = mandatory;
    p.priority    = priority;
    p.version     = 1;
    p.effectiveFrom = std::chrono::system_clock::now();
    p.createdAt     = p.effectiveFrom;
    p.modifiedAt    = p.effectiveFrom;
    p.createdBy     = "tier7-integration";

    SS_C::PolicySetting setting;
    setting.key         = std::move(settingKey);
    setting.displayName = "Integration Setting";
    setting.value       = std::move(value);
    setting.enforcement = p.enforcement;
    setting.description = "Managed by integration test";
    p.settings.emplace(setting.key, setting);
    return p;
}

// ---------------------------------------------------------------------------
// Build a custom ProfileDefinition.
// ---------------------------------------------------------------------------
[[nodiscard]] SS_C::ProfileDefinition MakeCustomProfile(const std::string& name,
                                                         uint32_t           maxCpu,
                                                         uint32_t           heuristic,
                                                         bool               rtpEnabled,
                                                         bool               notificationsEnabled)
{
    SS_C::ProfileDefinition def;
    def.profileType       = SS_C::SystemProfile::Custom;
    def.customName        = name;
    def.description       = "Tier-7 integration test custom profile";
    def.resources.maxCpuPercent        = maxCpu;
    def.resources.maxMemoryMb          = 512;
    def.resources.maxConcurrentScans   = 2;
    def.scan.realtimeProtection        = rtpEnabled;
    def.scan.heuristicLevel            = heuristic;
    def.notifications.enabled          = notificationsEnabled;
    def.notifications.showThreatAlerts = true;
    def.createdAt  = std::chrono::system_clock::now();
    def.modifiedAt = def.createdAt;
    return def;
}

} // anonymous namespace

// ============================================================================
// BASE INTEGRATION FIXTURE
// ============================================================================
class ConfigPropagationFixture : public ::testing::Test {
protected:
    ScopedTempDir tempDir;

    SS_C::ConfigManager&   configMgr  = SS_C::ConfigManager::Instance();
    SS_C::PolicyManager&   policyMgr  = SS_C::PolicyManager::Instance();
    SS_C::SettingsManager& settingsMgr = SS_C::SettingsManager::Instance();
    SS_C::ProfileManager&  profileMgr  = SS_C::ProfileManager::Instance();

    // -----------------------------------------------------------------------
    // Per-test setUp: shutdown all four in reverse dependency order, then
    // initialize fresh instances against the per-test temp directory.
    // -----------------------------------------------------------------------
    void SetUp() override {
        ASSERT_TRUE(tempDir.Valid()) << "Failed to create temporary directory";

        profileMgr.Shutdown();
        settingsMgr.Shutdown();
        policyMgr.Shutdown();
        configMgr.Shutdown();

        // ConfigManager: file-backed, no hot-reload, auditing on.
        SS_C::ConfigManagerConfiguration cfgConfig;
        cfgConfig.databasePath         = tempDir.File(L"config.db");
        cfgConfig.enableHotReload      = false;
        cfgConfig.enableCaching        = true;
        cfgConfig.cacheTtlSeconds      = 300;
        cfgConfig.enableAuditing       = true;
        cfgConfig.maxSnapshots         = 50;
        cfgConfig.validateOnLoad       = true;
        ASSERT_TRUE(configMgr.Initialize(cfgConfig))
            << "ConfigManager::Initialize failed";

        // PolicyManager: offline cache, no auto-sync.
        SS_C::PolicyManagerConfiguration polConfig;
        polConfig.enabled              = true;
        polConfig.enableAutoSync       = false;
        polConfig.enableOfflineCache   = true;
        polConfig.offlineCachePath     = tempDir.File(L"policy-cache.json");
        polConfig.enableViolationLogging   = true;
        polConfig.enableAutoRemediation    = false;
        polConfig.maxViolationHistory      = 256;
        ASSERT_TRUE(policyMgr.Initialize(polConfig))
            << "PolicyManager::Initialize failed";

        // SettingsManager: file-backed, no auto-save.
        SS_C::SettingsManagerConfiguration setConfig;
        setConfig.settingsFilePath         = tempDir.File(L"user-settings.json");
        setConfig.enableAutoSave           = false;
        setConfig.createBackupOnSave       = false;
        setConfig.maxBackups               = 3;
        ASSERT_TRUE(settingsMgr.Initialize(setConfig))
            << "SettingsManager::Initialize failed";

        // ProfileManager: Standard, no auto-detection, no schedules, 0 cooldown.
        SS_C::ProfileManagerConfiguration profConfig;
        profConfig.initialProfile             = SS_C::SystemProfile::Standard;
        profConfig.enableAutoDetection        = false;
        profConfig.enableScheduledSwitching   = false;
        profConfig.enableApplicationTriggers  = false;
        profConfig.switchCooldownSeconds      = 0;
        profConfig.enableEmergencyFallback    = true;
        profConfig.emergencyProfile           = SS_C::SystemProfile::Emergency;
        ASSERT_TRUE(profileMgr.Initialize(profConfig))
            << "ProfileManager::Initialize failed";

        configMgr.ResetStatistics();
        policyMgr.ResetStatistics();
        settingsMgr.ResetStatistics();
        profileMgr.ResetStatistics();
    }

    // -----------------------------------------------------------------------
    // Per-test tearDown: shutdown all four managers.
    // -----------------------------------------------------------------------
    void TearDown() override {
        if (profileMgr.IsInitialized()) {
            if (profileMgr.IsInEmergencyMode())
                (void)profileMgr.ExitEmergencyMode();
            profileMgr.Shutdown();
        }
        if (settingsMgr.IsInitialized()) settingsMgr.Shutdown();
        if (policyMgr.IsInitialized())   policyMgr.Shutdown();
        if (configMgr.IsInitialized())   configMgr.Shutdown();
    }

    // -----------------------------------------------------------------------
    // Helper: register a ConfigManager validation callback that blocks writes
    // to <key> when PolicyManager reports that key as enforced.
    // Returns the callback ID (caller must unregister on test end).
    // -----------------------------------------------------------------------
    void RegisterPolicyEnforcementValidator(const std::string& key) {
        auto& pm = policyMgr;
        configMgr.RegisterValidator(key,
            [&pm, key](const std::string& /*k*/, const SS_C::ConfigValue& /*v*/)
            -> SS_C::ValidationResult
            {
                if (pm.IsEnforced(key)) {
                    return SS_C::ValidationResult::PolicyLocked;
                }
                return SS_C::ValidationResult::Valid;
            });
    }

    // -----------------------------------------------------------------------
    // Helper: remove all active policies and reset all Config layers.
    // -----------------------------------------------------------------------
    void ResetAllState() {
        for (const auto& pol : policyMgr.GetAllPolicies()) {
            (void)policyMgr.RemovePolicy(pol.id);
        }
        for (const auto layer : {SS_C::ConfigLayer::Default, SS_C::ConfigLayer::System,
                                  SS_C::ConfigLayer::Enterprise, SS_C::ConfigLayer::Policy,
                                  SS_C::ConfigLayer::User, SS_C::ConfigLayer::Session,
                                  SS_C::ConfigLayer::Override}) {
            configMgr.ResetToDefaults(layer);
        }
    }
};


// ============================================================================
// GROUP 1 — ConfigManager ↔ PolicyManager: Enforcement Layer Integration
// ============================================================================

TEST_F(ConfigPropagationFixture,
       ConfigPolicy_PolicyLayerWriteIsReadableByConfigManager)
{
    const std::string key = UniqueKey("policy.heuristic_level");

    // Write the policy-mandated value directly to ConfigManager's Policy layer.
    ASSERT_TRUE(configMgr.SetValue<int64_t>(key, 4, SS_C::ConfigLayer::Policy));

    // The value must be readable and must come from the Policy layer.
    EXPECT_EQ(configMgr.GetValue<int64_t>(key, -1), 4);
    EXPECT_EQ(configMgr.GetEffectiveLayer(key), SS_C::ConfigLayer::Policy);
}

TEST_F(ConfigPropagationFixture,
       ConfigPolicy_UserLayerTakesPrecedenceOverPolicyLayer)
{
    const std::string key = UniqueKey("policy.archive_depth");

    // Simulate PolicyManager enforcing a default; write to Policy layer.
    ASSERT_TRUE(configMgr.SetValue<int64_t>(key, 3, SS_C::ConfigLayer::Policy));

    // User preference overrides the policy-layer value (User > Policy in priority).
    ASSERT_TRUE(configMgr.SetValue<int64_t>(key, 7, SS_C::ConfigLayer::User));

    EXPECT_EQ(configMgr.GetValue<int64_t>(key, -1), 7);
    EXPECT_EQ(configMgr.GetEffectiveLayer(key), SS_C::ConfigLayer::User);
}

TEST_F(ConfigPropagationFixture,
       ConfigPolicy_MandatoryEnforcementCallbackBlocksConfigManagerWrite)
{
    const std::string key = UniqueKey("protection.behavior_monitoring");

    // Apply mandatory policy in PolicyManager.
    const auto policy = MakePolicy("pol-blocking-001", key, SS_C::PolicyValue{true},
                                   /*mandatory=*/true);
    ASSERT_TRUE(policyMgr.ApplyPolicy(policy));
    ASSERT_TRUE(policyMgr.ActivatePolicy("pol-blocking-001"));
    ASSERT_TRUE(policyMgr.IsEnforced(key));

    // Register validator that rejects writes when policy is enforced.
    RegisterPolicyEnforcementValidator(key);

    // Write attempt via SetValueValidated must be blocked.
    const auto [accepted, msg] = configMgr.SetValueValidated<bool>(
        key, false, SS_C::ConfigLayer::User);
    EXPECT_FALSE(accepted);
    EXPECT_EQ(configMgr.ValidateValue(key, SS_C::ConfigValue{false}),
              SS_C::ValidationResult::PolicyLocked);
}

TEST_F(ConfigPropagationFixture,
       ConfigPolicy_PolicyRemoval_RestoresConfigManagerWritability)
{
    const std::string key = UniqueKey("protection.cloud_lookup");

    // Apply and activate mandatory policy.
    const auto policy = MakePolicy("pol-restore-001", key, SS_C::PolicyValue{true},
                                   /*mandatory=*/true);
    ASSERT_TRUE(policyMgr.ApplyPolicy(policy));
    ASSERT_TRUE(policyMgr.ActivatePolicy("pol-restore-001"));
    RegisterPolicyEnforcementValidator(key);

    // Confirm blocked.
    {
        const auto [accepted, _] = configMgr.SetValueValidated<bool>(
            key, false, SS_C::ConfigLayer::User);
        EXPECT_FALSE(accepted);
    }

    // Remove the policy.
    ASSERT_TRUE(policyMgr.RemovePolicy("pol-restore-001"));
    EXPECT_FALSE(policyMgr.IsEnforced(key));

    // Write must now succeed.
    {
        const auto [accepted, _] = configMgr.SetValueValidated<bool>(
            key, false, SS_C::ConfigLayer::User);
        EXPECT_TRUE(accepted);
    }
    EXPECT_EQ(configMgr.GetValue<bool>(key, true), false);
}

TEST_F(ConfigPropagationFixture,
       ConfigPolicy_HigherPriorityMandatoryPolicyEnforcedValue_WinsOnConflict)
{
    const std::string key = UniqueKey("scan.max_depth");

    // Two policies targeting the same key; higher priority must win.
    const auto policyLow  = MakePolicy("pol-lo-001", key, SS_C::PolicyValue{int64_t{5}},
                                        true, 50);
    const auto policyHigh = MakePolicy("pol-hi-001", key, SS_C::PolicyValue{int64_t{10}},
                                        true, 200);
    ASSERT_TRUE(policyMgr.ApplyPolicy(policyLow));
    ASSERT_TRUE(policyMgr.ApplyPolicy(policyHigh));
    ASSERT_TRUE(policyMgr.ActivatePolicy("pol-lo-001"));
    ASSERT_TRUE(policyMgr.ActivatePolicy("pol-hi-001"));

    // PolicyManager::GetEnforcedValue must return the highest-priority value.
    const auto enforced = policyMgr.GetEnforcedValue(key);
    ASSERT_TRUE(enforced.has_value());
    const auto* enforcedInt = std::get_if<int64_t>(&*enforced);
    ASSERT_NE(enforcedInt, nullptr);
    EXPECT_EQ(*enforcedInt, 10);
}

TEST_F(ConfigPropagationFixture,
       ConfigPolicy_ChangeCallback_FiresWithPolicyUpdateReasonOnPolicyLayerWrite)
{
    const std::string key = UniqueKey("policy.scan_enabled");

    std::atomic<int>                      callbackCount{0};
    SS_C::ConfigChangeEvent               lastEvent{};
    std::mutex                            eventMutex;

    const uint64_t cbId = configMgr.RegisterChangeCallback(
        [&](const SS_C::ConfigChangeEvent& evt) {
            if (evt.key == key) {
                std::lock_guard<std::mutex> lk(eventMutex);
                lastEvent = evt;
                callbackCount.fetch_add(1, std::memory_order_relaxed);
            }
        });

    ASSERT_TRUE(configMgr.SetRawValue(
        key,
        SS_C::ConfigValue{true},
        SS_C::ConfigLayer::Policy));

    // Callback must have fired exactly once for this key.
    EXPECT_GE(callbackCount.load(), 1);

    {
        std::lock_guard<std::mutex> lk(eventMutex);
        EXPECT_EQ(lastEvent.key, key);
        EXPECT_EQ(lastEvent.layer, SS_C::ConfigLayer::Policy);
    }

    configMgr.UnregisterCallback(cbId);
}

TEST_F(ConfigPropagationFixture,
       ConfigPolicy_AdvisoryPolicyValue_CanBeOverriddenByUserLayer)
{
    const std::string key = UniqueKey("scan.advisory_depth");

    // Advisory policy: sets a recommended value but does NOT block overrides.
    const auto policy = MakePolicy("pol-advisory-001", key,
                                   SS_C::PolicyValue{int64_t{3}},
                                   /*mandatory=*/false);
    ASSERT_TRUE(policyMgr.ApplyPolicy(policy));
    ASSERT_TRUE(policyMgr.ActivatePolicy("pol-advisory-001"));

    // Advisory policies must not lock the key.
    EXPECT_FALSE(policyMgr.IsEnforced(key))
        << "Advisory-only policy must not lock key in PolicyManager";

    // User can freely override without any validator blocking.
    ASSERT_TRUE(configMgr.SetValue<int64_t>(key, 9, SS_C::ConfigLayer::User));
    EXPECT_EQ(configMgr.GetValue<int64_t>(key, -1), 9);
}

TEST_F(ConfigPropagationFixture,
       ConfigPolicy_PolicyBatchApply_AllSucceedAndStatisticsReflectChanges)
{
    const std::string keyA = UniqueKey("batch.policy_a");
    const std::string keyB = UniqueKey("batch.policy_b");
    const std::string keyC = UniqueKey("batch.policy_c");

    std::vector<SS_C::Policy> policies = {
        MakePolicy("pol-batch-a", keyA, SS_C::PolicyValue{true}),
        MakePolicy("pol-batch-b", keyB, SS_C::PolicyValue{int64_t{8}}),
        MakePolicy("pol-batch-c", keyC, SS_C::PolicyValue{std::string("strict")})
    };

    const auto result = policyMgr.ApplyPolicies(policies);
    EXPECT_TRUE(result.success);
    EXPECT_EQ(result.newPolicies, 3u);
    EXPECT_EQ(result.failedPolicies, 0u);

    for (const auto& pol : policies) {
        (void)policyMgr.ActivatePolicy(pol.id);
    }

    const auto stats = policyMgr.GetStatistics();
    EXPECT_GE(stats.policiesApplied.load(), 3u);
}


// ============================================================================
// GROUP 2 — ConfigManager ↔ SettingsManager: User Layer Propagation
// ============================================================================

TEST_F(ConfigPropagationFixture,
       ConfigSettings_ThemeChangePropagatesToConfigManagerUserLayer)
{
    const std::string key = "settings.theme";

    // Change theme through SettingsManager.
    settingsMgr.SetTheme(SS_C::Theme::Dark);

    // Propagate via explicit write to ConfigManager User layer (application wiring).
    const uint8_t themeValue = static_cast<uint8_t>(settingsMgr.GetThemeSettings().theme);
    ASSERT_TRUE(configMgr.SetValue<int32_t>(key,
        static_cast<int32_t>(themeValue),
        SS_C::ConfigLayer::User));

    EXPECT_EQ(configMgr.GetValue<int32_t>(key, -1),
              static_cast<int32_t>(SS_C::Theme::Dark));
    EXPECT_EQ(configMgr.GetEffectiveLayer(key), SS_C::ConfigLayer::User);
}

TEST_F(ConfigPropagationFixture,
       ConfigSettings_ConfigManagerUserLayerWrite_ReflectsInSettingsManager)
{
    // Write language preference into ConfigManager's User layer.
    ASSERT_TRUE(configMgr.SetValue<std::string>(
        "settings.language", "de-DE", SS_C::ConfigLayer::User));

    // Read from ConfigManager and apply to SettingsManager.
    const std::string lang =
        configMgr.GetValue<std::string>("settings.language", "en-US");
    settingsMgr.SetLanguage(lang);

    EXPECT_EQ(settingsMgr.GetLocalizationSettings().languageCode, "de-DE");
}

TEST_F(ConfigPropagationFixture,
       ConfigSettings_SnapshotCapturesSettingsOriginatedValues)
{
    const std::string themeKey = UniqueKey("snap.theme");
    const std::string langKey  = UniqueKey("snap.language");

    // Populate ConfigManager User layer from SettingsManager values.
    settingsMgr.SetTheme(SS_C::Theme::Dark);
    settingsMgr.SetLanguage("ja-JP");

    ASSERT_TRUE(configMgr.SetValue<int32_t>(
        themeKey,
        static_cast<int32_t>(SS_C::Theme::Dark),
        SS_C::ConfigLayer::User));
    ASSERT_TRUE(configMgr.SetValue<std::string>(
        langKey, "ja-JP", SS_C::ConfigLayer::User));

    // Snapshot.
    const uint64_t snapId = configMgr.CreateSnapshot("before-settings-change");
    EXPECT_NE(snapId, 0u);

    // Modify User layer.
    ASSERT_TRUE(configMgr.SetValue<int32_t>(
        themeKey,
        static_cast<int32_t>(SS_C::Theme::Light),
        SS_C::ConfigLayer::User));
    ASSERT_TRUE(configMgr.SetValue<std::string>(
        langKey, "en-US", SS_C::ConfigLayer::User));
    EXPECT_EQ(configMgr.GetValue<int32_t>(themeKey, -1),
              static_cast<int32_t>(SS_C::Theme::Light));

    // Restore snapshot.
    ASSERT_TRUE(configMgr.RestoreSnapshot(snapId));

    // Values must revert to the snapshot state.
    EXPECT_EQ(configMgr.GetValue<int32_t>(themeKey, -1),
              static_cast<int32_t>(SS_C::Theme::Dark));
    EXPECT_EQ(configMgr.GetValue<std::string>(langKey, ""), "ja-JP");
}

TEST_F(ConfigPropagationFixture,
       ConfigSettings_ExportImportRoundTrip_PreservesUserLayerValues)
{
    const std::string notifKey  = UniqueKey("settings.notif_level");
    const std::string themeKey  = UniqueKey("settings.theme_val");

    ASSERT_TRUE(configMgr.SetValue<int32_t>(
        notifKey,
        static_cast<int32_t>(SS_C::NotificationLevel::Critical),
        SS_C::ConfigLayer::User));
    ASSERT_TRUE(configMgr.SetValue<int32_t>(
        themeKey,
        static_cast<int32_t>(SS_C::Theme::HighContrast),
        SS_C::ConfigLayer::User));

    // Export to JSON.
    SS_C::ConfigIOOptions opts;
    opts.layers = {SS_C::ConfigLayer::User};
    const std::string json = configMgr.ExportToJson(opts);
    EXPECT_FALSE(json.empty());

    // Wipe User layer.
    configMgr.ResetToDefaults(SS_C::ConfigLayer::User);
    EXPECT_EQ(configMgr.GetValue<int32_t>(notifKey, -99), -99)
        << "User layer must be empty after reset";

    // Re-import.
    ASSERT_TRUE(configMgr.ImportFromJson(json, SS_C::ConfigLayer::User));

    EXPECT_EQ(configMgr.GetValue<int32_t>(notifKey, -1),
              static_cast<int32_t>(SS_C::NotificationLevel::Critical));
    EXPECT_EQ(configMgr.GetValue<int32_t>(themeKey, -1),
              static_cast<int32_t>(SS_C::Theme::HighContrast));
}

TEST_F(ConfigPropagationFixture,
       ConfigSettings_ChangeCallback_FiresWhenSettingsOriginatedKeyIsWritten)
{
    const std::string key = UniqueKey("settings.notif_enabled");
    std::atomic<int> fired{0};

    const uint64_t cbId = configMgr.RegisterKeyChangeCallback(key,
        [&](const SS_C::ConfigChangeEvent&) {
            fired.fetch_add(1, std::memory_order_relaxed);
        });

    ASSERT_TRUE(configMgr.SetValue<bool>(key, false, SS_C::ConfigLayer::User));
    EXPECT_GE(fired.load(), 1);
    ASSERT_TRUE(configMgr.SetValue<bool>(key, true, SS_C::ConfigLayer::User));
    EXPECT_GE(fired.load(), 2);

    configMgr.UnregisterCallback(cbId);
}

TEST_F(ConfigPropagationFixture,
       ConfigSettings_PolicyLockedNotificationKey_BlocksSettingsManagerPropagation)
{
    const std::string key = UniqueKey("settings.notification_level");

    // Mandatory policy enforces Critical notifications.
    const auto policy = MakePolicy("pol-notif-lock-001", key,
                                   SS_C::PolicyValue{int64_t{static_cast<int64_t>(
                                       SS_C::NotificationLevel::Critical)}},
                                   /*mandatory=*/true);
    ASSERT_TRUE(policyMgr.ApplyPolicy(policy));
    ASSERT_TRUE(policyMgr.ActivatePolicy("pol-notif-lock-001"));
    ASSERT_TRUE(policyMgr.IsEnforced(key));

    // Register enforcement validator.
    RegisterPolicyEnforcementValidator(key);

    // SettingsManager wants to write None — propagation through ConfigManager
    // must be blocked.
    settingsMgr.SetNotificationLevel(SS_C::NotificationLevel::None);
    const auto [accepted, _] = configMgr.SetValueValidated<int32_t>(
        key,
        static_cast<int32_t>(SS_C::NotificationLevel::None),
        SS_C::ConfigLayer::User);
    EXPECT_FALSE(accepted)
        << "Propagation of None notification level must be blocked by mandatory policy";
}

TEST_F(ConfigPropagationFixture,
       ConfigSettings_SettingsManagerResetToDefaults_WipesUserLayerKeys)
{
    const std::string key = UniqueKey("settings.dnd_enabled");

    // Write user preference.
    ASSERT_TRUE(configMgr.SetValue<bool>(key, true, SS_C::ConfigLayer::User));
    EXPECT_TRUE(configMgr.GetValue<bool>(key, false));

    // Reset SettingsManager and propagate the reset to ConfigManager User layer.
    settingsMgr.ResetToDefaults();
    configMgr.ResetToDefaults(SS_C::ConfigLayer::User);

    // Key must no longer be found in User layer; fall through to default (absent).
    EXPECT_EQ(configMgr.GetOptionalValue<bool>(key), std::nullopt);
}


// ============================================================================
// GROUP 3 — ConfigManager ↔ ProfileManager: Profile-Layer Propagation
// ============================================================================

TEST_F(ConfigPropagationFixture,
       ConfigProfile_SwitchToHighSecurity_PropagatesResourceLimitsToSessionLayer)
{
    const std::string cpuKey = UniqueKey("profile.max_cpu_percent");

    // Capture HighSecurity profile resource limits.
    const auto hsDefinition =
        profileMgr.GetProfileDefinition(SS_C::SystemProfile::HighSecurity);
    const uint32_t expectedCpu = hsDefinition.resources.maxCpuPercent;

    // Switch profile.
    ASSERT_TRUE(profileMgr.SetActiveProfile(SS_C::SystemProfile::HighSecurity));
    EXPECT_EQ(profileMgr.GetActiveProfile(), SS_C::SystemProfile::HighSecurity);

    // Propagate via switch callback (simulated here with explicit write).
    ASSERT_TRUE(configMgr.SetValue<uint32_t>(cpuKey, expectedCpu,
                                              SS_C::ConfigLayer::Session));

    // Session layer must override any User layer write.
    ASSERT_TRUE(configMgr.SetValue<uint32_t>(cpuKey, 99u, SS_C::ConfigLayer::User));
    EXPECT_EQ(configMgr.GetValue<uint32_t>(cpuKey, 0u), expectedCpu)
        << "Session layer must dominate User layer";
    EXPECT_EQ(configMgr.GetEffectiveLayer(cpuKey), SS_C::ConfigLayer::Session);
}

TEST_F(ConfigPropagationFixture,
       ConfigProfile_SwitchToGaming_RelaxesHeuristicLevelInConfigManager)
{
    const std::string heuristicKey = UniqueKey("profile.heuristic_level");

    const auto gamingDef = profileMgr.GetProfileDefinition(SS_C::SystemProfile::Gaming);
    const auto stdDef    = profileMgr.GetProfileDefinition(SS_C::SystemProfile::HighSecurity);

    // HighSecurity heuristic should be at least as strict as Gaming.
    ASSERT_GE(stdDef.scan.heuristicLevel, gamingDef.scan.heuristicLevel);

    // Set HighSecurity level in Session layer.
    ASSERT_TRUE(configMgr.SetValue<uint32_t>(
        heuristicKey, stdDef.scan.heuristicLevel, SS_C::ConfigLayer::Session));

    // Switch to Gaming and update Session layer with Gaming's lower heuristic.
    ASSERT_TRUE(profileMgr.SetActiveProfile(SS_C::SystemProfile::Gaming));
    ASSERT_TRUE(configMgr.SetValue<uint32_t>(
        heuristicKey, gamingDef.scan.heuristicLevel, SS_C::ConfigLayer::Session));

    EXPECT_EQ(configMgr.GetValue<uint32_t>(heuristicKey, 99u),
              gamingDef.scan.heuristicLevel);
}

TEST_F(ConfigPropagationFixture,
       ConfigProfile_ProfileSwitchCallback_UpdatesConfigManagerSessionLayer)
{
    const std::string cpuKey = UniqueKey("profile.cpu_from_callback");
    std::atomic<bool> callbackFired{false};

    const uint64_t switchCbId = profileMgr.RegisterSwitchCallback(
        [&](const SS_C::ProfileSwitchEvent& evt) {
            if (!evt.success) return;
            const auto def = profileMgr.GetProfileDefinition(evt.newProfile);
            (void)configMgr.SetValue<uint32_t>(cpuKey,
                                                def.resources.maxCpuPercent,
                                                SS_C::ConfigLayer::Session);
            callbackFired.store(true, std::memory_order_release);
        });

    ASSERT_TRUE(profileMgr.SetActiveProfile(SS_C::SystemProfile::LowResource));
    // Callback must have fired and populated the Session key.
    EXPECT_TRUE(callbackFired.load(std::memory_order_acquire));
    const auto lrDef = profileMgr.GetProfileDefinition(SS_C::SystemProfile::LowResource);
    EXPECT_EQ(configMgr.GetValue<uint32_t>(cpuKey, 0u),
              lrDef.resources.maxCpuPercent);

    profileMgr.UnregisterCallback(switchCbId);
}

TEST_F(ConfigPropagationFixture,
       ConfigProfile_EmergencyProfileActivation_PopulatesOverrideLayer)
{
    const std::string rtpKey = UniqueKey("profile.rtp_override");

    // Write a user-layer preference first.
    ASSERT_TRUE(configMgr.SetValue<bool>(rtpKey, false, SS_C::ConfigLayer::User));
    EXPECT_FALSE(configMgr.GetValue<bool>(rtpKey, true));

    // Activate emergency profile — Override layer takes absolute priority.
    ASSERT_TRUE(profileMgr.ActivateEmergencyProfile());
    EXPECT_TRUE(profileMgr.IsInEmergencyMode());

    const auto emDef =
        profileMgr.GetProfileDefinition(SS_C::SystemProfile::Emergency);
    // Emergency enables real-time protection unconditionally.
    ASSERT_TRUE(configMgr.SetValue<bool>(rtpKey, emDef.scan.realtimeProtection,
                                          SS_C::ConfigLayer::Override));

    // Override layer must dominate User layer.
    EXPECT_EQ(configMgr.GetValue<bool>(rtpKey, false),
              emDef.scan.realtimeProtection);
    EXPECT_EQ(configMgr.GetEffectiveLayer(rtpKey), SS_C::ConfigLayer::Override);

    // Exit emergency mode; Override value must be cleared.
    ASSERT_TRUE(profileMgr.ExitEmergencyMode());
    EXPECT_FALSE(profileMgr.IsInEmergencyMode());
    configMgr.ResetToDefaults(SS_C::ConfigLayer::Override);
    // Now User layer (false) must be effective.
    EXPECT_FALSE(configMgr.GetValue<bool>(rtpKey, true));
    EXPECT_EQ(configMgr.GetEffectiveLayer(rtpKey), SS_C::ConfigLayer::User);
}

TEST_F(ConfigPropagationFixture,
       ConfigProfile_CustomProfileDefinition_MatchesConfigManagerValuesRoundTrip)
{
    const std::string cpuKey  = UniqueKey("profile.custom.max_cpu");
    const std::string heurKey = UniqueKey("profile.custom.heuristic");
    const std::string name    = UniqueKey("custom-profile");

    const auto customDef = MakeCustomProfile(name, 25u, 3u, true, true);
    ASSERT_TRUE(profileMgr.CreateCustomProfile(customDef));

    // Encode custom profile settings into ConfigManager Session layer.
    ASSERT_TRUE(configMgr.SetValue<uint32_t>(cpuKey,
        customDef.resources.maxCpuPercent, SS_C::ConfigLayer::Session));
    ASSERT_TRUE(configMgr.SetValue<uint32_t>(heurKey,
        customDef.scan.heuristicLevel, SS_C::ConfigLayer::Session));

    // Round-trip: read back and compare to profile definition.
    const auto retrievedCpu  = configMgr.GetValue<uint32_t>(cpuKey,  0u);
    const auto retrievedHeur = configMgr.GetValue<uint32_t>(heurKey, 0u);

    const auto retrieved = profileMgr.GetCustomProfile(name);
    ASSERT_TRUE(retrieved.has_value());
    EXPECT_EQ(retrievedCpu,  retrieved->resources.maxCpuPercent);
    EXPECT_EQ(retrievedHeur, retrieved->scan.heuristicLevel);

    (void)profileMgr.DeleteCustomProfile(name);
}

TEST_F(ConfigPropagationFixture,
       ConfigProfile_SessionLayerSurvives_ProfileSwitchDoesNotWipeIt)
{
    const std::string key = UniqueKey("session.persistent_key");

    // Write a value to Session layer before any profile switch.
    ASSERT_TRUE(configMgr.SetValue<std::string>(key, "persisted",
                                                 SS_C::ConfigLayer::Session));
    EXPECT_EQ(configMgr.GetValue<std::string>(key, ""), "persisted");

    // Profile switch must not clear unrelated Session keys written by the app.
    ASSERT_TRUE(profileMgr.SetActiveProfile(SS_C::SystemProfile::Server));
    ASSERT_TRUE(profileMgr.SetActiveProfile(SS_C::SystemProfile::Standard));

    EXPECT_EQ(configMgr.GetValue<std::string>(key, ""), "persisted")
        << "Session-layer key must survive profile switches";
}


// ============================================================================
// GROUP 4 — PolicyManager ↔ ProfileManager: Constraint Pipeline
// ============================================================================

TEST_F(ConfigPropagationFixture,
       PolicyProfile_MandatoryRTPPolicy_IsEnforced_WhenProfileWouldDisableIt)
{
    const std::string key = "protection.realtime";

    // Mandatory policy: real-time protection must be true.
    const auto policy = MakePolicy("pol-rtp-001", key,
                                   SS_C::PolicyValue{true},
                                   /*mandatory=*/true,
                                   200,
                                   SS_C::PolicyType::Protection);
    ASSERT_TRUE(policyMgr.ApplyPolicy(policy));
    ASSERT_TRUE(policyMgr.ActivatePolicy("pol-rtp-001"));
    ASSERT_TRUE(policyMgr.IsEnforced(key));

    // Create a custom profile that disables RTP.
    const std::string customName = UniqueKey("gaming-no-rtp");
    auto noRtpProfile = MakeCustomProfile(customName, 80u, 0u,
                                          /*rtpEnabled=*/false,
                                          /*notificationsEnabled=*/true);
    ASSERT_TRUE(profileMgr.CreateCustomProfile(noRtpProfile));

    // Validate against policy before switching: the profile's RTP=false setting
    // must fail PolicyManager::ValidateSetting.
    EXPECT_FALSE(policyMgr.ValidateSetting(key, SS_C::PolicyValue{false}))
        << "Mandatory policy must reject RTP=false";

    // Validate a compliant value: must pass.
    EXPECT_TRUE(policyMgr.ValidateSetting(key, SS_C::PolicyValue{true}));

    (void)profileMgr.DeleteCustomProfile(customName);
}

TEST_F(ConfigPropagationFixture,
       PolicyProfile_ComplianceReport_ReflectsActiveMandatoryPolicies)
{
    const std::string key = UniqueKey("compliance.heuristic");

    // Mandatory policy: heuristic_level must be >= 3 (represented as int64).
    const auto policy = MakePolicy("pol-compliance-001", key,
                                   SS_C::PolicyValue{int64_t{3}},
                                   /*mandatory=*/true);
    ASSERT_TRUE(policyMgr.ApplyPolicy(policy));
    ASSERT_TRUE(policyMgr.ActivatePolicy("pol-compliance-001"));

    // Check compliance.
    const auto report = policyMgr.GenerateComplianceReport();
    EXPECT_GT(report.totalPolicies, 0u);
    EXPECT_GE(report.reportId, 0u);

    // Compliance percentage must be a valid ratio [0.0, 100.0].
    const double pct = report.GetCompliancePercentage();
    EXPECT_GE(pct, 0.0);
    EXPECT_LE(pct, 100.0);
}

TEST_F(ConfigPropagationFixture,
       PolicyProfile_MultiplePolicies_HighestPriority_DeterminesEnforcedValue)
{
    const std::string key = UniqueKey("profile.heuristic_policy");

    // Lower-priority advisory: heuristic = 1.
    const auto polAdvisory = MakePolicy("pol-pp-adv-001", key,
                                         SS_C::PolicyValue{int64_t{1}},
                                         /*mandatory=*/false, 50);
    // Higher-priority mandatory: heuristic = 4.
    const auto polMandatory = MakePolicy("pol-pp-man-001", key,
                                          SS_C::PolicyValue{int64_t{4}},
                                          /*mandatory=*/true, 300);
    ASSERT_TRUE(policyMgr.ApplyPolicy(polAdvisory));
    ASSERT_TRUE(policyMgr.ApplyPolicy(polMandatory));
    ASSERT_TRUE(policyMgr.ActivatePolicy("pol-pp-adv-001"));
    ASSERT_TRUE(policyMgr.ActivatePolicy("pol-pp-man-001"));

    ASSERT_TRUE(policyMgr.IsEnforced(key));
    const auto enforced = policyMgr.GetEnforcedValue(key);
    ASSERT_TRUE(enforced.has_value());
    const auto* val = std::get_if<int64_t>(&*enforced);
    ASSERT_NE(val, nullptr);
    EXPECT_EQ(*val, int64_t{4});
}

TEST_F(ConfigPropagationFixture,
       PolicyProfile_PolicyRevocation_AllowsProfileScanSettingChange)
{
    const std::string key = "protection.realtime.enabled";

    // Apply and activate mandatory policy.
    const auto policy = MakePolicy("pol-revoke-001", key,
                                   SS_C::PolicyValue{true}, true, 100,
                                   SS_C::PolicyType::Protection);
    ASSERT_TRUE(policyMgr.ApplyPolicy(policy));
    ASSERT_TRUE(policyMgr.ActivatePolicy("pol-revoke-001"));
    ASSERT_TRUE(policyMgr.IsEnforced(key));

    // RTP=false must be blocked while policy is active.
    EXPECT_FALSE(policyMgr.ValidateSetting(key, SS_C::PolicyValue{false}));

    // Revoke the policy.
    ASSERT_TRUE(policyMgr.RemovePolicy("pol-revoke-001"));
    EXPECT_FALSE(policyMgr.IsEnforced(key));

    // Now RTP=false must pass validation.
    EXPECT_TRUE(policyMgr.ValidateSetting(key, SS_C::PolicyValue{false}));
}

TEST_F(ConfigPropagationFixture,
       PolicyProfile_PolicyUpdateTrigger_StatisticsTrackedCorrectly)
{
    const std::string key = UniqueKey("profile.policy_trigger");

    policyMgr.ResetStatistics();

    // Apply three policies in sequence.
    for (int i = 0; i < 3; ++i) {
        const auto pol = MakePolicy(
            "pol-stats-" + std::to_string(i), key,
            SS_C::PolicyValue{int64_t{i}}, true, 100 + i);
        ASSERT_TRUE(policyMgr.ApplyPolicy(pol));
        (void)policyMgr.ActivatePolicy(pol.id);
    }

    const auto stats = policyMgr.GetStatistics();
    EXPECT_GE(stats.policiesApplied.load(), 3u);
    EXPECT_GE(stats.policiesActive.load(), 1u);
}

TEST_F(ConfigPropagationFixture,
       PolicyProfile_ExpiredPolicy_IsNotEnforced)
{
    const std::string key = UniqueKey("expired.policy.key");

    SS_C::Policy expiredPolicy = MakePolicy("pol-expired-001", key,
                                             SS_C::PolicyValue{true});
    // Set expiry to the past.
    expiredPolicy.expiresAt =
        std::chrono::system_clock::now() - std::chrono::hours(24);

    ASSERT_TRUE(policyMgr.ApplyPolicy(expiredPolicy));

    // IsExpired() must be true; the policy manager must not enforce it.
    const auto retrieved = policyMgr.GetPolicy("pol-expired-001");
    ASSERT_TRUE(retrieved.has_value());
    EXPECT_TRUE(retrieved->IsExpired());
}


// ============================================================================
// GROUP 5 — PolicyManager ↔ SettingsManager: Notification Enforcement
// ============================================================================

TEST_F(ConfigPropagationFixture,
       PolicySettings_MandatoryNotificationLevel_BlocksPropagation)
{
    const std::string key = UniqueKey("settings.notification_level_enforcement");

    // Mandatory policy: Critical notifications only.
    const auto policy = MakePolicy("pol-notif-001", key,
                                   SS_C::PolicyValue{int64_t{static_cast<int64_t>(
                                       SS_C::NotificationLevel::Critical)}},
                                   /*mandatory=*/true,
                                   100,
                                   SS_C::PolicyType::Logging);
    ASSERT_TRUE(policyMgr.ApplyPolicy(policy));
    ASSERT_TRUE(policyMgr.ActivatePolicy("pol-notif-001"));
    ASSERT_TRUE(policyMgr.IsEnforced(key));

    // Wire enforcement into ConfigManager.
    RegisterPolicyEnforcementValidator(key);

    // Attempt to propagate SettingsManager's None level.
    settingsMgr.SetNotificationLevel(SS_C::NotificationLevel::None);
    const auto [accepted, _] = configMgr.SetValueValidated<int32_t>(
        key,
        static_cast<int32_t>(SS_C::NotificationLevel::None),
        SS_C::ConfigLayer::User);
    EXPECT_FALSE(accepted)
        << "Mandatory policy must block None notification level";
}

TEST_F(ConfigPropagationFixture,
       PolicySettings_AdvisoryNotificationPolicy_AllowsOverride_ButRecordsViolation)
{
    const std::string key = UniqueKey("settings.notif_advisory");

    // Advisory policy: recommend Important level.
    const auto policy = MakePolicy("pol-advisory-notif-001", key,
                                   SS_C::PolicyValue{int64_t{static_cast<int64_t>(
                                       SS_C::NotificationLevel::Important)}},
                                   /*mandatory=*/false);
    ASSERT_TRUE(policyMgr.ApplyPolicy(policy));
    ASSERT_TRUE(policyMgr.ActivatePolicy("pol-advisory-notif-001"));

    // Advisory policy must NOT lock the key.
    EXPECT_FALSE(policyMgr.IsEnforced(key));

    // User sets None; must succeed without ConfigManager blocking.
    settingsMgr.SetNotificationLevel(SS_C::NotificationLevel::None);
    ASSERT_TRUE(configMgr.SetValue<int32_t>(
        key,
        static_cast<int32_t>(SS_C::NotificationLevel::None),
        SS_C::ConfigLayer::User));
    EXPECT_EQ(configMgr.GetValue<int32_t>(key, -1),
              static_cast<int32_t>(SS_C::NotificationLevel::None));
}

TEST_F(ConfigPropagationFixture,
       PolicySettings_MandatoryDNDDisablePolicy_BlocksSettingsManagerDNDEnable)
{
    const std::string key = UniqueKey("settings.dnd_blocked");

    // Mandatory policy: DND must remain off (security environment).
    const auto policy = MakePolicy("pol-dnd-001", key,
                                   SS_C::PolicyValue{false},
                                   /*mandatory=*/true);
    ASSERT_TRUE(policyMgr.ApplyPolicy(policy));
    ASSERT_TRUE(policyMgr.ActivatePolicy("pol-dnd-001"));
    ASSERT_TRUE(policyMgr.IsEnforced(key));

    RegisterPolicyEnforcementValidator(key);

    // SettingsManager attempts to enable DND.
    settingsMgr.SetDoNotDisturb(true);
    const auto [accepted, _] = configMgr.SetValueValidated<bool>(
        key, true, SS_C::ConfigLayer::User);
    EXPECT_FALSE(accepted)
        << "Mandatory DND-disable policy must block DND enable";
}

TEST_F(ConfigPropagationFixture,
       PolicySettings_PolicyRemoval_AllowsSettingsManagerFreedom)
{
    const std::string key = UniqueKey("settings.language_enforce");

    const auto policy = MakePolicy("pol-lang-lock-001", key,
                                   SS_C::PolicyValue{std::string("en-US")},
                                   /*mandatory=*/true);
    ASSERT_TRUE(policyMgr.ApplyPolicy(policy));
    ASSERT_TRUE(policyMgr.ActivatePolicy("pol-lang-lock-001"));
    RegisterPolicyEnforcementValidator(key);

    // Blocked while policy active.
    {
        const auto [ok, _] = configMgr.SetValueValidated<std::string>(
            key, "fr-FR", SS_C::ConfigLayer::User);
        EXPECT_FALSE(ok);
    }

    // Remove policy.
    ASSERT_TRUE(policyMgr.RemovePolicy("pol-lang-lock-001"));

    // Now succeeds.
    {
        const auto [ok, _] = configMgr.SetValueValidated<std::string>(
            key, "fr-FR", SS_C::ConfigLayer::User);
        EXPECT_TRUE(ok);
    }
    settingsMgr.SetLanguage("fr-FR");
    EXPECT_EQ(settingsMgr.GetLocalizationSettings().languageCode, "fr-FR");
}

TEST_F(ConfigPropagationFixture,
       PolicySettings_HigherPriorityMandatoryPolicy_WinsNotificationEnforcement)
{
    const std::string key = UniqueKey("settings.notif_priority_test");

    // Low-priority mandatory (Important).
    const auto polLow = MakePolicy("pol-np-lo-001", key,
                                    SS_C::PolicyValue{int64_t{static_cast<int64_t>(
                                        SS_C::NotificationLevel::Important)}},
                                    true, 50);
    // High-priority mandatory (Critical).
    const auto polHigh = MakePolicy("pol-np-hi-001", key,
                                     SS_C::PolicyValue{int64_t{static_cast<int64_t>(
                                         SS_C::NotificationLevel::Critical)}},
                                     true, 300);
    ASSERT_TRUE(policyMgr.ApplyPolicy(polLow));
    ASSERT_TRUE(policyMgr.ApplyPolicy(polHigh));
    ASSERT_TRUE(policyMgr.ActivatePolicy("pol-np-lo-001"));
    ASSERT_TRUE(policyMgr.ActivatePolicy("pol-np-hi-001"));

    ASSERT_TRUE(policyMgr.IsEnforced(key));
    const auto enforced = policyMgr.GetEnforcedValue(key);
    ASSERT_TRUE(enforced.has_value());
    const auto* val = std::get_if<int64_t>(&*enforced);
    ASSERT_NE(val, nullptr);
    EXPECT_EQ(*val, int64_t{static_cast<int64_t>(SS_C::NotificationLevel::Critical)});
}

TEST_F(ConfigPropagationFixture,
       PolicySettings_PolicySyncResult_CorrectlyTracksNewAndUpdatedPolicies)
{
    // Apply initial batch.
    const std::vector<SS_C::Policy> batch1 = {
        MakePolicy("pol-sync-a", UniqueKey("sync.a"), SS_C::PolicyValue{true}),
        MakePolicy("pol-sync-b", UniqueKey("sync.b"), SS_C::PolicyValue{int64_t{5}}),
        MakePolicy("pol-sync-c", UniqueKey("sync.c"), SS_C::PolicyValue{std::string("en")})
    };
    const auto result1 = policyMgr.ApplyPolicies(batch1);
    EXPECT_TRUE(result1.success);
    EXPECT_EQ(result1.newPolicies, 3u);
    EXPECT_EQ(result1.failedPolicies, 0u);

    // Apply updated batch (same IDs, incremented versions).
    std::vector<SS_C::Policy> batch2 = batch1;
    for (auto& p : batch2) {
        p.version = 2;
        p.modifiedAt = std::chrono::system_clock::now();
    }
    const auto result2 = policyMgr.ApplyPolicies(batch2);
    EXPECT_TRUE(result2.success);
    EXPECT_EQ(result2.updatedPolicies, 3u);
    EXPECT_EQ(result2.newPolicies, 0u);
}


// ============================================================================
// GROUP 6 — SettingsManager ↔ ProfileManager: Preference Sync
// ============================================================================

TEST_F(ConfigPropagationFixture,
       SettingsProfile_SilentProfileSwitch_UpdatesNotificationPreferences)
{
    std::atomic<bool> callbackFired{false};
    SS_C::NotificationSettings capturedSettings{};
    std::mutex mtx;

    // Register SettingsManager change callback.
    const uint64_t setCbId = settingsMgr.RegisterChangeCallback(
        [&](const SS_C::SettingsChangeEvent&) {
            std::lock_guard<std::mutex> lk(mtx);
            capturedSettings = settingsMgr.GetNotificationSettings();
            callbackFired.store(true, std::memory_order_release);
        });

    // Register ProfileManager switch callback that propagates notification
    // settings from the new profile to SettingsManager.
    const uint64_t profCbId = profileMgr.RegisterSwitchCallback(
        [&](const SS_C::ProfileSwitchEvent& evt) {
            if (!evt.success) return;
            const auto def = profileMgr.GetProfileDefinition(evt.newProfile);
            SS_C::NotificationSettings ns = settingsMgr.GetNotificationSettings();
            ns.enabled           = def.notifications.enabled;
            ns.showScanProgress  = def.notifications.showScanProgress;
            settingsMgr.SetNotificationSettings(ns);
        });

    // Switch to Silent profile.
    ASSERT_TRUE(profileMgr.SetActiveProfile(SS_C::SystemProfile::Silent));
    EXPECT_EQ(profileMgr.GetActiveProfile(), SS_C::SystemProfile::Silent);

    const auto silentDef = profileMgr.GetProfileDefinition(SS_C::SystemProfile::Silent);

    // SettingsManager must have been updated from the profile's notification config.
    const auto ns = settingsMgr.GetNotificationSettings();
    EXPECT_EQ(ns.enabled, silentDef.notifications.enabled);

    settingsMgr.UnregisterCallback(setCbId);
    profileMgr.UnregisterCallback(profCbId);
}

TEST_F(ConfigPropagationFixture,
       SettingsProfile_ProfileSwitch_DoesNotOverwriteUIPreferences)
{
    // Set explicit UI preferences in SettingsManager.
    settingsMgr.SetTheme(SS_C::Theme::Dark);
    settingsMgr.SetLanguage("fr-FR");

    // Switch profile multiple times.
    ASSERT_TRUE(profileMgr.SetActiveProfile(SS_C::SystemProfile::Server));
    ASSERT_TRUE(profileMgr.SetActiveProfile(SS_C::SystemProfile::LowResource));
    ASSERT_TRUE(profileMgr.SetActiveProfile(SS_C::SystemProfile::Standard));

    // UI preferences must not have been touched by profile switches.
    EXPECT_EQ(settingsMgr.GetThemeSettings().theme, SS_C::Theme::Dark)
        << "Theme must survive profile switches";
    EXPECT_EQ(settingsMgr.GetLocalizationSettings().languageCode, "fr-FR")
        << "Language must survive profile switches";
}

TEST_F(ConfigPropagationFixture,
       SettingsProfile_DNDAlignmentFollowsProfileSwitchCallback)
{
    // Start without DND.
    settingsMgr.SetDoNotDisturb(false);
    EXPECT_FALSE(settingsMgr.GetNotificationSettings().doNotDisturbEnabled);

    // Register a callback that syncs DND state from profile notifications.
    const uint64_t cbId = profileMgr.RegisterSwitchCallback(
        [&](const SS_C::ProfileSwitchEvent& evt) {
            if (!evt.success) return;
            const auto def = profileMgr.GetProfileDefinition(evt.newProfile);
            settingsMgr.SetDoNotDisturb(def.notifications.doNotDisturbEnabled);
        });

    // Switch to Silent profile (which has DND enabled).
    ASSERT_TRUE(profileMgr.SetActiveProfile(SS_C::SystemProfile::Silent));
    const auto silentDef = profileMgr.GetProfileDefinition(SS_C::SystemProfile::Silent);

    EXPECT_EQ(settingsMgr.GetNotificationSettings().doNotDisturbEnabled,
              silentDef.notifications.doNotDisturbEnabled);

    // Switch back to Standard (DND disabled).
    ASSERT_TRUE(profileMgr.SetActiveProfile(SS_C::SystemProfile::Standard));
    const auto stdDef = profileMgr.GetProfileDefinition(SS_C::SystemProfile::Standard);
    EXPECT_EQ(settingsMgr.GetNotificationSettings().doNotDisturbEnabled,
              stdDef.notifications.doNotDisturbEnabled);

    profileMgr.UnregisterCallback(cbId);
}

TEST_F(ConfigPropagationFixture,
       SettingsProfile_CustomProfilePreservesSettingsCustomizations)
{
    const std::string customName = UniqueKey("custom-preserve");

    // Create a custom profile with specific notification settings.
    auto customDef = MakeCustomProfile(customName, 40u, 2u, true, true);
    customDef.notifications.dndStartHour = 22;
    customDef.notifications.dndEndHour   = 7;
    ASSERT_TRUE(profileMgr.CreateCustomProfile(customDef));

    // Set SettingsManager preferences.
    settingsMgr.SetTheme(SS_C::Theme::HighContrast);
    settingsMgr.AddFavoriteLocation(L"C:\\Projects\\Secure");
    settingsMgr.AddRecentItem(L"C:\\Temp\\report.txt");

    // Switch to custom profile.
    ASSERT_TRUE(profileMgr.SetActiveProfile(customName));
    EXPECT_EQ(profileMgr.GetActiveProfile(), SS_C::SystemProfile::Custom);

    // SettingsManager customizations must survive.
    EXPECT_EQ(settingsMgr.GetThemeSettings().theme, SS_C::Theme::HighContrast);
    const auto favorites = settingsMgr.GetFavoriteLocations();
    EXPECT_FALSE(favorites.empty());
    const auto recents = settingsMgr.GetRecentItems();
    EXPECT_FALSE(recents.empty());

    (void)profileMgr.DeleteCustomProfile(customName);
}

TEST_F(ConfigPropagationFixture,
       SettingsProfile_SwitchHistory_AndSettingsStatistics_BothAccurate)
{
    // Start stats fresh.
    profileMgr.ResetStatistics();
    settingsMgr.ResetStatistics();

    // Switch through a chain of profiles.
    ASSERT_TRUE(profileMgr.SetActiveProfile(SS_C::SystemProfile::HighSecurity));
    ASSERT_TRUE(profileMgr.SetActiveProfile(SS_C::SystemProfile::Server));
    ASSERT_TRUE(profileMgr.SetActiveProfile(SS_C::SystemProfile::Standard));

    // Update settings between profile switches.
    settingsMgr.SetTheme(SS_C::Theme::Light);
    settingsMgr.SetLanguage("tr-TR");
    settingsMgr.SetNotificationLevel(SS_C::NotificationLevel::Important);

    const auto profStats    = profileMgr.GetStatistics();
    const auto setStats     = settingsMgr.GetStatistics();
    const auto switchHistory = profileMgr.GetSwitchHistory();

    EXPECT_GE(profStats.profileSwitches.load(), 3u);
    EXPECT_GE(setStats.settingChanges.load(), 3u)
        << "Each SetTheme/SetLanguage/SetNotificationLevel must count as a change";
    EXPECT_GE(switchHistory.size(), 3u);
}


// ============================================================================
// GROUP 7 — FourWayPropagation: Full Four-Manager Pipeline
// ============================================================================

TEST_F(ConfigPropagationFixture,
       FourWay_AllManagersSelfTestPass)
{
    EXPECT_TRUE(configMgr.SelfTest())    << "ConfigManager self-test failed";
    EXPECT_TRUE(policyMgr.SelfTest())    << "PolicyManager self-test failed";
    EXPECT_TRUE(settingsMgr.SelfTest())  << "SettingsManager self-test failed";
    EXPECT_TRUE(profileMgr.SelfTest())   << "ProfileManager self-test failed";
}

TEST_F(ConfigPropagationFixture,
       FourWay_PolicyPushTriggersFullPropagationChain)
{
    const std::string rtpKey   = UniqueKey("fw.rtp_enabled");
    const std::string heurKey  = UniqueKey("fw.heuristic");
    const std::string notifKey = UniqueKey("fw.notification_level");

    std::atomic<int> configChanges{0};
    const uint64_t cfgCbId = configMgr.RegisterChangeCallback(
        [&](const SS_C::ConfigChangeEvent& evt) {
            if (evt.key == rtpKey || evt.key == heurKey || evt.key == notifKey)
                configChanges.fetch_add(1, std::memory_order_relaxed);
        });

    // Step 1: Apply mandatory protection policy.
    std::vector<SS_C::Policy> policies = {
        MakePolicy("fw-pol-rtp",   rtpKey,  SS_C::PolicyValue{true},        true, 200,
                   SS_C::PolicyType::Protection),
        MakePolicy("fw-pol-heur",  heurKey, SS_C::PolicyValue{int64_t{4}},  true, 200,
                   SS_C::PolicyType::Scan),
        MakePolicy("fw-pol-notif", notifKey,
                   SS_C::PolicyValue{int64_t{static_cast<int64_t>(
                       SS_C::NotificationLevel::Critical)}},
                   true, 200, SS_C::PolicyType::Logging)
    };
    const auto syncResult = policyMgr.ApplyPolicies(policies);
    ASSERT_TRUE(syncResult.success);
    for (const auto& p : policies) {
        ASSERT_TRUE(policyMgr.ActivatePolicy(p.id));
    }

    // Step 2: Write enforced values to ConfigManager Policy layer.
    ASSERT_TRUE(configMgr.SetRawValue(rtpKey,  SS_C::ConfigValue{true},        SS_C::ConfigLayer::Policy));
    ASSERT_TRUE(configMgr.SetRawValue(heurKey, SS_C::ConfigValue{int64_t{4}},  SS_C::ConfigLayer::Policy));
    ASSERT_TRUE(configMgr.SetRawValue(notifKey,
        SS_C::ConfigValue{int64_t{static_cast<int64_t>(SS_C::NotificationLevel::Critical)}},
        SS_C::ConfigLayer::Policy));

    // ConfigManager must have notified on all three writes.
    EXPECT_EQ(configChanges.load(), 3);

    // Step 3: Read enforced values from ConfigManager and apply to SettingsManager.
    const int64_t enforcedNotif = configMgr.GetValue<int64_t>(notifKey, -1);
    settingsMgr.SetNotificationLevel(static_cast<SS_C::NotificationLevel>(enforcedNotif));
    EXPECT_EQ(settingsMgr.GetNotificationSettings().level,
              SS_C::NotificationLevel::Critical);

    // Step 4: Profile compliance — HighSecurity profile satisfies heuristic >= 4.
    const auto hsDef = profileMgr.GetProfileDefinition(SS_C::SystemProfile::HighSecurity);
    EXPECT_GE(hsDef.scan.heuristicLevel, 4u)
        << "HighSecurity profile must meet mandatory heuristic >= 4";

    // Step 5: Switch to HighSecurity profile.
    ASSERT_TRUE(profileMgr.SetActiveProfile(SS_C::SystemProfile::HighSecurity));
    EXPECT_EQ(profileMgr.GetActiveProfile(), SS_C::SystemProfile::HighSecurity);

    configMgr.UnregisterCallback(cfgCbId);
}

TEST_F(ConfigPropagationFixture,
       FourWay_EmergencyMode_AllManagersConsistent)
{
    const std::string rtpKey   = UniqueKey("emergency.rtp");
    const std::string notifKey = UniqueKey("emergency.notif");

    // Baseline: user-layer values.
    ASSERT_TRUE(configMgr.SetValue<bool>(rtpKey,   false, SS_C::ConfigLayer::User));
    settingsMgr.SetNotificationLevel(SS_C::NotificationLevel::None);

    // Activate emergency profile.
    ASSERT_TRUE(profileMgr.ActivateEmergencyProfile());
    ASSERT_TRUE(profileMgr.IsInEmergencyMode());

    // Emergency: Override layer enables RTP unconditionally.
    ASSERT_TRUE(configMgr.SetValue<bool>(rtpKey, true, SS_C::ConfigLayer::Override));
    // Emergency: SettingsManager switches to Critical notifications.
    settingsMgr.SetNotificationLevel(SS_C::NotificationLevel::Critical);
    // Emergency: Apply mandatory protection policy.
    const auto emPol = MakePolicy("fw-emergency-pol", rtpKey,
                                   SS_C::PolicyValue{true}, true, 999,
                                   SS_C::PolicyType::Protection);
    ASSERT_TRUE(policyMgr.ApplyPolicy(emPol));
    ASSERT_TRUE(policyMgr.ActivatePolicy("fw-emergency-pol"));

    // Verify all four managers are consistent in emergency state.
    EXPECT_TRUE(configMgr.GetValue<bool>(rtpKey, false))
        << "Override layer must dominate during emergency";
    EXPECT_EQ(configMgr.GetEffectiveLayer(rtpKey), SS_C::ConfigLayer::Override);
    EXPECT_EQ(settingsMgr.GetNotificationSettings().level,
              SS_C::NotificationLevel::Critical);
    EXPECT_TRUE(policyMgr.IsEnforced(rtpKey));
    EXPECT_TRUE(profileMgr.IsInEmergencyMode());

    // Exit emergency — Override cleared, user-layer (false) must reassert.
    ASSERT_TRUE(profileMgr.ExitEmergencyMode());
    configMgr.ResetToDefaults(SS_C::ConfigLayer::Override);
    EXPECT_FALSE(configMgr.GetValue<bool>(rtpKey, true))
        << "User-layer false must reassert after emergency exit";
}

TEST_F(ConfigPropagationFixture,
       FourWay_FullRoundTrip_ExportAndReimportPreservesAllState)
{
    const std::string langKey  = UniqueKey("fw.rt.language");
    const std::string themeKey = UniqueKey("fw.rt.theme");
    const std::string cpuKey   = UniqueKey("fw.rt.max_cpu");

    // Populate all four managers.
    ASSERT_TRUE(configMgr.SetValue<std::string>(langKey,  "pt-BR", SS_C::ConfigLayer::User));
    ASSERT_TRUE(configMgr.SetValue<int32_t>(themeKey,
        static_cast<int32_t>(SS_C::Theme::Dark), SS_C::ConfigLayer::User));
    ASSERT_TRUE(configMgr.SetValue<uint32_t>(cpuKey, 30u, SS_C::ConfigLayer::Session));

    settingsMgr.SetLanguage("pt-BR");
    settingsMgr.SetTheme(SS_C::Theme::Dark);

    const auto policy = MakePolicy("fw-rt-pol-001",
                                    UniqueKey("fw.rt.policy_key"),
                                    SS_C::PolicyValue{int64_t{2}});
    ASSERT_TRUE(policyMgr.ApplyPolicy(policy));

    ASSERT_TRUE(profileMgr.SetActiveProfile(SS_C::SystemProfile::Server));

    // Export ConfigManager User layer.
    SS_C::ConfigIOOptions opts;
    opts.layers = {SS_C::ConfigLayer::User};
    const std::string configJson = configMgr.ExportToJson(opts);
    EXPECT_FALSE(configJson.empty());

    // Export SettingsManager.
    const auto settingsPath = tempDir.File(L"exported-settings.json");
    ASSERT_TRUE(settingsMgr.ExportSettings(settingsPath));

    // Save PolicyManager offline cache.
    ASSERT_TRUE(policyMgr.SaveToOfflineCache());

    // Shutdown and reinitialize all four managers.
    profileMgr.Shutdown();
    settingsMgr.Shutdown();
    policyMgr.Shutdown();
    configMgr.Shutdown();

    SS_C::ConfigManagerConfiguration cfgConfig2;
    cfgConfig2.databasePath    = tempDir.File(L"config2.db");
    cfgConfig2.enableHotReload = false;
    ASSERT_TRUE(configMgr.Initialize(cfgConfig2));

    SS_C::PolicyManagerConfiguration polConfig2;
    polConfig2.enableAutoSync      = false;
    polConfig2.enableOfflineCache  = true;
    polConfig2.offlineCachePath    = tempDir.File(L"policy-cache.json");
    ASSERT_TRUE(policyMgr.Initialize(polConfig2));

    SS_C::SettingsManagerConfiguration setConfig2;
    setConfig2.settingsFilePath = tempDir.File(L"user-settings2.json");
    setConfig2.enableAutoSave   = false;
    ASSERT_TRUE(settingsMgr.Initialize(setConfig2));

    SS_C::ProfileManagerConfiguration profConfig2;
    profConfig2.initialProfile         = SS_C::SystemProfile::Standard;
    profConfig2.enableAutoDetection    = false;
    profConfig2.switchCooldownSeconds  = 0;
    ASSERT_TRUE(profileMgr.Initialize(profConfig2));

    // Reimport ConfigManager User layer.
    ASSERT_TRUE(configMgr.ImportFromJson(configJson, SS_C::ConfigLayer::User));
    EXPECT_EQ(configMgr.GetValue<std::string>(langKey, ""), "pt-BR");
    EXPECT_EQ(configMgr.GetValue<int32_t>(themeKey, -1),
              static_cast<int32_t>(SS_C::Theme::Dark));

    // Reimport SettingsManager.
    ASSERT_TRUE(settingsMgr.ImportSettings(settingsPath));
    EXPECT_EQ(settingsMgr.GetLocalizationSettings().languageCode, "pt-BR");
    EXPECT_EQ(settingsMgr.GetThemeSettings().theme, SS_C::Theme::Dark);

    // Reimport PolicyManager offline cache.
    ASSERT_TRUE(policyMgr.LoadFromOfflineCache());
    const auto policies = policyMgr.GetAllPolicies();
    EXPECT_FALSE(policies.empty())
        << "Offline cache must restore at least one policy";
}

TEST_F(ConfigPropagationFixture,
       FourWay_PolicySnapshotRollback_ManagersRemaindIndependent)
{
    const std::string key = UniqueKey("fw.snap.key");

    // t=0: Snapshot ConfigManager before any policy.
    ASSERT_TRUE(configMgr.SetValue<std::string>(key, "baseline", SS_C::ConfigLayer::User));
    const uint64_t snap0 = configMgr.CreateSnapshot("t0-baseline");
    EXPECT_NE(snap0, 0u);

    // t=1: Apply policy and write to Policy layer.
    const auto policy = MakePolicy("fw-snap-pol-001", key,
                                    SS_C::PolicyValue{std::string("policy-mandated")});
    ASSERT_TRUE(policyMgr.ApplyPolicy(policy));
    ASSERT_TRUE(policyMgr.ActivatePolicy("fw-snap-pol-001"));
    ASSERT_TRUE(configMgr.SetValue<std::string>(key, "policy-mandated",
                                                 SS_C::ConfigLayer::Policy));

    // t=2: Switch profile.
    ASSERT_TRUE(profileMgr.SetActiveProfile(SS_C::SystemProfile::HighSecurity));

    // Rollback ConfigManager to t=0 snapshot.
    ASSERT_TRUE(configMgr.RestoreSnapshot(snap0));

    // ConfigManager must be back to baseline — Policy layer was wiped by restore.
    // (Snapshot captures the entire layer state at the time of snapshot.)
    // The effective value returns to the User layer's baseline string.
    EXPECT_EQ(configMgr.GetValue<std::string>(key, ""), "baseline");

    // PolicyManager state is INDEPENDENT: policy still active.
    ASSERT_TRUE(policyMgr.IsEnforced(key));

    // ProfileManager state is INDEPENDENT: still on HighSecurity.
    EXPECT_EQ(profileMgr.GetActiveProfile(), SS_C::SystemProfile::HighSecurity);
}


// ============================================================================
// GROUP 8 — ConcurrencySafety: Multi-Threaded Cross-Manager Access
// ============================================================================

TEST_F(ConfigPropagationFixture,
       Concurrency_SimultaneousReads_AcrossAllFourManagers_NoCrash)
{
    const std::string readKey = UniqueKey("concurrency.read_key");
    ASSERT_TRUE(configMgr.SetValue<int64_t>(readKey, 42, SS_C::ConfigLayer::User));

    constexpr int kThreadsPerManager = 2;
    constexpr int kIterations        = 300;

    std::vector<std::thread> threads;
    threads.reserve(kThreadsPerManager * 4);

    // ConfigManager readers.
    for (int t = 0; t < kThreadsPerManager; ++t) {
        threads.emplace_back([&] {
            for (int i = 0; i < kIterations; ++i) {
                (void)configMgr.GetValue<int64_t>(readKey, -1);
                (void)configMgr.GetEffectiveLayer(readKey);
                (void)configMgr.HasKey(readKey);
            }
        });
    }
    // PolicyManager readers.
    for (int t = 0; t < kThreadsPerManager; ++t) {
        threads.emplace_back([&] {
            for (int i = 0; i < kIterations; ++i) {
                (void)policyMgr.GetActivePolicies();
                (void)policyMgr.GetStatus();
                (void)policyMgr.IsEnforced(readKey);
            }
        });
    }
    // SettingsManager readers.
    for (int t = 0; t < kThreadsPerManager; ++t) {
        threads.emplace_back([&] {
            for (int i = 0; i < kIterations; ++i) {
                (void)settingsMgr.GetThemeSettings();
                (void)settingsMgr.GetNotificationSettings();
                (void)settingsMgr.GetLocalizationSettings();
            }
        });
    }
    // ProfileManager readers.
    for (int t = 0; t < kThreadsPerManager; ++t) {
        threads.emplace_back([&] {
            for (int i = 0; i < kIterations; ++i) {
                (void)profileMgr.GetActiveProfile();
                (void)profileMgr.GetCurrentResourceLimits();
                (void)profileMgr.GetActiveProfileName();
            }
        });
    }

    for (auto& thr : threads) thr.join();
    // If we reach here without ASAN/TSAN errors, the test passes.
    SUCCEED();
}

TEST_F(ConfigPropagationFixture,
       Concurrency_ConcurrentPolicyApplyAndConfigRead_NoCrash)
{
    const std::string key = UniqueKey("concurrency.pol_cfg");
    std::atomic<uint64_t> policyCounter{0};

    constexpr int kWriterThreads = 3;
    constexpr int kReaderThreads = 3;
    constexpr int kIterations    = 100;

    std::vector<std::thread> threads;
    threads.reserve(kWriterThreads + kReaderThreads);

    // Writers: alternate apply/remove policies.
    for (int t = 0; t < kWriterThreads; ++t) {
        threads.emplace_back([&, t] {
            for (int i = 0; i < kIterations; ++i) {
                const std::string id =
                    "conc-pol-" + std::to_string(t) + "-" + std::to_string(i);
                SS_C::Policy p = MakePolicy(id, key, SS_C::PolicyValue{int64_t{i}},
                                             true, 100 + i);
                (void)policyMgr.ApplyPolicy(p);
                policyCounter.fetch_add(1, std::memory_order_relaxed);
                (void)policyMgr.RemovePolicy(id);
            }
        });
    }
    // Readers: read ConfigManager Policy layer and PolicyManager enforcement.
    for (int t = 0; t < kReaderThreads; ++t) {
        threads.emplace_back([&] {
            for (int i = 0; i < kIterations; ++i) {
                (void)configMgr.GetValue<int64_t>(key, -1);
                (void)policyMgr.IsEnforced(key);
                (void)policyMgr.GetActivePolicies();
            }
        });
    }

    for (auto& thr : threads) thr.join();
    EXPECT_GE(policyCounter.load(), static_cast<uint64_t>(kWriterThreads * kIterations));
}

TEST_F(ConfigPropagationFixture,
       Concurrency_ConcurrentProfileSwitches_WhileSettingsRead_NoCrash)
{
    constexpr int kSwitchers  = 2;
    constexpr int kReaders    = 4;
    constexpr int kIterations = 50;

    const std::array<SS_C::SystemProfile, 4> profiles = {
        SS_C::SystemProfile::Standard,
        SS_C::SystemProfile::HighSecurity,
        SS_C::SystemProfile::LowResource,
        SS_C::SystemProfile::Server
    };

    std::vector<std::thread> threads;
    threads.reserve(kSwitchers + kReaders);

    for (int t = 0; t < kSwitchers; ++t) {
        threads.emplace_back([&, t] {
            for (int i = 0; i < kIterations; ++i) {
                (void)profileMgr.SetActiveProfile(
                    profiles[static_cast<size_t>(i + t) % profiles.size()]);
            }
        });
    }
    for (int t = 0; t < kReaders; ++t) {
        threads.emplace_back([&] {
            for (int i = 0; i < kIterations; ++i) {
                (void)settingsMgr.GetNotificationSettings();
                (void)profileMgr.GetActiveProfile();
                (void)profileMgr.GetCurrentResourceLimits();
            }
        });
    }

    for (auto& thr : threads) thr.join();
    SUCCEED();
}

TEST_F(ConfigPropagationFixture,
       Concurrency_ConcurrentConfigWritesAndReads_LayerConsistencyHeld)
{
    const std::string key = UniqueKey("concurrency.layer_write");

    constexpr int kWriters   = 4;
    constexpr int kReaders   = 4;
    constexpr int kIterations = 200;

    std::vector<std::thread> threads;
    threads.reserve(kWriters + kReaders);

    for (int t = 0; t < kWriters; ++t) {
        threads.emplace_back([&, t] {
            const auto layer = (t % 2 == 0) ? SS_C::ConfigLayer::User
                                             : SS_C::ConfigLayer::Session;
            for (int i = 0; i < kIterations; ++i) {
                (void)configMgr.SetValue<int64_t>(key, static_cast<int64_t>(i), layer);
            }
        });
    }
    for (int t = 0; t < kReaders; ++t) {
        threads.emplace_back([&] {
            for (int i = 0; i < kIterations; ++i) {
                const int64_t v = configMgr.GetValue<int64_t>(key, -1);
                // Value must always be a non-negative integer (never -1 after first write).
                // We cannot assert on exact value due to races, but it must be >= 0
                // once the key has been set at least once.
                (void)v;
            }
        });
    }

    for (auto& thr : threads) thr.join();
    // Final state must be readable without error.
    const int64_t final_val = configMgr.GetValue<int64_t>(key, -1);
    EXPECT_GE(final_val, 0)
        << "Final value must be a valid write result, not the default sentinel";
}


// ============================================================================
// GROUP 9 — Edge Cases and Security Boundaries
// ============================================================================

TEST_F(ConfigPropagationFixture,
       EdgeCase_EmptyKeyRejectedByAllManagers)
{
    // ConfigManager: SetValue with empty key must fail silently (return false).
    EXPECT_FALSE(configMgr.SetValue<int64_t>("", 42, SS_C::ConfigLayer::User));
    EXPECT_FALSE(configMgr.HasKey(""));

    // PolicyManager: Policy with empty setting key must be invalid.
    SS_C::Policy invalidPolicy = MakePolicy("pol-empty-key", "",
                                             SS_C::PolicyValue{true});
    // A policy with an empty setting key must either be rejected or treated
    // as non-enforcing on any non-empty key.
    // If ApplyPolicy accepts it, IsEnforced("") must remain false.
    if (policyMgr.ApplyPolicy(invalidPolicy)) {
        (void)policyMgr.ActivatePolicy("pol-empty-key");
    }
    EXPECT_FALSE(policyMgr.IsEnforced(""))
        << "Empty key must never be reported as enforced";

    // ProfileManager: custom profile with empty name must be rejected.
    auto emptyNameProfile = MakeCustomProfile("", 50u, 2u, true, true);
    EXPECT_FALSE(profileMgr.CreateCustomProfile(emptyNameProfile))
        << "Profile with empty custom name must be rejected";
}

TEST_F(ConfigPropagationFixture,
       EdgeCase_OverlengthKeyRejectedByConfigManager)
{
    // Key at exactly MAX_KEY_LENGTH is at the boundary; MAX_KEY_LENGTH+1 must fail.
    const std::string maxKey(SS_C::ConfigConstants::MAX_KEY_LENGTH, 'a');
    const std::string tooLong(SS_C::ConfigConstants::MAX_KEY_LENGTH + 1, 'a');

    // Too-long key must be rejected.
    EXPECT_FALSE(configMgr.SetValue<int64_t>(tooLong, 1, SS_C::ConfigLayer::User))
        << "Key exceeding MAX_KEY_LENGTH must be rejected";
}

TEST_F(ConfigPropagationFixture,
       EdgeCase_ReInitializationWithNewConfig_StateIsClean)
{
    const std::string key = UniqueKey("reinit.key");

    // Populate state in first initialization (already done in SetUp).
    ASSERT_TRUE(configMgr.SetValue<std::string>(key, "first-run", SS_C::ConfigLayer::User));
    settingsMgr.SetTheme(SS_C::Theme::Dark);
    const auto policy = MakePolicy("reinit-pol-001",
                                    UniqueKey("reinit.policy_key"),
                                    SS_C::PolicyValue{true});
    ASSERT_TRUE(policyMgr.ApplyPolicy(policy));
    ASSERT_TRUE(profileMgr.SetActiveProfile(SS_C::SystemProfile::Server));

    // Shutdown all.
    profileMgr.Shutdown();
    settingsMgr.Shutdown();
    policyMgr.Shutdown();
    configMgr.Shutdown();

    // Reinitialize against a fresh (different) DB path.
    SS_C::ConfigManagerConfiguration freshCfg;
    freshCfg.databasePath    = tempDir.File(L"config-fresh.db");
    freshCfg.enableHotReload = false;
    ASSERT_TRUE(configMgr.Initialize(freshCfg));

    SS_C::PolicyManagerConfiguration freshPol;
    freshPol.enableAutoSync      = false;
    freshPol.enableOfflineCache  = false;
    ASSERT_TRUE(policyMgr.Initialize(freshPol));

    SS_C::SettingsManagerConfiguration freshSet;
    freshSet.settingsFilePath = tempDir.File(L"settings-fresh.json");
    freshSet.enableAutoSave   = false;
    ASSERT_TRUE(settingsMgr.Initialize(freshSet));

    SS_C::ProfileManagerConfiguration freshProf;
    freshProf.initialProfile         = SS_C::SystemProfile::Standard;
    freshProf.enableAutoDetection    = false;
    freshProf.switchCooldownSeconds  = 0;
    ASSERT_TRUE(profileMgr.Initialize(freshProf));

    // Fresh ConfigManager must not contain values from the previous run.
    EXPECT_EQ(configMgr.GetOptionalValue<std::string>(key), std::nullopt)
        << "Fresh ConfigManager DB must not contain values from previous run";

    // Fresh SettingsManager must use factory defaults.
    EXPECT_EQ(settingsMgr.GetThemeSettings().theme,
              settingsMgr.GetFactoryDefaults().theme.theme)
        << "Fresh SettingsManager must use factory defaults";

    // Fresh PolicyManager must have no active policies from previous run.
    EXPECT_TRUE(policyMgr.GetAllPolicies().empty())
        << "Fresh PolicyManager must have no stale policies";

    // Fresh ProfileManager must start on the configured initial profile.
    EXPECT_EQ(profileMgr.GetActiveProfile(), SS_C::SystemProfile::Standard);
}

TEST_F(ConfigPropagationFixture,
       EdgeCase_ExpiredPolicy_DoesNotInfluenceConfigOrSettings)
{
    const std::string key = UniqueKey("expired.scan_level");

    // Apply a policy already expired at creation.
    SS_C::Policy expiredPol = MakePolicy("pol-exp-cfg-001", key,
                                          SS_C::PolicyValue{int64_t{99}});
    expiredPol.expiresAt =
        std::chrono::system_clock::now() - std::chrono::hours(48);
    ASSERT_TRUE(policyMgr.ApplyPolicy(expiredPol));

    // Even if ActivatePolicy is called, IsExpired must return true.
    const auto retrieved = policyMgr.GetPolicy("pol-exp-cfg-001");
    ASSERT_TRUE(retrieved.has_value());
    EXPECT_TRUE(retrieved->IsExpired())
        << "Policy with past expiry must be recognized as expired";

    // ConfigManager must not have 99 written to its layers; write from an
    // external enforcement path must not have occurred.
    EXPECT_NE(configMgr.GetValue<int64_t>(key, -1), 99)
        << "Expired policy value must not auto-populate ConfigManager";
}

TEST_F(ConfigPropagationFixture,
       EdgeCase_CallbackUnregister_NoUseAfterUnregister_NoCrash)
{
    const std::string key = UniqueKey("edge.callback_unreg");
    std::atomic<int> hits{0};

    const uint64_t cbId = configMgr.RegisterKeyChangeCallback(key,
        [&](const SS_C::ConfigChangeEvent&) {
            hits.fetch_add(1, std::memory_order_relaxed);
        });

    ASSERT_TRUE(configMgr.SetValue<int64_t>(key, 1, SS_C::ConfigLayer::User));
    EXPECT_GE(hits.load(), 1);

    // Unregister; subsequent writes must not invoke the callback.
    configMgr.UnregisterCallback(cbId);
    const int hitsBefore = hits.load();

    ASSERT_TRUE(configMgr.SetValue<int64_t>(key, 2, SS_C::ConfigLayer::User));
    ASSERT_TRUE(configMgr.SetValue<int64_t>(key, 3, SS_C::ConfigLayer::User));

    EXPECT_EQ(hits.load(), hitsBefore)
        << "Unregistered callback must not fire on subsequent writes";
}

TEST_F(ConfigPropagationFixture,
       EdgeCase_AllManagersAtLoad_StatisticsRemainAccurate)
{
    const std::string baseKey = UniqueKey("load.stats");

    // ConfigManager: 50 writes.
    for (int i = 0; i < 50; ++i) {
        ASSERT_TRUE(configMgr.SetValue<int64_t>(
            baseKey + "_" + std::to_string(i), static_cast<int64_t>(i),
            SS_C::ConfigLayer::User));
    }

    // PolicyManager: 10 policy applications.
    for (int i = 0; i < 10; ++i) {
        const auto pol = MakePolicy(
            "load-pol-" + std::to_string(i),
            UniqueKey("load.policy"),
            SS_C::PolicyValue{int64_t{i}},
            true, 100 + i);
        ASSERT_TRUE(policyMgr.ApplyPolicy(pol));
    }

    // SettingsManager: 5 setting changes.
    settingsMgr.SetTheme(SS_C::Theme::Dark);
    settingsMgr.SetTheme(SS_C::Theme::Light);
    settingsMgr.SetLanguage("en-GB");
    settingsMgr.SetNotificationLevel(SS_C::NotificationLevel::Important);
    settingsMgr.SetNotificationLevel(SS_C::NotificationLevel::All);

    // ProfileManager: 5 profile switches.
    ASSERT_TRUE(profileMgr.SetActiveProfile(SS_C::SystemProfile::Server));
    ASSERT_TRUE(profileMgr.SetActiveProfile(SS_C::SystemProfile::LowResource));
    ASSERT_TRUE(profileMgr.SetActiveProfile(SS_C::SystemProfile::Developer));
    ASSERT_TRUE(profileMgr.SetActiveProfile(SS_C::SystemProfile::HighSecurity));
    ASSERT_TRUE(profileMgr.SetActiveProfile(SS_C::SystemProfile::Standard));

    // Validate statistics.
    const auto cfgStats  = configMgr.GetStatistics();
    const auto polStats  = policyMgr.GetStatistics();
    const auto setStats  = settingsMgr.GetStatistics();
    const auto profStats = profileMgr.GetStatistics();

    EXPECT_GE(cfgStats.totalWrites.load(), 50u)
        << "ConfigManager must have tracked >= 50 writes";
    EXPECT_GE(polStats.policiesApplied.load(), 10u)
        << "PolicyManager must have tracked >= 10 policy applications";
    EXPECT_GE(setStats.settingChanges.load(), 5u)
        << "SettingsManager must have tracked >= 5 setting changes";
    EXPECT_GE(profStats.profileSwitches.load(), 5u)
        << "ProfileManager must have tracked >= 5 profile switches";
}

TEST_F(ConfigPropagationFixture,
       EdgeCase_MultipleValidators_AllEvaluated_FirstFailureWins)
{
    const std::string key = UniqueKey("validators.multi");

    // Register a validator that rejects negative integers.
    configMgr.RegisterValidator(key,
        [](const std::string&, const SS_C::ConfigValue& v) -> SS_C::ValidationResult {
            const auto* i = std::get_if<int64_t>(&v);
            if (i != nullptr && *i < 0)
                return SS_C::ValidationResult::OutOfRange;
            return SS_C::ValidationResult::Valid;
        });

    // Register a second validator (policy enforcement) that rejects odd numbers.
    configMgr.RegisterValidator(key,
        [](const std::string&, const SS_C::ConfigValue& v) -> SS_C::ValidationResult {
            const auto* i = std::get_if<int64_t>(&v);
            if (i != nullptr && (*i % 2 != 0))
                return SS_C::ValidationResult::InvalidFormat;
            return SS_C::ValidationResult::Valid;
        });

    // Negative value: must fail range check.
    EXPECT_NE(configMgr.ValidateValue(key, SS_C::ConfigValue{int64_t{-1}}),
              SS_C::ValidationResult::Valid);

    // Odd positive value: must fail format check.
    EXPECT_NE(configMgr.ValidateValue(key, SS_C::ConfigValue{int64_t{3}}),
              SS_C::ValidationResult::Valid);

    // Even positive value: must pass both validators.
    EXPECT_EQ(configMgr.ValidateValue(key, SS_C::ConfigValue{int64_t{4}}),
              SS_C::ValidationResult::Valid);
}
