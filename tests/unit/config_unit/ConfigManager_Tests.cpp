/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * Comprehensive unit coverage for the shared configuration manager.
 *
 * Focus:
 *   - configuration validation and public utility helpers
 *   - metadata-driven validation and value conversion
 *   - layer resolution, callbacks, snapshots, import/export, and resets
 */

#include "pch.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <map>
#include <optional>
#include <string>
#include <vector>

#include "../../../src/PhantomCore/Config/ConfigManager.hpp"
#include "Config_TestUtils.hpp"

namespace ShadowStrike::Config::Test {

class ConfigManagerTest : public ::testing::Test {
protected:
    ConfigManager& manager = ConfigManager::Instance();
    std::vector<uint64_t> callbackIds;
    std::vector<uint64_t> snapshotIds;
    const std::string prefix = UniqueUtf8("config");

    void SetUp() override {
        manager.Shutdown();
        // Re-initialize ConfigManager (was missing, caused PolicyManager crashes)
        ConfigManagerConfiguration config;
        (void)manager.Initialize(config);
        ResetAllLayers();
        DeleteAllSnapshots();
        manager.ResetStatistics();
    }

    void TearDown() override {
        for (const auto callbackId : callbackIds) {
            manager.UnregisterCallback(callbackId);
        }
        DeleteAllSnapshots();
        ResetAllLayers();
        manager.ResetStatistics();
        manager.Shutdown();
    }

    [[nodiscard]] std::string Key(std::string_view suffix) const {
        return prefix + "." + std::string(suffix);
    }

    void ResetAllLayers() {
        for (const auto layer : {ConfigLayer::Default, ConfigLayer::System, ConfigLayer::Enterprise,
                                 ConfigLayer::Policy, ConfigLayer::User, ConfigLayer::Session,
                                 ConfigLayer::Override}) {
            manager.ResetToDefaults(layer);
        }
    }

    void DeleteAllSnapshots() {
        for (const auto& snapshot : manager.ListSnapshots()) {
            (void)manager.DeleteSnapshot(snapshot.snapshotId);
        }
    }
};

TEST_F(ConfigManagerTest, ConfigurationAndStatisticsContractsRejectUnsafeValues) {
    ConfigManagerConfiguration config;
    EXPECT_TRUE(config.IsValid());

    config.hotReloadIntervalMs = 99;
    EXPECT_FALSE(config.IsValid());

    config = {};
    config.maxSnapshots = 0;
    EXPECT_FALSE(config.IsValid());

    config = {};
    config.cacheTtlSeconds = 0;
    EXPECT_FALSE(config.IsValid());

    config = {};
    config.enableCaching = false;
    config.cacheTtlSeconds = 0;
    EXPECT_TRUE(config.IsValid());

    ConfigStatistics stats;
    stats.totalReads.store(11, std::memory_order_relaxed);
    stats.totalWrites.store(7, std::memory_order_relaxed);
    stats.cacheHits.store(5, std::memory_order_relaxed);
    stats.cacheMisses.store(2, std::memory_order_relaxed);
    stats.validationErrors.store(3, std::memory_order_relaxed);
    stats.hotReloads.store(4, std::memory_order_relaxed);
    stats.policyUpdates.store(1, std::memory_order_relaxed);
    stats.snapshotsTaken.store(6, std::memory_order_relaxed);

    const auto beforeReset = ParseJson(stats.ToJson());
    EXPECT_EQ(beforeReset.at("totalReads").get<uint64_t>(), 11u);
    EXPECT_EQ(beforeReset.at("totalWrites").get<uint64_t>(), 7u);
    EXPECT_EQ(beforeReset.at("cacheHits").get<uint64_t>(), 5u);
    EXPECT_EQ(beforeReset.at("cacheMisses").get<uint64_t>(), 2u);
    EXPECT_EQ(beforeReset.at("validationErrors").get<uint64_t>(), 3u);
    EXPECT_EQ(beforeReset.at("hotReloads").get<uint64_t>(), 4u);
    EXPECT_EQ(beforeReset.at("policyUpdates").get<uint64_t>(), 1u);
    EXPECT_EQ(beforeReset.at("snapshotsTaken").get<uint64_t>(), 6u);
    EXPECT_GE(beforeReset.at("uptimeSeconds").get<int64_t>(), 0);

    stats.Reset();
    const auto afterReset = ParseJson(stats.ToJson());
    EXPECT_EQ(afterReset.at("totalReads").get<uint64_t>(), 0u);
    EXPECT_EQ(afterReset.at("totalWrites").get<uint64_t>(), 0u);
    EXPECT_EQ(afterReset.at("cacheHits").get<uint64_t>(), 0u);
    EXPECT_EQ(afterReset.at("cacheMisses").get<uint64_t>(), 0u);
    EXPECT_EQ(afterReset.at("validationErrors").get<uint64_t>(), 0u);
    EXPECT_EQ(afterReset.at("hotReloads").get<uint64_t>(), 0u);
    EXPECT_EQ(afterReset.at("policyUpdates").get<uint64_t>(), 0u);
    EXPECT_EQ(afterReset.at("snapshotsTaken").get<uint64_t>(), 0u);

    EXPECT_EQ(ConfigManager::GetVersionString(), "3.0.0");
    EXPECT_TRUE(ConfigManager::HasInstance());
    EXPECT_TRUE(manager.SelfTest());
}

TEST_F(ConfigManagerTest, UtilityFunctionsAndStructSerializationCoverPublicContracts) {
    ConfigKeyMetadata metadata;
    metadata.key = Key("threat.level");
    metadata.displayName = "Threat Level";
    metadata.description = "Controls sensitivity";
    metadata.category = "engine";
    metadata.valueType = ValueType::String;
    metadata.defaultValue = std::string("balanced");
    metadata.minValue = 1.0;
    metadata.maxValue = 5.0;
    metadata.allowedValues = {"balanced", "strict"};
    metadata.isSensitive = true;
    metadata.isReadOnly = true;
    metadata.isDeprecated = true;
    metadata.requiresRestart = true;
    metadata.dependencies = {"engine.enabled"};
    metadata.versionAdded = "3.0.0";

    const auto metadataJson = ParseJson(metadata.ToJson());
    EXPECT_EQ(metadataJson.at("key").get<std::string>(), metadata.key);
    EXPECT_EQ(metadataJson.at("displayName").get<std::string>(), metadata.displayName);
    EXPECT_EQ(metadataJson.at("valueType").get<std::string>(), "String");
    EXPECT_EQ(metadataJson.at("minValue").get<double>(), 1.0);
    EXPECT_EQ(metadataJson.at("maxValue").get<double>(), 5.0);
    EXPECT_EQ(metadataJson.at("allowedValues").size(), 2u);
    EXPECT_EQ(metadataJson.at("dependencies").size(), 1u);
    EXPECT_TRUE(metadataJson.at("isSensitive").get<bool>());
    EXPECT_TRUE(metadataJson.at("isReadOnly").get<bool>());
    EXPECT_TRUE(metadataJson.at("isDeprecated").get<bool>());
    EXPECT_TRUE(metadataJson.at("requiresRestart").get<bool>());

    ConfigChangeEvent changeEvent;
    changeEvent.key = Key("scan.mode");
    changeEvent.oldValue = std::string("balanced");
    changeEvent.newValue = std::string("strict");
    changeEvent.layer = ConfigLayer::Policy;
    changeEvent.reason = ChangeReason::PolicyUpdate;
    changeEvent.timestamp = std::chrono::system_clock::time_point{std::chrono::milliseconds(1337)};
    changeEvent.source = "unit-test";

    const auto changeJson = ParseJson(changeEvent.ToJson());
    EXPECT_EQ(changeJson.at("layer").get<std::string>(), "Policy");
    EXPECT_EQ(changeJson.at("reason").get<std::string>(), "PolicyUpdate");
    EXPECT_EQ(changeJson.at("oldValue").get<std::string>(), "balanced");
    EXPECT_EQ(changeJson.at("newValue").get<std::string>(), "strict");
    EXPECT_EQ(changeJson.at("source").get<std::string>(), "unit-test");

    ConfigSnapshot snapshot;
    snapshot.snapshotId = 42;
    snapshot.timestamp = std::chrono::system_clock::time_point{std::chrono::milliseconds(2024)};
    snapshot.layer = ConfigLayer::User;
    snapshot.description = "before policy import";
    snapshot.values.emplace(Key("scan.enabled"), true);
    snapshot.values.emplace(Key("scan.level"), std::string("balanced"));

    const auto snapshotJson = ParseJson(snapshot.ToJson());
    EXPECT_EQ(snapshotJson.at("snapshotId").get<uint64_t>(), 42u);
    EXPECT_EQ(snapshotJson.at("layer").get<std::string>(), "User");
    EXPECT_EQ(snapshotJson.at("description").get<std::string>(), "before policy import");
    EXPECT_EQ(snapshotJson.at("keyCount").get<size_t>(), 2u);

    ConfigValidationError validationError;
    validationError.key = Key("engine.mode");
    validationError.result = ValidationResult::InvalidFormat;
    validationError.message = "Unexpected enum token";
    validationError.suggestedFix = "Use balanced or strict";

    const auto errorJson = ParseJson(validationError.ToJson());
    EXPECT_EQ(errorJson.at("key").get<std::string>(), validationError.key);
    EXPECT_EQ(errorJson.at("result").get<std::string>(), "InvalidFormat");
    EXPECT_EQ(errorJson.at("suggestedFix").get<std::string>(), "Use balanced or strict");

    EXPECT_EQ(GetConfigLayerName(ConfigLayer::Override), "Override");
    EXPECT_EQ(GetConfigLayerName(static_cast<ConfigLayer>(0xFF)), "Unknown");
    EXPECT_EQ(GetValueTypeName(ValueType::Map), "Map");
    EXPECT_EQ(GetValueTypeName(static_cast<ValueType>(0xFF)), "Unknown");
    EXPECT_EQ(GetChangeReasonName(ChangeReason::Rollback), "Rollback");
    EXPECT_EQ(GetChangeReasonName(static_cast<ChangeReason>(0xFF)), "Unknown");
    EXPECT_EQ(GetValidationResultName(ValidationResult::DependencyFailed), "DependencyFailed");
    EXPECT_EQ(GetValidationResultName(static_cast<ValidationResult>(0xFF)), "Unknown");

    EXPECT_EQ(ConfigValueToString(ConfigValue{std::monostate{}}), "<null>");
    EXPECT_EQ(ConfigValueToString(ConfigValue{true}), "true");
    EXPECT_EQ(ConfigValueToString(ConfigValue{int32_t{-7}}), "-7");
    EXPECT_EQ(ConfigValueToString(ConfigValue{uint64_t{9}}), "9");
    EXPECT_EQ(ConfigValueToString(ConfigValue{std::wstring(L"wide-value")}), "wide-value");
    EXPECT_EQ(ConfigValueToString(ConfigValue{std::vector<std::string>{"a", "b"}}), "[\"a\",\"b\"]");
    EXPECT_EQ(ConfigValueToString(ConfigValue{std::vector<int64_t>{1, 2}}), "[1,2]");
    EXPECT_EQ(ConfigValueToString(ConfigValue{std::map<std::string, std::string>{{"k", "v"}}}), "{\"k\":\"v\"}");

    const auto parsedBool = ParseConfigValue("true", ValueType::Boolean);
    ASSERT_TRUE(std::holds_alternative<bool>(parsedBool));
    EXPECT_TRUE(std::get<bool>(parsedBool));

    const auto parsedInt = ParseConfigValue("-44", ValueType::Integer);
    ASSERT_TRUE(std::holds_alternative<int64_t>(parsedInt));
    EXPECT_EQ(std::get<int64_t>(parsedInt), -44);

    const auto parsedUInt = ParseConfigValue("44", ValueType::UInteger);
    ASSERT_TRUE(std::holds_alternative<uint64_t>(parsedUInt));
    EXPECT_EQ(std::get<uint64_t>(parsedUInt), 44u);

    const auto parsedFloat = ParseConfigValue("3.5", ValueType::Float);
    ASSERT_TRUE(std::holds_alternative<double>(parsedFloat));
    EXPECT_DOUBLE_EQ(std::get<double>(parsedFloat), 3.5);

    const auto parsedStringList = ParseConfigValue("[\"x\",\"y\"]", ValueType::StringList);
    ASSERT_TRUE(std::holds_alternative<std::vector<std::string>>(parsedStringList));
    EXPECT_THAT(std::get<std::vector<std::string>>(parsedStringList),
                ::testing::ElementsAre("x", "y"));

    const auto parsedIntList = ParseConfigValue("[1,2,3]", ValueType::IntList);
    ASSERT_TRUE(std::holds_alternative<std::vector<int64_t>>(parsedIntList));
    EXPECT_THAT(std::get<std::vector<int64_t>>(parsedIntList),
                ::testing::ElementsAre(1, 2, 3));

    const auto parsedMap = ParseConfigValue("{\"path\":\"C:/Temp\",\"enabled\":true}", ValueType::Map);
    ASSERT_EQ(GetConfigValueType(parsedMap), ValueType::Map);
    const auto& parsedMapValue = std::get<std::map<std::string, std::string>>(parsedMap);
    EXPECT_EQ(parsedMapValue.at("path"), "C:/Temp");
    EXPECT_EQ(parsedMapValue.at("enabled"), "true");

    EXPECT_TRUE(std::holds_alternative<std::monostate>(
        ParseConfigValue("definitely-not-bool", ValueType::Boolean)));

    EXPECT_EQ(GetConfigValueType(ConfigValue{false}), ValueType::Boolean);
    EXPECT_EQ(GetConfigValueType(ConfigValue{uint32_t{7}}), ValueType::UInteger);
    EXPECT_EQ(GetConfigValueType(ConfigValue{std::wstring(L"wide")}), ValueType::WString);
    EXPECT_EQ(GetConfigValueType(ConfigValue{std::vector<int64_t>{1}}), ValueType::IntList);
}

TEST_F(ConfigManagerTest, MetadataValidationAndLayerResolutionHonorContracts) {
    const std::string intKey = Key("limits.retry");
    const std::string modeKey = Key("mode");
    const std::string dependencyKey = Key("feature.dependent");
    const std::string dependencyTargetKey = Key("feature.enabled");
    const std::string readOnlyKey = Key("readonly");
    const std::string deprecatedKey = Key("deprecated");
    const std::string customValidatorKey = Key("custom.validator");

    ConfigKeyMetadata intMeta;
    intMeta.key = intKey;
    intMeta.category = "limits";
    intMeta.valueType = ValueType::Integer;
    intMeta.defaultValue = int64_t{3};
    intMeta.minValue = 1.0;
    intMeta.maxValue = 8.0;
    ASSERT_TRUE(manager.RegisterKeyMetadata(intMeta));

    ConfigKeyMetadata modeMeta;
    modeMeta.key = modeKey;
    modeMeta.category = "profile";
    modeMeta.valueType = ValueType::String;
    modeMeta.allowedValues = {"balanced", "strict"};
    ASSERT_TRUE(manager.RegisterKeyMetadata(modeMeta));

    ConfigKeyMetadata dependencyMeta;
    dependencyMeta.key = dependencyKey;
    dependencyMeta.valueType = ValueType::String;
    dependencyMeta.dependencies = {dependencyTargetKey};
    ASSERT_TRUE(manager.RegisterKeyMetadata(dependencyMeta));

    ConfigKeyMetadata readOnlyMeta;
    readOnlyMeta.key = readOnlyKey;
    readOnlyMeta.valueType = ValueType::String;
    readOnlyMeta.isReadOnly = true;
    readOnlyMeta.defaultValue = std::string("factory");
    ASSERT_TRUE(manager.RegisterKeyMetadata(readOnlyMeta));

    ConfigKeyMetadata deprecatedMeta;
    deprecatedMeta.key = deprecatedKey;
    deprecatedMeta.valueType = ValueType::String;
    deprecatedMeta.isDeprecated = true;
    ASSERT_TRUE(manager.RegisterKeyMetadata(deprecatedMeta));

    ConfigKeyMetadata customMeta;
    customMeta.key = customValidatorKey;
    customMeta.valueType = ValueType::String;
    ASSERT_TRUE(manager.RegisterKeyMetadata(customMeta));

    manager.RegisterValidator(customValidatorKey, [](const std::string&, const ConfigValue& value) {
        const auto* stringValue = std::get_if<std::string>(&value);
        if (stringValue != nullptr && stringValue->rfind("allow:", 0) == 0) {
            return ValidationResult::Valid;
        }
        return ValidationResult::InvalidFormat;
    });

    manager.LoadFactoryDefaults();
    EXPECT_EQ(manager.GetValue<int64_t>(intKey, -1), 3);
    EXPECT_EQ(manager.GetEffectiveLayer(intKey), ConfigLayer::Default);
    EXPECT_TRUE(manager.HasKey(readOnlyKey));

    EXPECT_EQ(manager.ValidateValue(intKey, ConfigValue{std::string("wrong")}),
              ValidationResult::InvalidType);
    EXPECT_EQ(manager.ValidateValue(intKey, ConfigValue{int64_t{99}}),
              ValidationResult::OutOfRange);
    EXPECT_EQ(manager.ValidateValue(modeKey, ConfigValue{std::string("aggressive")}),
              ValidationResult::InvalidFormat);
    EXPECT_EQ(manager.ValidateValue(dependencyKey, ConfigValue{std::string("on")}),
              ValidationResult::DependencyFailed);
    EXPECT_EQ(manager.ValidateValue(readOnlyKey, ConfigValue{std::string("override")}),
              ValidationResult::ReadOnly);
    EXPECT_EQ(manager.ValidateValue(deprecatedKey, ConfigValue{std::string("legacy")}),
              ValidationResult::Deprecated);
    EXPECT_EQ(manager.ValidateValue(customValidatorKey, ConfigValue{std::string("deny")}),
              ValidationResult::InvalidFormat);
    EXPECT_EQ(manager.ValidateValue(customValidatorKey, ConfigValue{std::string("allow:yes")}),
              ValidationResult::Valid);

    ASSERT_TRUE(manager.SetRawValue(dependencyTargetKey, ConfigValue{true}, ConfigLayer::Session));
    EXPECT_EQ(manager.ValidateValue(dependencyKey, ConfigValue{std::string("on")}),
              ValidationResult::Valid);

    const auto validatedResult = manager.SetValueValidated<int64_t>(intKey, 7, ConfigLayer::Session);
    EXPECT_TRUE(validatedResult.first);
    EXPECT_TRUE(validatedResult.second.empty());
    ASSERT_EQ(manager.GetValueFromLayer<int64_t>(intKey, ConfigLayer::Session), std::optional<int64_t>(7));
    EXPECT_EQ(manager.GetValue<int64_t>(intKey, -1), 7);
    EXPECT_EQ(manager.GetEffectiveLayer(intKey), ConfigLayer::Session);

    EXPECT_FALSE(manager.SetRawValue(readOnlyKey, ConfigValue{std::string("blocked")}, ConfigLayer::User));
    EXPECT_TRUE(manager.SetRawValue(readOnlyKey, ConfigValue{std::string("override")}, ConfigLayer::Override));
    EXPECT_EQ(manager.GetValue<std::string>(readOnlyKey, ""), "override");
    EXPECT_EQ(manager.GetEffectiveLayer(readOnlyKey), ConfigLayer::Override);

    const auto metadata = manager.GetKeyMetadata(modeKey);
    ASSERT_TRUE(metadata.has_value());
    EXPECT_EQ(metadata->allowedValues.size(), 2u);

    const auto categories = manager.GetCategories();
    EXPECT_NE(std::find(categories.begin(), categories.end(), "limits"), categories.end());
    EXPECT_NE(std::find(categories.begin(), categories.end(), "profile"), categories.end());

    const auto limitKeys = manager.GetKeysByCategory("limits");
    EXPECT_NE(std::find(limitKeys.begin(), limitKeys.end(), intKey), limitKeys.end());

    // Set valid values for keys that would otherwise fail validation
    // modeKey requires one of {"balanced", "strict"}
    ASSERT_TRUE(manager.SetRawValue(modeKey, ConfigValue{std::string("balanced")}, ConfigLayer::Session));
    // customValidatorKey requires "allow:" prefix
    ASSERT_TRUE(manager.SetRawValue(customValidatorKey, ConfigValue{std::string("allow:test")}, ConfigLayer::Session));

    const auto validationErrors = manager.ValidateAll();
    EXPECT_TRUE(validationErrors.empty());
}

TEST_F(ConfigManagerTest, BulkOperationsAndImportFailuresPreserveAtomicContracts) {
    const std::string batchStringKey = Key("batch.string");
    const std::string batchIntKey = Key("batch.int");
    const std::string readOnlyKey = Key("batch.readonly");
    const std::string importedObjectKey = Key("imported.object");

    ConfigKeyMetadata stringMeta;
    stringMeta.key = batchStringKey;
    stringMeta.category = "batch";
    stringMeta.valueType = ValueType::String;
    stringMeta.defaultValue = std::string("factory");
    ASSERT_TRUE(manager.RegisterKeyMetadata(stringMeta));

    ConfigKeyMetadata intMeta;
    intMeta.key = batchIntKey;
    intMeta.category = "batch";
    intMeta.valueType = ValueType::Integer;
    ASSERT_TRUE(manager.RegisterKeyMetadata(intMeta));

    ConfigKeyMetadata readOnlyMeta;
    readOnlyMeta.key = readOnlyKey;
    readOnlyMeta.category = "batch";
    readOnlyMeta.valueType = ValueType::String;
    readOnlyMeta.isReadOnly = true;
    readOnlyMeta.defaultValue = std::string("locked");
    ASSERT_TRUE(manager.RegisterKeyMetadata(readOnlyMeta));

    ConfigKeyMetadata importedObjectMeta;
    importedObjectMeta.key = importedObjectKey;
    importedObjectMeta.category = "batch";
    importedObjectMeta.valueType = ValueType::String;
    ASSERT_TRUE(manager.RegisterKeyMetadata(importedObjectMeta));

    manager.LoadFactoryDefaults();
    ASSERT_TRUE(manager.SetRawValue(batchStringKey, ConfigValue{std::string("seed")}, ConfigLayer::User));

    EXPECT_FALSE(manager.SetMultipleValues({
        {batchStringKey, ConfigValue{std::string("mutated")}},
        {"", ConfigValue{std::string("invalid")}}
    }, ConfigLayer::User));
    EXPECT_EQ(manager.GetValue<std::string>(batchStringKey, ""), "seed");

    EXPECT_FALSE(manager.SetMultipleValues({
        {batchStringKey, ConfigValue{std::string("mutated")}},
        {readOnlyKey, ConfigValue{std::string("blocked")}}
    }, ConfigLayer::User));
    EXPECT_EQ(manager.GetValue<std::string>(batchStringKey, ""), "seed");
    EXPECT_EQ(manager.GetValue<std::string>(readOnlyKey, ""), "locked");

    EXPECT_TRUE(manager.SetMultipleValues({
        {batchStringKey, ConfigValue{std::string("override")}},
        {batchIntKey, ConfigValue{int64_t{42}}}
    }, ConfigLayer::Override));
    EXPECT_EQ(manager.GetValue<std::string>(batchStringKey, ""), "override");
    EXPECT_EQ(manager.GetOptionalValue<int64_t>(batchIntKey), std::optional<int64_t>(42));
    EXPECT_FALSE(manager.GetOptionalValue<int64_t>(batchStringKey).has_value());
    EXPECT_EQ(manager.GetValueType(Key("missing")), ValueType::Null);
    EXPECT_FALSE(manager.HasKey(""));

    manager.SetHotReloadEnabled(false);
    EXPECT_FALSE(manager.IsHotReloadEnabled());
    manager.SetHotReloadEnabled(true);
    EXPECT_TRUE(manager.IsHotReloadEnabled());

    EXPECT_FALSE(manager.ImportFromJson("", ConfigLayer::Override));
    EXPECT_FALSE(manager.ImportFromJson("{", ConfigLayer::Override));
    EXPECT_FALSE(manager.ImportFromJson(R"({"metadata":{}})", ConfigLayer::Override));

    const std::string oversizedKey(ConfigConstants::MAX_KEY_LENGTH + 1, 'x');
    const std::string importJson = std::string("{\"values\":{\"") + importedObjectKey +
                                   "\":{\"mode\":\"strict\"},\"" + oversizedKey + "\":true}}";
    ASSERT_TRUE(manager.ImportFromJson(importJson, ConfigLayer::Session));
    EXPECT_EQ(manager.GetOptionalValue<std::string>(importedObjectKey),
              std::optional<std::string>("{\"mode\":\"strict\"}"));
    EXPECT_FALSE(manager.HasKey(oversizedKey));
}

TEST_F(ConfigManagerTest, CallbacksSnapshotsImportExportAndResetsPreserveObservableBehavior) {
    const std::string userKey = Key("scan.mode");
    const std::string defaultKey = Key("engine.mode");
    const std::string sensitiveKey = Key("secrets.token");
    const std::string importedFlagKey = Key("imported.flag");
    const std::string importedCountKey = Key("imported.count");
    const std::string importedMapKey = Key("imported.map");

    ConfigKeyMetadata userMeta;
    userMeta.key = userKey;
    userMeta.category = "export";
    userMeta.valueType = ValueType::String;
    ASSERT_TRUE(manager.RegisterKeyMetadata(userMeta));

    ConfigKeyMetadata defaultMeta;
    defaultMeta.key = defaultKey;
    defaultMeta.category = "export";
    defaultMeta.valueType = ValueType::String;
    defaultMeta.defaultValue = std::string("balanced");
    ASSERT_TRUE(manager.RegisterKeyMetadata(defaultMeta));

    ConfigKeyMetadata sensitiveMeta;
    sensitiveMeta.key = sensitiveKey;
    sensitiveMeta.category = "secrets";
    sensitiveMeta.valueType = ValueType::String;
    sensitiveMeta.defaultValue = std::string("hidden");
    sensitiveMeta.isSensitive = true;
    ASSERT_TRUE(manager.RegisterKeyMetadata(sensitiveMeta));

    ConfigKeyMetadata importedFlagMeta;
    importedFlagMeta.key = importedFlagKey;
    importedFlagMeta.category = "import";
    importedFlagMeta.valueType = ValueType::Boolean;
    ASSERT_TRUE(manager.RegisterKeyMetadata(importedFlagMeta));

    ConfigKeyMetadata importedCountMeta;
    importedCountMeta.key = importedCountKey;
    importedCountMeta.category = "import";
    importedCountMeta.valueType = ValueType::Integer;
    ASSERT_TRUE(manager.RegisterKeyMetadata(importedCountMeta));

    ConfigKeyMetadata importedMapMeta;
    importedMapMeta.key = importedMapKey;
    importedMapMeta.category = "import";
    importedMapMeta.valueType = ValueType::String;
    ASSERT_TRUE(manager.RegisterKeyMetadata(importedMapMeta));

    manager.LoadFactoryDefaults();

    std::vector<ConfigChangeEvent> observedEvents;
    callbackIds.push_back(manager.RegisterChangeCallback(
        [&observedEvents](const ConfigChangeEvent& event) {
            observedEvents.push_back(event);
        }));
    callbackIds.push_back(manager.RegisterKeyChangeCallback(
        userKey, [&observedEvents](const ConfigChangeEvent& event) {
            observedEvents.push_back(event);
        }));

    ASSERT_TRUE(manager.SetRawValue(userKey, ConfigValue{std::string("strict")}, ConfigLayer::User));
    EXPECT_EQ(manager.GetValue<std::string>(userKey, ""), "strict");

    const auto snapshotId = manager.CreateSnapshot("before import");
    snapshotIds.push_back(snapshotId);
    ASSERT_TRUE(snapshotId > 0);

    ASSERT_TRUE(manager.SetRawValue(userKey, ConfigValue{std::string("relaxed")}, ConfigLayer::User));
    EXPECT_EQ(manager.GetValue<std::string>(userKey, ""), "relaxed");

    ASSERT_TRUE(manager.RestoreSnapshot(snapshotId));
    EXPECT_EQ(manager.GetValue<std::string>(userKey, ""), "strict");

    const auto snapshots = manager.ListSnapshots();
    EXPECT_TRUE(std::any_of(snapshots.begin(), snapshots.end(), [snapshotId](const ConfigSnapshot& snapshot) {
        return snapshot.snapshotId == snapshotId;
    }));

    ConfigIOOptions exportOptions;
    exportOptions.includeMetadata = true;
    exportOptions.includeSensitive = false;
    exportOptions.layers = {ConfigLayer::Default, ConfigLayer::User};
    exportOptions.categories = {"export", "secrets"};

    const auto exportedJson = ParseJson(manager.ExportToJson(exportOptions));
    ASSERT_TRUE(exportedJson.contains("values"));
    EXPECT_EQ(exportedJson.at("values").at(defaultKey).get<std::string>(), "balanced");
    EXPECT_EQ(exportedJson.at("values").at(userKey).get<std::string>(), "strict");
    EXPECT_FALSE(exportedJson.at("values").contains(sensitiveKey));
    EXPECT_EQ(exportedJson.at("metadata").at(defaultKey).at("category").get<std::string>(), "export");
    EXPECT_TRUE(exportedJson.at("metadata").at(sensitiveKey).at("isSensitive").get<bool>());

    const std::string importJson = std::string("{\"values\":{\"") + importedFlagKey + "\":true,\"" +
                                   importedCountKey + "\":13,\"" + importedMapKey +
                                   "\":{\"policy\":\"locked\"}}}";
    ASSERT_TRUE(manager.ImportFromJson(importJson, ConfigLayer::Override));
    ASSERT_EQ(manager.GetOptionalValue<bool>(importedFlagKey), std::optional<bool>(true));
    ASSERT_EQ(manager.GetOptionalValue<int64_t>(importedCountKey), std::optional<int64_t>(13));
    ASSERT_EQ(manager.GetOptionalValue<std::string>(importedMapKey), std::optional<std::string>("{\"policy\":\"locked\"}"));

    const auto allKeys = manager.GetAllKeys();
    EXPECT_NE(std::find(allKeys.begin(), allKeys.end(), userKey), allKeys.end());
    EXPECT_NE(std::find(allKeys.begin(), allKeys.end(), importedFlagKey), allKeys.end());

    EXPECT_TRUE(manager.DeleteValue(importedMapKey, ConfigLayer::Override));
    EXPECT_FALSE(manager.DeleteValue(importedMapKey, ConfigLayer::Override));

    ASSERT_TRUE(manager.SetRawValue(defaultKey, ConfigValue{std::string("override")}, ConfigLayer::Session));
    EXPECT_EQ(manager.GetValue<std::string>(defaultKey, ""), "override");
    EXPECT_TRUE(manager.ResetKeyToDefault(defaultKey));
    EXPECT_EQ(manager.GetValue<std::string>(defaultKey, ""), "balanced");

    manager.ResetToDefaults(ConfigLayer::User);
    EXPECT_FALSE(manager.GetValueFromLayer<std::string>(userKey, ConfigLayer::User).has_value());
    EXPECT_GE(observedEvents.size(), 3u);

    const auto stats = manager.GetStatistics();
    EXPECT_GE(stats.snapshotsTaken.load(std::memory_order_relaxed), 1u);
    EXPECT_GE(stats.totalWrites.load(std::memory_order_relaxed), 3u);
}

}  // namespace ShadowStrike::Config::Test
