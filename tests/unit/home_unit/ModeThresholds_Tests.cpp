/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/**
 * @file ModeThresholds_Tests.cpp
 * @brief What Passive, Balanced and Aggressive actually mean, and that they stay ordered.
 *
 * ApplyModeThresholds is described by its own header as "the single authority for what Passive,
 * Balanced and Aggressive mean in terms of concrete config keys", and the header carries a table
 * of the four values per mode. Nothing verified that the code agreed with that table, and nothing
 * verified the property that makes the three modes a scale rather than three unrelated presets.
 *
 * THE INVARIANT THAT MATTERS IS RELATIONAL, NOT THE INDIVIDUAL NUMBERS. Sensitivity rises
 * 25 -> 60 -> 90 while the AI confidence bar FALLS 0.85 -> 0.70 -> 0.55, because a lower
 * confidence threshold admits more detections. Those two move in opposite directions, so a
 * plausible-looking edit to one number can invert the scale and make a more aggressive mode less
 * sensitive than a less aggressive one. That inversion would not crash, would not fail a build,
 * and would not be visible in any log - the product would simply detect less in Aggressive mode
 * than in Balanced. The ordering cases below are the reason this file exists; the exact-value
 * cases exist so the header's documented table cannot drift from the code silently.
 *
 * The rejection cases cover the validation the implementation performs on the module name before
 * it builds a ConfigManager key, because a malformed name produces a corrupted key path such as
 * "Home//Sensitivity" that would desync from the orchestrator's convention or collide with an
 * unrelated subtree.
 */

#include "pch.h"

#include <gtest/gtest.h>

#include "Products/Community/PhantomHome/ModeThresholds.hpp"
#include "PhantomCore/Config/ConfigManager.hpp"

#include <filesystem>
#include <string>
#include <system_error>

namespace ShadowStrike::Products::Home::Test {
namespace {

using ::ShadowStrike::Config::ConfigManager;

class ModeThresholdsTest : public ::testing::Test {
protected:
    void SetUp() override {
        auto& cfg = ConfigManager::Instance();
        cfg.Shutdown();
        std::error_code ec;
        m_dir = std::filesystem::temp_directory_path(ec) / L"ss_mode_thresholds_tests";
        std::filesystem::create_directories(m_dir, ec);
        m_db = m_dir / L"config.db";
        std::filesystem::remove(m_db, ec);
        ASSERT_TRUE(cfg.Initialize(m_db.wstring()))
            << "ConfigManager could not be initialised, so the written values cannot be read back";
    }

    void TearDown() override {
        ConfigManager::Instance().Shutdown();
        std::error_code ec;
        std::filesystem::remove_all(m_dir, ec);
    }

    struct Applied {
        std::int32_t sensitivity = -1;
        double aiConfidence = -1.0;
        bool blockOnSuspicion = false;
        bool detectOnly = false;
    };

    /// Applies a mode to a uniquely named module and reads the four keys back.
    [[nodiscard]] Applied ApplyAndRead(const std::string& moduleName, ProtectionMode mode) {
        EXPECT_TRUE(ApplyModeThresholds(moduleName, mode))
            << "ApplyModeThresholds rejected a valid module name and mode";
        auto& cfg = ConfigManager::Instance();
        const std::string prefix = "Home/" + moduleName + "/";
        Applied a;
        a.sensitivity = cfg.GetValue<std::int32_t>(prefix + "Sensitivity", -1);
        a.aiConfidence = cfg.GetValue<double>(prefix + "AIConfidenceThreshold", -1.0);
        a.blockOnSuspicion = cfg.GetValue<bool>(prefix + "BlockOnSuspicion", false);
        a.detectOnly = cfg.GetValue<bool>(prefix + "DetectOnly", false);
        return a;
    }

    std::filesystem::path m_dir;
    std::filesystem::path m_db;
};

// ============================================================================================
// The documented table
// ============================================================================================

TEST_F(ModeThresholdsTest, PassiveWritesTheDocumentedValues) {
    const auto a = ApplyAndRead("TestModulePassive", ProtectionMode::Passive);
    EXPECT_EQ(25, a.sensitivity);
    EXPECT_DOUBLE_EQ(0.85, a.aiConfidence);
    EXPECT_FALSE(a.blockOnSuspicion) << "Passive must not block on suspicion";
    EXPECT_TRUE(a.detectOnly) << "Passive must be detect-only";
}

TEST_F(ModeThresholdsTest, BalancedWritesTheDocumentedValues) {
    const auto a = ApplyAndRead("TestModuleBalanced", ProtectionMode::Balanced);
    EXPECT_EQ(60, a.sensitivity);
    EXPECT_DOUBLE_EQ(0.70, a.aiConfidence);
    EXPECT_TRUE(a.blockOnSuspicion);
    EXPECT_FALSE(a.detectOnly);
}

TEST_F(ModeThresholdsTest, AggressiveWritesTheDocumentedValues) {
    const auto a = ApplyAndRead("TestModuleAggressive", ProtectionMode::Aggressive);
    EXPECT_EQ(90, a.sensitivity);
    EXPECT_DOUBLE_EQ(0.55, a.aiConfidence);
    EXPECT_TRUE(a.blockOnSuspicion);
    EXPECT_FALSE(a.detectOnly);
}

// ============================================================================================
// The ordering - the property that makes these a scale
// ============================================================================================

TEST_F(ModeThresholdsTest, SensitivityRisesWithEachMode) {
    const auto passive = ApplyAndRead("OrderSensPassive", ProtectionMode::Passive);
    const auto balanced = ApplyAndRead("OrderSensBalanced", ProtectionMode::Balanced);
    const auto aggressive = ApplyAndRead("OrderSensAggressive", ProtectionMode::Aggressive);

    EXPECT_LT(passive.sensitivity, balanced.sensitivity)
        << "Balanced is no more sensitive than Passive, so the scale is inverted";
    EXPECT_LT(balanced.sensitivity, aggressive.sensitivity)
        << "Aggressive is no more sensitive than Balanced, so the scale is inverted";
}

TEST_F(ModeThresholdsTest, TheAiConfidenceBarFallsWithEachMode) {
    // A LOWER threshold admits more detections, so this must move opposite to sensitivity.
    // Asserting it separately from sensitivity is deliberate: the two are easy to conflate, and
    // raising this value in Aggressive mode would quietly reduce detection.
    const auto passive = ApplyAndRead("OrderAiPassive", ProtectionMode::Passive);
    const auto balanced = ApplyAndRead("OrderAiBalanced", ProtectionMode::Balanced);
    const auto aggressive = ApplyAndRead("OrderAiAggressive", ProtectionMode::Aggressive);

    EXPECT_GT(passive.aiConfidence, balanced.aiConfidence)
        << "Balanced demands at least as much AI confidence as Passive, so it detects no more";
    EXPECT_GT(balanced.aiConfidence, aggressive.aiConfidence)
        << "Aggressive demands at least as much AI confidence as Balanced, so it detects no more";
}

TEST_F(ModeThresholdsTest, OnlyPassiveIsDetectOnly) {
    // If an active mode became detect-only, the product would report threats and act on none of
    // them while still describing itself as protecting.
    EXPECT_TRUE(ApplyAndRead("DetectOnlyPassive", ProtectionMode::Passive).detectOnly);
    EXPECT_FALSE(ApplyAndRead("DetectOnlyBalanced", ProtectionMode::Balanced).detectOnly);
    EXPECT_FALSE(ApplyAndRead("DetectOnlyAggressive", ProtectionMode::Aggressive).detectOnly);
}

// ============================================================================================
// Module name validation - a malformed name corrupts the key path
// ============================================================================================

TEST_F(ModeThresholdsTest, AnEmptyModuleNameIsRejected) {
    EXPECT_FALSE(ApplyModeThresholds("", ProtectionMode::Balanced))
        << "an empty name yields the key \"Home//Sensitivity\"";
}

TEST_F(ModeThresholdsTest, APathSeparatorInTheModuleNameIsRejected) {
    // "Home/a/b/Sensitivity" would either desync from the orchestrator's key convention or
    // collide with an unrelated configuration subtree.
    EXPECT_FALSE(ApplyModeThresholds("a/b", ProtectionMode::Balanced));
    EXPECT_FALSE(ApplyModeThresholds("a\\b", ProtectionMode::Balanced));
}

TEST_F(ModeThresholdsTest, AControlCharacterInTheModuleNameIsRejected) {
    EXPECT_FALSE(ApplyModeThresholds(std::string("bad\x01name"), ProtectionMode::Balanced));
    EXPECT_FALSE(ApplyModeThresholds(std::string("bad\x7F""name"), ProtectionMode::Balanced));
}

TEST_F(ModeThresholdsTest, AnAbsurdlyLongModuleNameIsRejected) {
    EXPECT_TRUE(ApplyModeThresholds(std::string(128, 'a'), ProtectionMode::Balanced))
        << "128 characters is the documented limit and must be accepted";
    EXPECT_FALSE(ApplyModeThresholds(std::string(129, 'a'), ProtectionMode::Balanced))
        << "129 characters exceeds the limit and must be rejected";
}

TEST_F(ModeThresholdsTest, OffIsRejectedRatherThanSilentlyTreatedAsAMode) {
    // Off is the orchestrator's shutdown path. If this helper accepted it, a module would be left
    // registered and running with sensitivity 0 rather than actually stopped - protection that
    // reports as configured and examines nothing.
    EXPECT_FALSE(ApplyModeThresholds("TestModuleOff", ProtectionMode::Off));
}

}  // namespace
}  // namespace ShadowStrike::Products::Home::Test
