/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/**
 * @file IoTDeviceRiskScore_Tests.cpp
 * @brief The 0-100 risk score for a discovered device, and the point at which it stops discriminating.
 *
 * IoTDeviceInfo::GetOverallRiskScore is what the IoT page ranks discovered devices by, so it decides
 * which device a user is told to deal with first. It sums four independent contributions and clamps to
 * 100.
 *
 * THE SCALE SATURATES BEFORE THE EVIDENCE RUNS OUT, and that is what these cases record.
 * VulnerabilityLevel::Critical is 5 and the level contributes level * 20, so Critical alone reaches
 * exactly 100. Default credentials add 30, a suspected compromise adds 50, and every open service
 * without authentication adds 10 - and none of it can move a Critical device's score, because the clamp
 * has already been reached. Two Critical devices, one of them compromised with default credentials and
 * three exposed unauthenticated services, are reported as equally risky. An analyst ranking by this
 * number cannot tell them apart.
 *
 * The cases below assert the contributions that DO discriminate, at a vulnerability level low enough to
 * leave headroom, and separately pin the saturation so the limitation is visible rather than folklore.
 * It is filed.
 */

#include "pch.h"

#include <gtest/gtest.h>

#include "Products/Community/PhantomHome/IoT/IoTDeviceScanner.hpp"

namespace ShadowStrike::IoT::Test {
namespace {

/// A device with no findings at all.
[[nodiscard]] IoTDeviceInfo CleanDevice() {
    IoTDeviceInfo d{};
    d.vulnerabilityLevel = VulnerabilityLevel::None;
    d.hasDefaultCredentials = false;
    d.isPotentiallyCompromised = false;
    d.services.clear();
    return d;
}

// Named ExposedService rather than OpenService because <windows.h> defines OpenService
// as a macro expanding to OpenServiceW, which turns the helper into a Win32 call.
[[nodiscard]] ServiceInfo ExposedService(bool requiresAuth) {
    ServiceInfo s{};
    s.isOpen = true;
    s.requiresAuth = requiresAuth;
    return s;
}

TEST(IoTDeviceRiskScoreTest, ACleanDeviceScoresZero) {
    EXPECT_EQ(0, CleanDevice().GetOverallRiskScore())
        << "a device with no vulnerability, no default credentials, no compromise and no services "
           "scored above zero, so the floor of the scale is unreachable";
}

TEST(IoTDeviceRiskScoreTest, TheScoreStaysWithinItsRange) {
    auto worst = CleanDevice();
    worst.vulnerabilityLevel = VulnerabilityLevel::Critical;
    worst.hasDefaultCredentials = true;
    worst.isPotentiallyCompromised = true;
    worst.services = {ExposedService(false), ExposedService(false), ExposedService(false)};
    const int score = worst.GetOverallRiskScore();
    EXPECT_GE(score, 0);
    EXPECT_LE(score, 100) << "the score exceeded 100, so the page cannot render it as a percentage";
}

TEST(IoTDeviceRiskScoreTest, TheVulnerabilityLevelsAreOrdered) {
    // Relational, so a reweighting does not fail this but an inversion does.
    int previous = -1;
    for (const auto level : {VulnerabilityLevel::None, VulnerabilityLevel::Informational,
                             VulnerabilityLevel::Low, VulnerabilityLevel::Medium,
                             VulnerabilityLevel::High, VulnerabilityLevel::Critical}) {
        auto d = CleanDevice();
        d.vulnerabilityLevel = level;
        const int score = d.GetOverallRiskScore();
        EXPECT_GE(score, previous)
            << "raising the vulnerability level lowered the risk score";
        previous = score;
    }
}

TEST(IoTDeviceRiskScoreTest, DefaultCredentialsRaiseTheScore) {
    // Asserted at a level with headroom, because at Critical the clamp hides every other signal.
    auto base = CleanDevice();
    base.vulnerabilityLevel = VulnerabilityLevel::Low;
    auto withCreds = base;
    withCreds.hasDefaultCredentials = true;
    EXPECT_GT(withCreds.GetOverallRiskScore(), base.GetOverallRiskScore())
        << "a device shipping with default credentials scored no higher than one without";
}

TEST(IoTDeviceRiskScoreTest, ASuspectedCompromiseRaisesTheScore) {
    auto base = CleanDevice();
    base.vulnerabilityLevel = VulnerabilityLevel::Low;
    auto compromised = base;
    compromised.isPotentiallyCompromised = true;
    EXPECT_GT(compromised.GetOverallRiskScore(), base.GetOverallRiskScore())
        << "a device suspected of being compromised scored no higher than a healthy one";
}

TEST(IoTDeviceRiskScoreTest, OnlyUnauthenticatedOpenServicesCount) {
    // An open service that demands authentication is not the same exposure as one that does not, and
    // the score must distinguish them or a properly secured device looks as risky as an open one.
    auto authed = CleanDevice();
    authed.vulnerabilityLevel = VulnerabilityLevel::Low;
    authed.services = {ExposedService(true), ExposedService(true)};

    auto unauthed = CleanDevice();
    unauthed.vulnerabilityLevel = VulnerabilityLevel::Low;
    unauthed.services = {ExposedService(false), ExposedService(false)};

    EXPECT_LT(authed.GetOverallRiskScore(), unauthed.GetOverallRiskScore())
        << "open services requiring authentication scored the same as unauthenticated ones";
}

TEST(IoTDeviceRiskScoreTest, MoreExposedServicesRaiseTheScore) {
    auto one = CleanDevice();
    one.vulnerabilityLevel = VulnerabilityLevel::Low;
    one.services = {ExposedService(false)};

    auto three = CleanDevice();
    three.vulnerabilityLevel = VulnerabilityLevel::Low;
    three.services = {ExposedService(false), ExposedService(false), ExposedService(false)};

    EXPECT_LT(one.GetOverallRiskScore(), three.GetOverallRiskScore())
        << "three exposed unauthenticated services scored no higher than one";
}

TEST(IoTDeviceRiskScoreTest, ACriticalDeviceSaturatesTheScaleAndStopsDiscriminating) {
    // CURRENT BEHAVIOUR, pinned so the limitation cannot be forgotten. Critical is level 5 and the
    // level contributes level * 20, which is exactly the clamp, so nothing else can move the number.
    // The consequence is that a Critical device cannot be ranked against another Critical device, which
    // is precisely when ranking matters most. Filed.
    auto critical = CleanDevice();
    critical.vulnerabilityLevel = VulnerabilityLevel::Critical;

    auto criticalAndWorse = critical;
    criticalAndWorse.hasDefaultCredentials = true;
    criticalAndWorse.isPotentiallyCompromised = true;
    criticalAndWorse.services = {ExposedService(false), ExposedService(false), ExposedService(false)};

    EXPECT_EQ(100, critical.GetOverallRiskScore());
    EXPECT_EQ(critical.GetOverallRiskScore(), criticalAndWorse.GetOverallRiskScore())
        << "if this now fails, the level weighting was changed so the scale keeps discriminating at "
           "Critical - update the filing and this comment rather than restoring the saturation";
}

}  // namespace
}  // namespace ShadowStrike::IoT::Test
