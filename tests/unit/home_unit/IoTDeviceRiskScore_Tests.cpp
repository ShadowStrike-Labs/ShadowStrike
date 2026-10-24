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
 * IoTDeviceInfo::GetOverallRiskScore ranks discovered devices. The vulnerability level holds at most
 * 60 of the 100 points and the concrete findings (risk factors, default credentials, a suspected
 * compromise, unauthenticated open services) at most 40 (task 277). Before, the level contributed
 * level * 20, so Critical alone was the clamp and every finding on a Critical device was discarded.
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

TEST(IoTDeviceRiskScoreTest, FindingsStillRankCriticalDevices) {
    auto critical = CleanDevice();
    critical.vulnerabilityLevel = VulnerabilityLevel::Critical;
    auto compromised = critical;
    compromised.isPotentiallyCompromised = true;
    auto compromisedWithCreds = compromised;
    compromisedWithCreds.hasDefaultCredentials = true;

    EXPECT_LT(critical.GetOverallRiskScore(), compromised.GetOverallRiskScore())
        << "a suspected compromise did not raise a Critical device above a bare Critical one";
    EXPECT_LT(compromised.GetOverallRiskScore(), compromisedWithCreds.GetOverallRiskScore());
    EXPECT_EQ(100, compromisedWithCreds.GetOverallRiskScore());
}

TEST(IoTDeviceRiskScoreTest, TheLevelAloneNeverReachesTheTop) {
    auto critical = CleanDevice();
    critical.vulnerabilityLevel = VulnerabilityLevel::Critical;
    EXPECT_EQ(60, critical.GetOverallRiskScore());
}

TEST(IoTDeviceRiskScoreTest, AnInformationalLevelWeighsLessThanFourRiskFactors) {
    // Informational carried 20 of 100, more than four risk factors together.
    auto info = CleanDevice();
    info.vulnerabilityLevel = VulnerabilityLevel::Informational;
    auto fourFactors = CleanDevice();
    fourFactors.risks = RiskFactor::OpenTelnet | RiskFactor::UPnPEnabled | RiskFactor::WPSEnabled |
                        RiskFactor::NoEncryption;
    EXPECT_LT(info.GetOverallRiskScore(), fourFactors.GetOverallRiskScore());
    EXPECT_GT(info.GetOverallRiskScore(), 0);
}

}  // namespace
}  // namespace ShadowStrike::IoT::Test
