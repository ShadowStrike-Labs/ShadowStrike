/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/**
 * @file RouterEncryptionRisk_Tests.cpp
 * @brief The risk level a wireless encryption mode is reported as.
 *
 * GetEncryptionRiskLevel turns an encryption mode into the risk level a user is shown for their router.
 * SecurityRiskLevel is ordered by increasing risk - Secure 0, Informational 1, Low 2, Medium 3, High 4,
 * Critical 5 - so a smaller value is a calmer message.
 *
 * The ordering among the KNOWN modes is correct and is asserted relationally, so a future recalibration
 * does not fail these cases while an inversion does. WEP must outrank Open because a broken cipher
 * invites a false sense of protection that an obviously open network does not.
 *
 * ONE CASE PINS BEHAVIOUR THAT READS AS FAIL-OPEN AND SAYS SO. WirelessEncryption::Unknown matches no
 * case label, so it reaches `default:` and is reported as Informational - level 1, the second calmest
 * value in the scale, better than WPA2. An encryption mode the product could not determine is therefore
 * presented as safer than a properly configured WPA2 network. Filed as a second instance of the same
 * shape already recorded for the WiFi score, which rates unknown encryption above WEP.
 */

#include "pch.h"

#include <gtest/gtest.h>

#include "Products/Community/PhantomHome/IoT/RouterSecurityChecker.hpp"

#include <cstdint>
#include <vector>

namespace ShadowStrike::IoT::Test {
namespace {

[[nodiscard]] int Risk(WirelessEncryption enc) {
    return static_cast<int>(GetEncryptionRiskLevel(enc));
}

}  // namespace

TEST(RouterEncryptionRiskTest, TheKnownModesAreOrderedByActualWeakness) {
    // Relational, not absolute: a recalibration of the levels must not fail this, but an inversion must.
    EXPECT_GT(Risk(WirelessEncryption::WEP), Risk(WirelessEncryption::Open))
        << "WEP must be reported as at least as risky as an open network - a broken cipher invites "
           "trust that an obviously open network does not";
    EXPECT_GT(Risk(WirelessEncryption::Open), Risk(WirelessEncryption::WPA_Personal));
    EXPECT_GT(Risk(WirelessEncryption::WPA_Personal), Risk(WirelessEncryption::WPA2_Personal));
    EXPECT_GT(Risk(WirelessEncryption::WPA2_Personal), Risk(WirelessEncryption::WPA3_Personal));
}

TEST(RouterEncryptionRiskTest, TheEnterpriseVariantsMatchTheirPersonalCounterparts) {
    EXPECT_EQ(Risk(WirelessEncryption::WPA_Personal), Risk(WirelessEncryption::WPA_Enterprise));
    EXPECT_EQ(Risk(WirelessEncryption::WPA2_Personal), Risk(WirelessEncryption::WPA2_Enterprise));
    EXPECT_EQ(Risk(WirelessEncryption::WPA3_Personal), Risk(WirelessEncryption::WPA3_Enterprise));
    EXPECT_EQ(Risk(WirelessEncryption::WPA3_Personal), Risk(WirelessEncryption::WPA3_SAE));
}

TEST(RouterEncryptionRiskTest, TheBestAndWorstModesReachTheEndsOfTheScale) {
    // Anti-vacuity for the relational cases: a function returning one constant would satisfy the
    // equalities above and every GT would fail, but a function using only the middle of the scale would
    // pass them while never telling a user anything is safe or critical.
    EXPECT_EQ(static_cast<int>(SecurityRiskLevel::Secure), Risk(WirelessEncryption::WPA3_SAE));
    EXPECT_EQ(static_cast<int>(SecurityRiskLevel::Critical), Risk(WirelessEncryption::WEP));
}

TEST(RouterEncryptionRiskTest, AMixedModeNetworkIsNoSaferThanItsWeakestMember) {
    // Mixed means some clients negotiate the older cipher, so it cannot be calmer than WPA.
    EXPECT_GE(Risk(WirelessEncryption::Mixed), Risk(WirelessEncryption::WPA_Personal));
}

TEST(RouterEncryptionRiskTest, AnUndeterminedEncryptionIsReportedCalmerThanWpa2) {
    // PINNED, NOT ENDORSED. Unknown matches no case label and reaches `default:`, which returns
    // Informational - level 1 of 5, calmer than WPA2's Low. So a router whose encryption could not be
    // determined is presented as safer than one correctly configured with WPA2, and a parse failure
    // reads to the user as reassurance.
    //
    // Filed as a second instance of the shape already recorded for the WiFi security score. If this case
    // now fails, the mapping was made conservative - update the filings and delete this case rather than
    // restoring the calmer answer.
    EXPECT_LT(Risk(WirelessEncryption::Unknown), Risk(WirelessEncryption::WPA2_Personal))
        << "an undetermined encryption mode is no longer reported as calmer than WPA2";
    EXPECT_EQ(static_cast<int>(SecurityRiskLevel::Informational),
              Risk(WirelessEncryption::Unknown));
}

TEST(RouterEncryptionRiskTest, AValueOutsideTheEnumIsNotReportedAsSecure) {
    // Whatever the default becomes, it must never claim a network is Secure. That is the one answer
    // that would actively mislead, because it is the only level that means no action is needed.
    const auto bogus = static_cast<WirelessEncryption>(240);
    EXPECT_NE(static_cast<int>(SecurityRiskLevel::Secure), Risk(bogus))
        << "an unrecognised encryption value was reported as Secure";
}

}  // namespace ShadowStrike::IoT::Test
