/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/**
 * @file WiFiSecurityScore_Tests.cpp
 * @brief The 0-100 score a user is shown for the network they are about to trust.
 *
 * WiFiNetworkInfo::GetOverallScore is what the IoT page renders as a network's security rating, so it
 * is the number a user acts on when deciding whether to connect. It is a sum of six independent
 * terms, which makes it easy to change one weight without noticing that the ORDER of the encryption
 * tiers has stopped holding.
 *
 * That ordering is the property worth pinning, and it is asserted relationally rather than by
 * absolute value: WPA3 must rate above WPA2, WPA2 above WPA, WPA above WEP, and WEP above an open
 * network. A retune that changes the numbers should not fail these; a retune that lets WPA2 rate
 * above WPA3 must.
 *
 * ONE CASE PINS BEHAVIOUR THAT LOOKS WRONG, and says so rather than quietly asserting it as correct:
 * the switch's default arm awards 10 points, so an encryption type the parser did not recognise rates
 * ABOVE WEP at 5 and above an open network at 0. An unrecognised cipher is an unknown quantity, and
 * scoring it in the middle of the range is optimistic where a security rating should be
 * conservative. It is filed for a ruling; the case exists so the number cannot change by accident
 * before that ruling happens.
 */

#include "pch.h"

#include <gtest/gtest.h>

#include "Products/Community/PhantomHome/IoT/WiFiSecurityAnalyzer.hpp"

namespace ShadowStrike::IoT::Test {
namespace {

/// A network that is neutral on every term except encryption, so the encryption tier is isolated.
[[nodiscard]] WiFiNetworkInfo NetworkWith(EncryptionType encryption) {
    WiFiNetworkInfo net{};
    net.encryption = encryption;
    net.pmfEnabled = false;
    net.wpsEnabled = true;      // no bonus
    net.signalStrength = -90;   // below every signal band
    net.isHidden = true;        // no bonus
    net.isWhitelisted = false;  // no bonus
    return net;
}

TEST(WiFiSecurityScoreTest, TheScoreStaysWithinItsRange) {
    // The page renders this as a percentage, so a value outside 0-100 would render nonsensically.
    for (const auto enc : {EncryptionType::Open, EncryptionType::WEP,
                           EncryptionType::WPA_Personal, EncryptionType::WPA2_Personal,
                           EncryptionType::WPA3_Personal}) {
        auto net = NetworkWith(enc);
        EXPECT_GE(net.GetOverallScore(), 0);
        EXPECT_LE(net.GetOverallScore(), 100);
    }
}

TEST(WiFiSecurityScoreTest, TheBestPossibleNetworkReachesTheTop) {
    WiFiNetworkInfo net{};
    net.encryption = EncryptionType::WPA3_SAE;
    net.pmfEnabled = true;
    net.wpsEnabled = false;
    net.signalStrength = -40;
    net.isHidden = false;
    net.isWhitelisted = true;
    EXPECT_EQ(100, net.GetOverallScore())
        << "a network that is ideal on every term does not reach 100, so the scale cannot be read as "
           "a percentage of achievable security";
}

TEST(WiFiSecurityScoreTest, AnOpenNetworkWithEveryWeaknessScoresZero) {
    // Anti-vacuity for the case above: the floor must be reachable too, or the scale is compressed.
    EXPECT_EQ(0, NetworkWith(EncryptionType::Open).GetOverallScore())
        << "an open, WPS-enabled, hidden network with no signal scored above zero";
}

TEST(WiFiSecurityScoreTest, TheEncryptionTiersAreOrderedByStrength) {
    // Relational, so a retune of the weights does not fail this but an inversion does.
    const int open = NetworkWith(EncryptionType::Open).GetOverallScore();
    const int wep = NetworkWith(EncryptionType::WEP).GetOverallScore();
    const int wpa = NetworkWith(EncryptionType::WPA_Personal).GetOverallScore();
    const int wpa2 = NetworkWith(EncryptionType::WPA2_Personal).GetOverallScore();
    const int wpa3 = NetworkWith(EncryptionType::WPA3_Personal).GetOverallScore();

    EXPECT_LT(open, wep) << "an open network rates at or above WEP";
    EXPECT_LT(wep, wpa) << "WEP rates at or above WPA";
    EXPECT_LT(wpa, wpa2) << "WPA rates at or above WPA2";
    EXPECT_LT(wpa2, wpa3) << "WPA2 rates at or above WPA3, so the newest protocol looks no safer";
}

TEST(WiFiSecurityScoreTest, TheEnterpriseVariantsRateWithTheirGeneration) {
    // A user should not see a different rating for the same protocol generation.
    EXPECT_EQ(NetworkWith(EncryptionType::WPA2_Personal).GetOverallScore(),
              NetworkWith(EncryptionType::WPA2_Enterprise).GetOverallScore());
    EXPECT_EQ(NetworkWith(EncryptionType::WPA3_Personal).GetOverallScore(),
              NetworkWith(EncryptionType::WPA3_Enterprise).GetOverallScore());
}

TEST(WiFiSecurityScoreTest, EachHardeningTermRaisesTheScore) {
    // Every term must be able to move the number, or a weight has been silently zeroed.
    const auto base = NetworkWith(EncryptionType::WPA2_Personal);
    const int baseScore = base.GetOverallScore();

    auto pmf = base;
    pmf.pmfEnabled = true;
    EXPECT_GT(pmf.GetOverallScore(), baseScore) << "protected management frames added nothing";

    auto noWps = base;
    noWps.wpsEnabled = false;
    EXPECT_GT(noWps.GetOverallScore(), baseScore) << "disabling WPS added nothing";

    auto visible = base;
    visible.isHidden = false;
    EXPECT_GT(visible.GetOverallScore(), baseScore) << "a non-hidden network gained nothing";

    auto strong = base;
    strong.signalStrength = -45;
    EXPECT_GT(strong.GetOverallScore(), baseScore) << "a strong signal gained nothing";
}

TEST(WiFiSecurityScoreTest, SignalStrengthBandsDoNotInvert) {
    // Monotone in signal quality: a stronger signal must never rate lower.
    auto net = NetworkWith(EncryptionType::WPA2_Personal);
    int previous = -1;
    for (const int dbm : {-90, -80, -70, -60, -50, -40}) {
        net.signalStrength = dbm;
        const int score = net.GetOverallScore();
        EXPECT_GE(score, previous) << "raising the signal to " << dbm << " dBm lowered the score";
        previous = score;
    }
}

TEST(WiFiSecurityScoreTest, AnUnrecognisedEncryptionTypeCurrentlyRatesAboveWep) {
    // CURRENT BEHAVIOUR, pinned rather than endorsed. The switch's default arm awards 10 points, so a
    // cipher the parser did not recognise rates above WEP's 5 and an open network's 0. That is
    // optimistic where a security rating should be conservative, and it is filed for a ruling. If the
    // default is lowered, this case fails and the decision is visible rather than accidental.
    const auto unknown = NetworkWith(EncryptionType::Unknown);
    const auto wep = NetworkWith(EncryptionType::WEP);
    EXPECT_GT(unknown.GetOverallScore(), wep.GetOverallScore())
        << "if this now fails, the default arm was made conservative - update the filing and this "
           "comment rather than restoring the old value";
}

}  // namespace
}  // namespace ShadowStrike::IoT::Test
