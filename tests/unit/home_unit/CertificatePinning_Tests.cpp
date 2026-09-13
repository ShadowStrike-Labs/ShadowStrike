/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/**
 * @file CertificatePinning_Tests.cpp
 * @brief Certificate validity windows, and the one convention all three accessors must share.
 *
 * CertificateInfo has three accessors that read the same two dates, and before the change these
 * tests accompany they disagreed about an unset date: IsExpired and IsNotYetValid treated the epoch
 * as "no constraint" and answered valid, while GetDaysUntilExpiry treated it as a real date and
 * returned roughly -20000. A caller testing expiry as GetDaysUntilExpiry() < 0 therefore reached the
 * opposite conclusion from IsExpired() on the same object.
 *
 * The direction chosen is fail-closed, and the reason is specific rather than general: notBefore and
 * notAfter are mandatory X.509 fields, so on this struct an unset date can only mean the certificate
 * was never parsed, and an unparsed certificate must not read as valid forever.
 *
 * CertificatePin is asserted separately and in the OPPOSITE direction, because there an unset
 * expiration genuinely means a permanent pin. Holding both in one file is deliberate: the two
 * structs use the same idiom for different reasons, and a future reader unifying them would break
 * one of them.
 */

#include "pch.h"

#include <gtest/gtest.h>

#include "Products/Community/PhantomHome/Banking/CertificatePinning.hpp"

#include <chrono>

namespace ShadowStrike::Banking::Test {
namespace {

using Clock = std::chrono::system_clock;

[[nodiscard]] CertificateInfo CertValidFor(std::chrono::hours span) {
    CertificateInfo cert;
    cert.subject = "CN=Test Subject";
    cert.notBefore = Clock::now() - span;
    cert.notAfter = Clock::now() + span;
    return cert;
}

// ============================================================================================
// A parsed certificate with real dates
// ============================================================================================

TEST(CertificateValidityTest, ACurrentCertificateIsNeitherExpiredNorPremature) {
    const auto cert = CertValidFor(std::chrono::hours{24});
    EXPECT_FALSE(cert.IsExpired());
    EXPECT_FALSE(cert.IsNotYetValid());
}

TEST(CertificateValidityTest, APastCertificateIsExpired) {
    CertificateInfo cert;
    cert.notBefore = Clock::now() - std::chrono::hours{48};
    cert.notAfter = Clock::now() - std::chrono::hours{24};
    EXPECT_TRUE(cert.IsExpired());
    EXPECT_FALSE(cert.IsNotYetValid())
        << "a certificate whose window has passed is expired, not premature";
}

TEST(CertificateValidityTest, AFutureCertificateIsNotYetValid) {
    CertificateInfo cert;
    cert.notBefore = Clock::now() + std::chrono::hours{24};
    cert.notAfter = Clock::now() + std::chrono::hours{48};
    EXPECT_TRUE(cert.IsNotYetValid());
    EXPECT_FALSE(cert.IsExpired())
        << "a certificate whose window has not opened is premature, not expired";
}

TEST(CertificateValidityTest, TheRemainingDaysMatchTheWindow) {
    CertificateInfo cert;
    cert.notBefore = Clock::now() - std::chrono::hours{24};
    cert.notAfter = Clock::now() + std::chrono::hours{24 * 30};
    const auto days = cert.GetDaysUntilExpiry();
    EXPECT_GE(days, 29) << "a certificate 30 days from expiry reported " << days;
    EXPECT_LE(days, 30);
}

// ============================================================================================
// The convention for a date that was never parsed
// ============================================================================================

TEST(CertificateValidityTest, AnUnparsedCertificateDoesNotReadAsValid) {
    // notBefore and notAfter are mandatory X.509 fields, so an unset date means the certificate was
    // never parsed. Reading that as "valid forever" is the wrong direction for a trust decision.
    const CertificateInfo unparsed;
    EXPECT_TRUE(unparsed.IsExpired())
        << "a certificate with no parsed expiry reads as valid, so the pinning validator's expiry "
           "branch is skipped for it";
    EXPECT_TRUE(unparsed.IsNotYetValid())
        << "a certificate with no parsed start date reads as already valid";
}

TEST(CertificateValidityTest, TheThreeAccessorsAgreeAboutAnUnparsedDate) {
    // THE DEFECT THIS FILE EXISTS FOR. IsExpired answered "valid" while GetDaysUntilExpiry answered
    // "expired about 20000 days ago" for the same object, so two callers could reach opposite
    // conclusions from the same certificate.
    const CertificateInfo unparsed;
    EXPECT_EQ(0, unparsed.GetDaysUntilExpiry())
        << "GetDaysUntilExpiry fabricated a date from the epoch instead of reporting that there is "
           "no parsed expiry, which contradicts IsExpired on the same object";
}

TEST(CertificateValidityTest, AParsedCertificateIsUnaffectedByTheConvention) {
    // Anti-vacuity: the convention must apply ONLY to unset dates. If it leaked into parsed
    // certificates, every real certificate would read as expired.
    const auto cert = CertValidFor(std::chrono::hours{24 * 10});
    EXPECT_FALSE(cert.IsExpired());
    EXPECT_FALSE(cert.IsNotYetValid());
    EXPECT_GT(cert.GetDaysUntilExpiry(), 0);
}

// ============================================================================================
// The sibling struct, whose identical idiom means something different
// ============================================================================================

TEST(CertificatePinValidityTest, APinWithNoExpiryIsPermanent) {
    // The OPPOSITE direction from CertificateInfo, deliberately. A pin without an expiration is a
    // permanent pin, not an unparsed one, so it must not read as expired - if it did, every
    // permanent pin would be skipped by the "if (pin.IsExpired()) continue;" filters and pinning
    // would silently stop enforcing.
    const CertificatePin pin;
    EXPECT_FALSE(pin.IsExpired())
        << "a pin with no configured expiry reads as expired, which would disable permanent pins";
}

TEST(CertificatePinValidityTest, APinPastItsExpiryIsExpired) {
    CertificatePin pin;
    pin.expiration = Clock::now() - std::chrono::hours{1};
    EXPECT_TRUE(pin.IsExpired());
}

}  // namespace
}  // namespace ShadowStrike::Banking::Test
