/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/**
 * @file IbanValidatorParity_Tests.cpp
 * @brief Two IBAN validators, one definition of an IBAN.
 *
 * TransactionMonitor::ValidateIBAN and DataLeakProtection's IBANCheck both implement the ISO 13616 MOD-97
 * pass, independently. Only the first verified the STRUCTURE first - two letters of country code, two check
 * digits - and MOD-97 alone accepts roughly one string in ninety-seven of a valid length. So an ordinary
 * sixteen-digit reference number was reported as a bank account about one percent of the time, and in a
 * data-leak module a false positive blocks a user's upload.
 *
 * Both now apply the same structural test. The parity case is the point of the file: two functions
 * answering one question will drift unless something requires them to agree.
 */

#include "pch.h"

#include <gtest/gtest.h>

#include "Products/Community/PhantomHome/Banking/TransactionMonitor.hpp"
#include "Products/Community/PhantomHome/Privacy/DataLeakProtection.hpp"

#include <string>
#include <vector>

namespace ShadowStrike::Banking::IbanTest {

// ============================================================================================
// Two IBAN validators, one definition of an IBAN
// ============================================================================================

TEST(IbanValidatorTest, AWellFormedIbanIsAcceptedByBoth) {
    // Anti-vacuity for every rejection below. These are the ISO 13616 published examples.
    const std::vector<std::string> valid = {
        "GB82WEST12345698765432",
        "DE89370400440532013000",
        "FR1420041010050500013M02606",
    };
    auto& dlp = Privacy::DataLeakProtection::Instance();
    for (const auto& iban : valid) {
        EXPECT_TRUE(ValidateIBAN(iban)) << iban << " rejected by TransactionMonitor";
        EXPECT_TRUE(dlp.ValidateIBAN(iban)) << iban << " rejected by DataLeakProtection";
    }
}

TEST(IbanValidatorTest, TheTwoValidatorsAgreeOnEveryProbe) {
    // The duplication is the risk: two functions answering one question, built independently. Only one
    // verified the country code and check digits before its MOD-97 pass, so they disagreed on strings
    // whose arithmetic happened to work out.
    const std::vector<std::string> probes = {
        "GB82WEST12345698765432",
        "DE89370400440532013000",
        "FR1420041010050500013M02606",
        "GB82WEST12345698765433",   // one digit altered
        "1234567890123456",         // numeric country code
        "GBXX WEST12345698765432",  // non-digit check digits and a space
        "GB82WEST1234569876543212345678901234567890",  // over length
        "GB82",                     // under length
        "",
        "not an iban at all",
    };
    auto& dlp = Privacy::DataLeakProtection::Instance();
    for (const auto& iban : probes) {
        EXPECT_EQ(ValidateIBAN(iban), dlp.ValidateIBAN(iban))
            << "the two IBAN validators disagree for \"" << iban
            << "\" - one of the duplicated implementations was changed alone";
    }
}

TEST(IbanValidatorTest, ANumericCountryCodeIsNotAnIban) {
    // MOD-97 alone accepts roughly one string in ninety-seven of a valid length. The structural test is
    // what stops an ordinary reference number being reported as a bank account.
    auto& dlp = Privacy::DataLeakProtection::Instance();
    for (const auto& bad : {"1234567890123456", "12BC370400440532013000", "GBAB370400440532013000"}) {
        EXPECT_FALSE(ValidateIBAN(bad)) << bad << " accepted by TransactionMonitor";
        EXPECT_FALSE(dlp.ValidateIBAN(bad)) << bad << " accepted by DataLeakProtection";
    }
}

TEST(IbanValidatorTest, AWrongCheckDigitIsRejected) {
    // Structure alone must not be sufficient, or the MOD-97 pass would have been replaced rather than
    // supplemented.
    auto& dlp = Privacy::DataLeakProtection::Instance();
    EXPECT_FALSE(ValidateIBAN("GB82WEST12345698765433"));
    EXPECT_FALSE(dlp.ValidateIBAN("GB82WEST12345698765433"));
}

}  // namespace ShadowStrike::Banking::IbanTest
