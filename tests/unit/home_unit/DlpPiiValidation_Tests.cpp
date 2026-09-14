/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/**
 * @file DlpPiiValidation_Tests.cpp
 * @brief Recognising personal data, and not revealing it once recognised.
 *
 * These are the two halves of a data-leak module's contract with the user, and they fail in opposite
 * directions, so they are asserted with opposite emphasis.
 *
 *   VALIDATION decides whether something IS personal data. A false positive here blocks a legitimate
 *   upload, so the cases lean on inputs that must be REJECTED. The defect this file was written against
 *   lived here: ValidateCreditCard was a bare Luhn check with no length policy, and Luhn is satisfied by
 *   "0", "18", "26" and "00", so a two-character token was a credit card. The same file already knew
 *   the minimum - MaskCreditCard refuses to reveal anything shorter than 13 digits - which is what made
 *   it an oversight rather than a decision.
 *
 *   MASKING decides how much of it to show once found. A defect here leaks the data the module exists
 *   to protect, into a report the user reads, so the cases assert what must NOT appear in the output.
 *   Both maskers are correct and are pinned so they stay that way; the interesting property is that
 *   masking is monotone in ignorance - given LESS confidence about the input, they reveal LESS.
 */

#include "pch.h"

#include <gtest/gtest.h>

#include "Products/Community/PhantomHome/Privacy/DataLeakProtection.hpp"

#include <string>

namespace ShadowStrike::Privacy::Test {
namespace {

/// A Luhn-valid 16-digit test number. Not a real card: the 4-prefix range is reserved for testing.
constexpr const char* kValidCard16 = "4532015112830366";

class DlpPiiValidationTest : public ::testing::Test {
protected:
    static void SetUpTestSuite() {
        ASSERT_TRUE(DataLeakProtection::Instance().Initialize())
            << "the module could not be initialised, so no verdict below would mean anything";
    }

    static DataLeakProtection& Dlp() { return DataLeakProtection::Instance(); }
};

// ============================================================================================
// Credit card validation
// ============================================================================================

TEST_F(DlpPiiValidationTest, AValidCardNumberIsAccepted) {
    // Anti-vacuity for every rejection below: if this fails the validator recognises nothing and the
    // rejections would all hold for the wrong reason.
    EXPECT_TRUE(Dlp().ValidateCreditCard(kValidCard16));
    EXPECT_TRUE(Dlp().ValidateCreditCard("4532 0151 1283 0366")) << "spaces must be tolerated";
    EXPECT_TRUE(Dlp().ValidateCreditCard("4532-0151-1283-0366")) << "dashes must be tolerated";
}

TEST_F(DlpPiiValidationTest, AShortLuhnValidTokenIsNotACardNumber) {
    // The defect. All of these satisfy the Luhn checksum, and none is a card number - no scheme issues
    // fewer than 12 digits. In a data-leak module each one is a false positive that blocks an upload.
    EXPECT_FALSE(Dlp().ValidateCreditCard("0")) << "a single zero satisfies Luhn and was accepted";
    EXPECT_FALSE(Dlp().ValidateCreditCard("00"));
    EXPECT_FALSE(Dlp().ValidateCreditCard("18")) << "1*2 + 8 = 10, so Luhn passes";
    EXPECT_FALSE(Dlp().ValidateCreditCard("26"));
    EXPECT_FALSE(Dlp().ValidateCreditCard("34"));
    EXPECT_FALSE(Dlp().ValidateCreditCard("000000000")) << "nine zeros";
}

TEST_F(DlpPiiValidationTest, TheAcceptedLengthRangeCoversEveryIssuedCardLength) {
    // ISO/IEC 7812 permits 12 to 19 digits. The bound must not be tighter than that, or a real card
    // stops being detected - which would be a detection loss dressed as a precision fix. A floor of 13
    // would reject a 12-digit Maestro number.
    // The checksum is asserted separately so this case tests the LENGTH bound and nothing else. Without
    // that, a failure here could mean either that the floor is wrong or that the test data is - and the
    // first draft of this case used a 12-digit number whose Luhn sum was 47, so it failed for the second
    // reason and looked like the first.
    ASSERT_TRUE(LuhnCheck("123456789015")) << "the 12-digit probe must itself be checksum-valid";
    EXPECT_TRUE(Dlp().ValidateCreditCard("123456789015"))
        << "a 12-digit card length was rejected, so the floor is too high and a Maestro number would "
           "not be detected";

    ASSERT_TRUE(LuhnCheck("12345678903")) << "the 11-digit probe must itself be checksum-valid, so its "
                                             "rejection can only be the length bound";
    EXPECT_FALSE(Dlp().ValidateCreditCard("12345678903"))
        << "11 digits is below every issued length";
}

TEST_F(DlpPiiValidationTest, AnOverlongNumberIsNotACardNumber) {
    // Checksum-valid at 20 digits, so the rejection can only be the ceiling. ISO/IEC 7812 stops at 19.
    ASSERT_TRUE(LuhnCheck("12345678901234567894"));
    EXPECT_FALSE(Dlp().ValidateCreditCard("12345678901234567894"))
        << "20 digits is above every issued length";
}

TEST_F(DlpPiiValidationTest, AWrongChecksumIsRejectedAtAValidLength) {
    // Length alone must not be sufficient, or the Luhn check would have been replaced rather than
    // supplemented.
    EXPECT_FALSE(Dlp().ValidateCreditCard("4532015112830367")) << "last digit altered";
    EXPECT_FALSE(Dlp().ValidateCreditCard("1234567890123456"));
}

TEST_F(DlpPiiValidationTest, EmptyAndNonNumericInputIsRejected) {
    EXPECT_FALSE(Dlp().ValidateCreditCard(""));
    EXPECT_FALSE(Dlp().ValidateCreditCard("not a card"));
    EXPECT_FALSE(Dlp().ValidateCreditCard("****************"));
}

TEST_F(DlpPiiValidationTest, TheChecksumPrimitiveItselfStillAcceptsShortInput) {
    // LuhnCheck is a public free function shared with other number kinds, so it deliberately applies NO
    // length policy - the Luhn algorithm has nothing to say about payload length. These two assertions
    // are what prove the fix landed in the card validator rather than by narrowing the primitive: the
    // primitive still answers true for "18", and ValidateCreditCard no longer does.
    EXPECT_TRUE(LuhnCheck("18")) << "the checksum primitive was narrowed instead of the validator";
    EXPECT_TRUE(LuhnCheck("0"));
    EXPECT_FALSE(LuhnCheck("")) << "the empty guard is the primitive's only length rule";
    EXPECT_FALSE(LuhnCheck("19")) << "a wrong checksum at the same length";
    EXPECT_FALSE(Dlp().ValidateCreditCard("18"))
        << "the validator must reject what the primitive accepts, because length is card policy";
}

// ============================================================================================
// Social security number validation
// ============================================================================================

TEST_F(DlpPiiValidationTest, AWellFormedSsnIsAccepted) {
    EXPECT_TRUE(Dlp().ValidateSSN("123-45-6789"));
    EXPECT_TRUE(Dlp().ValidateSSN("123456789"));
}

TEST_F(DlpPiiValidationTest, TheNeverIssuedSsnRangesAreRejected) {
    // These groups are not and never were issued, so accepting them is a false positive on ordinary
    // nine-digit numbers - an order reference or a phone number without separators.
    EXPECT_FALSE(Dlp().ValidateSSN("000-45-6789")) << "area 000 is never issued";
    EXPECT_FALSE(Dlp().ValidateSSN("666-45-6789")) << "area 666 is never issued";
    EXPECT_FALSE(Dlp().ValidateSSN("900-45-6789")) << "areas 900 and above are never issued";
    EXPECT_FALSE(Dlp().ValidateSSN("999-99-9999"));
    EXPECT_FALSE(Dlp().ValidateSSN("123-00-6789")) << "group 00 is never issued";
    EXPECT_FALSE(Dlp().ValidateSSN("123-45-0000")) << "serial 0000 is never issued";
}

TEST_F(DlpPiiValidationTest, AWrongLengthIsNotAnSsn) {
    EXPECT_FALSE(Dlp().ValidateSSN("12345678")) << "eight digits";
    EXPECT_FALSE(Dlp().ValidateSSN("1234567890")) << "ten digits";
    EXPECT_FALSE(Dlp().ValidateSSN(""));
}

// ============================================================================================
// Masking - what must never appear in the output
// ============================================================================================

TEST_F(DlpPiiValidationTest, MaskingACardRevealsOnlyTheFirstAndLastFour) {
    const std::string masked = MaskCreditCard(kValidCard16);
    EXPECT_EQ("4532********0366", masked);
    EXPECT_EQ(std::string(kValidCard16).length(), masked.length())
        << "the masked form must not disclose a different length than the input";
    EXPECT_EQ(std::string::npos, masked.find("0151"))
        << "an interior digit group survived masking";
    EXPECT_EQ(std::string::npos, masked.find("1283"));
}

TEST_F(DlpPiiValidationTest, MaskingRevealsLessWhenTheInputIsNotCardShaped) {
    // Masking is monotone in ignorance: given something it cannot interpret, it reveals nothing rather
    // than falling back on showing the ends. This is the property that makes the masker safe to call on
    // unvalidated input.
    EXPECT_EQ("****", MaskCreditCard("123"));
    EXPECT_EQ("****", MaskCreditCard(""));
    EXPECT_EQ("****", MaskCreditCard("123456789012"))
        << "a 12-digit number is masked entirely - deliberately stricter than the validator's floor, "
           "because masking more is never a leak";
}

TEST_F(DlpPiiValidationTest, MaskingAnSsnRevealsOnlyTheLastFour) {
    const std::string masked = MaskSSN("123-45-6789");
    EXPECT_EQ("***-**-6789", masked);
    EXPECT_EQ(std::string::npos, masked.find("123")) << "the area number survived masking";
    EXPECT_EQ(std::string::npos, masked.find("45")) << "the group number survived masking";
}

TEST_F(DlpPiiValidationTest, MaskingAMalformedSsnRevealsNothing) {
    EXPECT_EQ("***-**-****", MaskSSN("12345"));
    EXPECT_EQ("***-**-****", MaskSSN(""));
    EXPECT_EQ("***-**-****", MaskSSN("1234567890"))
        << "a ten-digit input revealed digits, so an over-long input is being treated as an SSN";
}

}  // namespace
}  // namespace ShadowStrike::Privacy::Test
