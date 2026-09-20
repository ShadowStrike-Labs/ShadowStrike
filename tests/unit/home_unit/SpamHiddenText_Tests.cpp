// SPDX-License-Identifier: AGPL-3.0-or-later
/*
 * ShadowStrike Phantom - Spam hidden-text detection tests
 * Copyright (C) 2026 ShadowStrike-Labs
 *
 * This program is free software: you can redistribute it and/or modify it under
 * the terms of the GNU Affero General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option) any
 * later version.
 */

/**
 * @file SpamHiddenText_Tests.cpp
 * @brief Pins which CSS counts as hiding text, and which merely looks like it.
 *
 * HasHiddenText runs on every HTML message and adds 30 to the rule score against a spam threshold of 70, so
 * a false positive puts a legitimate message most of the way to a verdict with a matched rule claiming
 * hidden text. Ten of its patterns searched for a property followed by a bare zero, which also matches the
 * same property with a FRACTIONAL value - opacity:0.95, font-size:0.9em, width:0.5em - all ordinary CSS.
 *
 * The value is now parsed. These cases run in both directions, and the negative ones are the point.
 *
 * This logic had no test before, because the function is in an anonymous namespace and the DetectHiddenText
 * wrapper its own header declares had never been defined. Defining it is what makes these cases possible;
 * no API was widened to do it.
 */

#include "pch.h"

#include <gtest/gtest.h>

#include <string>

#include "Products/Community/PhantomHome/Email/SpamDetector.hpp"

namespace {

using ShadowStrike::Email::DetectHiddenText;
using ShadowStrike::Email::TokenizeForBayes;

std::string Styled(const std::string& css) {
    return "<html><body><p style=\"" + css + "\">buy now</p></body></html>";
}

// ============================================================================
// Genuinely hidden text
// ============================================================================

TEST(SpamHiddenText, WhiteTextIsHidden) {
    EXPECT_TRUE(DetectHiddenText(Styled("color:#fff")));
    EXPECT_TRUE(DetectHiddenText(Styled("color: #ffffff")));
    EXPECT_TRUE(DetectHiddenText(Styled("color:white")));
}

TEST(SpamHiddenText, AHiddenOrCollapsedElementIsHidden) {
    EXPECT_TRUE(DetectHiddenText(Styled("display:none")));
    EXPECT_TRUE(DetectHiddenText(Styled("display: none")));
    EXPECT_TRUE(DetectHiddenText(Styled("visibility:hidden")));
    EXPECT_TRUE(DetectHiddenText(Styled("visibility: hidden")));
}

TEST(SpamHiddenText, AZeroValueIsHiddenInEverySpellingOfZero) {
    // The parsed form accepts more true positives than the old text match did: a bare zero was the only
    // form it recognised, so 0.0 and .0 - which are also fully transparent or zero-sized - were missed.
    for (const char* css : {"opacity:0", "opacity: 0", "opacity:0.0", "opacity: 0.00", "opacity:.0",
                            "opacity:+0", "opacity:-0"}) {
        EXPECT_TRUE(DetectHiddenText(Styled(css))) << css;
    }
    for (const char* css : {"font-size:0", "font-size: 0", "font-size:0px", "font-size:0.0em"}) {
        EXPECT_TRUE(DetectHiddenText(Styled(css))) << css;
    }
    for (const char* css : {"width:0", "width:0px", "height:0", "height: 0%",
                            "max-height:0", "max-width:0px"}) {
        EXPECT_TRUE(DetectHiddenText(Styled(css))) << css;
    }
}

TEST(SpamHiddenText, OffScreenPositioningIsHidden) {
    EXPECT_TRUE(DetectHiddenText(Styled("left:-9999px")));
    EXPECT_TRUE(DetectHiddenText(Styled("top: -9999px")));
    EXPECT_TRUE(DetectHiddenText(Styled("text-indent:-9999px")));
    EXPECT_TRUE(DetectHiddenText(Styled("margin-left:-9999px")));
}

TEST(SpamHiddenText, AOnePixelOverflowContainerIsHidden) {
    // This pair is deliberately conjunctive: overflow:hidden alone is ordinary, and a 1px height alone is
    // ordinary, but together they are the spacer trick.
    EXPECT_TRUE(DetectHiddenText(Styled("overflow:hidden;height:1px")));
    EXPECT_TRUE(DetectHiddenText(Styled("overflow: hidden;max-height:1px")));
    EXPECT_FALSE(DetectHiddenText(Styled("overflow:hidden")))
        << "overflow alone is how any scrolling container is written";
    EXPECT_FALSE(DetectHiddenText(Styled("height:1px")))
        << "a one-pixel rule line is ordinary";
}

// ============================================================================
// Not hidden - the false positives
// ============================================================================

TEST(SpamHiddenText, AFractionalOpacityIsNotHidden) {
    // The defect. Every one of these was reported as hidden text and cost 30 points, because the search for
    // "opacity:0" ends before the fraction.
    for (const char* css : {"opacity:0.95", "opacity: 0.9", "opacity:0.5", "opacity:0.01",
                            "opacity:0.999"}) {
        EXPECT_FALSE(DetectHiddenText(Styled(css))) << css << " is visible";
    }
}

TEST(SpamHiddenText, ARelativeFontSizeIsNotHidden) {
    for (const char* css : {"font-size:0.9em", "font-size: 0.8rem", "font-size:0.75em"}) {
        EXPECT_FALSE(DetectHiddenText(Styled(css))) << css << " is legible";
    }
}

TEST(SpamHiddenText, AFractionalDimensionIsNotHidden) {
    for (const char* css : {"width:0.5em", "height:0.8rem", "max-width:0.9in", "max-height: 0.5cm"}) {
        EXPECT_FALSE(DetectHiddenText(Styled(css))) << css << " has extent";
    }
}

TEST(SpamHiddenText, OrdinaryMarkupIsNotHidden) {
    // Non-vacuity: without these the positive cases would pass against a predicate that always answers true.
    EXPECT_FALSE(DetectHiddenText("<html><body><p>hello</p></body></html>"));
    EXPECT_FALSE(DetectHiddenText(Styled("color:#333;font-size:14px;width:600px")));
    EXPECT_FALSE(DetectHiddenText(Styled("opacity:1")));
    EXPECT_FALSE(DetectHiddenText(Styled("color:black")));
    EXPECT_FALSE(DetectHiddenText(""));
}

TEST(SpamHiddenText, APropertyNameWithoutAnAssignmentIsNotAValue) {
    // The parser requires a colon after the name, so prose or an attribute that merely mentions the property
    // is not read as a declaration.
    EXPECT_FALSE(DetectHiddenText("<p>set the opacity to whatever you like</p>"));
    EXPECT_FALSE(DetectHiddenText("<p>width and height are unset</p>"));
    EXPECT_FALSE(DetectHiddenText("<div data-opacity=\"0\">visible</div>"))
        << "an attribute named for a property is not the property";
}

TEST(SpamHiddenText, ARealMessageWithBothIsHidden) {
    // A mixed document: a legitimate fade next to an actual hidden block. The hidden block must still win.
    const std::string html =
        "<html><body>"
        "<div style=\"opacity:0.95;font-size:0.9em\">Genuine newsletter content</div>"
        "<div style=\"display:none\">pharmacy viagra casino</div>"
        "</body></html>";
    EXPECT_TRUE(DetectHiddenText(html));
}

// ============================================================================
// The tokenizer, now that it links
// ============================================================================

TEST(SpamTokenizer, WordsAreLoweredAndNonAlphanumericIsDropped) {
    const auto tokens = TokenizeForBayes("Buy CHEAP pills, now!!!");
    ASSERT_FALSE(tokens.empty());
    for (const auto& token : tokens) {
        for (const char c : token) {
            const bool ok = (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == ' ';
            EXPECT_TRUE(ok) << "unexpected character in token '" << token << "'";
        }
    }
    EXPECT_NE(tokens.end(), std::find(tokens.begin(), tokens.end(), "cheap")) << "lowered";
}

TEST(SpamTokenizer, BigramsAreEmittedAlongsideSingleWords) {
    const auto tokens = TokenizeForBayes("cheap pills");
    EXPECT_NE(tokens.end(), std::find(tokens.begin(), tokens.end(), "cheap"));
    EXPECT_NE(tokens.end(), std::find(tokens.begin(), tokens.end(), "pills"));
    EXPECT_GT(tokens.size(), 2u) << "a bigram is emitted as well, which is what makes phrase learning work";
}

TEST(SpamTokenizer, EmptyTextYieldsNoTokens) {
    EXPECT_TRUE(TokenizeForBayes("").empty());
    EXPECT_TRUE(TokenizeForBayes("!!! ,,, ...").empty()) << "punctuation alone is not a token";
}

}  // namespace
