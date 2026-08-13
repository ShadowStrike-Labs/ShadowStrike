/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */
// ============================================================================
// THREAT LEVEL MAPPING TESTS
// ============================================================================
//
// The threat level a detection carries decides whether it is a conviction or an
// indicator: ScanEngine maps ThreatLevel::Info to ScanVerdict::Suspicious
// (reported and monitored) and everything above it to ScanVerdict::Infected
// (blocked and quarantined). So a mistake in this mapping is a detection defect,
// in either direction - a level read too low stops a real threat from being
// blocked, and one read too high turns an informational rule into a quarantine.
//
// MEASURED FACTS ABOUT THE SHIPPED RULESET that these tests exist to protect:
//   11,716 rule declarations
//   11,716 carry `score = <integer>`   (the YARA Forge convention)
//        57 carry `severity = critical`
//        13 carry `severity = high`
//        38 carry `level = Experimental`
//         1 carries `threat_level = <integer>`
// So only 70 rules state a severity in words while ALL of them state a score.
// Before score was honoured, 11,646 rules reported a blanket Medium default.
// Honouring it yields 652 Low, 1348 Medium, 9706 High, 10 Critical.
//
// THE COLLISION THIS FILE GUARDS: `severity` uses a 0-5 ordinal where 5 is
// Critical, while `score` uses 0-100 where 5 would be almost nothing. Reading a
// score through the ordinal branch would invert the meaning at the low end and
// silently fall back to Medium in the middle. That is why they are separate
// branches, and why there is a test for exactly that value.
// ============================================================================

#include <map>
#include <string>

// ============================================================================
// GTEST
// ============================================================================

#include <gtest/gtest.h>

// ============================================================================
// SHADOWSTRIKE MODULE HEADERS
// ============================================================================

#include "src/PhantomCore/SignatureStore/YaraRuleStore.hpp"

using ShadowStrike::SignatureStore::ThreatLevel;
namespace YaraUtils = ShadowStrike::SignatureStore::YaraUtils;

namespace {

ThreatLevel Parse(std::map<std::string, std::string> meta) {
    return YaraUtils::ParseThreatLevel(meta);
}

} // namespace

// ============================================================================
// AN EXPLICIT SEVERITY IS A HUMAN JUDGEMENT AND WINS
// ============================================================================

TEST(ThreatLevelMapping_Severity, WordsMapToTheirLevels) {
    EXPECT_EQ(Parse({{"severity", "critical"}}), ThreatLevel::Critical);
    EXPECT_EQ(Parse({{"severity", "high"}}),     ThreatLevel::High);
    EXPECT_EQ(Parse({{"severity", "medium"}}),   ThreatLevel::Medium);
    EXPECT_EQ(Parse({{"severity", "low"}}),      ThreatLevel::Low);
}

TEST(ThreatLevelMapping_Severity, CaseInsensitive) {
    EXPECT_EQ(Parse({{"severity", "CRITICAL"}}), ThreatLevel::Critical);
    EXPECT_EQ(Parse({{"severity", "High"}}),     ThreatLevel::High);
}

TEST(ThreatLevelMapping_Severity, SynonymsAreAccepted) {
    EXPECT_EQ(Parse({{"severity", "severe"}}),   ThreatLevel::Critical);
    EXPECT_EQ(Parse({{"severity", "moderate"}}), ThreatLevel::Medium);
    EXPECT_EQ(Parse({{"severity", "minor"}}),    ThreatLevel::Low);
}

// A rule its own author called informational must not become a conviction.
// This previously returned Low, which mapped to ScanVerdict::Infected.
TEST(ThreatLevelMapping_Severity, InformationalMapsToInfoNotLow) {
    EXPECT_EQ(Parse({{"severity", "info"}}),          ThreatLevel::Info);
    EXPECT_EQ(Parse({{"severity", "informational"}}), ThreatLevel::Info);
    EXPECT_EQ(Parse({{"severity", "0"}}),             ThreatLevel::Info);
}

TEST(ThreatLevelMapping_Severity, OrdinalScaleIsHonoured) {
    // The 0-5 ordinal, as used by `severity = 5`.
    EXPECT_EQ(Parse({{"severity", "5"}}), ThreatLevel::Critical);
    EXPECT_EQ(Parse({{"severity", "4"}}), ThreatLevel::High);
    EXPECT_EQ(Parse({{"severity", "3"}}), ThreatLevel::Medium);
    EXPECT_EQ(Parse({{"severity", "2"}}), ThreatLevel::Low);
}

TEST(ThreatLevelMapping_Severity, AlternateKeysAreRecognised) {
    EXPECT_EQ(Parse({{"threat_level", "high"}}), ThreatLevel::High);
    EXPECT_EQ(Parse({{"Severity", "critical"}}), ThreatLevel::Critical);
    EXPECT_EQ(Parse({{"SEVERITY", "low"}}),      ThreatLevel::Low);
}

// ============================================================================
// THE CONFIDENCE SCORE - the signal 100% of the shipped rules actually carry
// ============================================================================

TEST(ThreatLevelMapping_Score, BandsMatchTheThreatLevelBoundaries) {
    EXPECT_EQ(Parse({{"score", "100"}}), ThreatLevel::Critical);
    EXPECT_EQ(Parse({{"score", "90"}}),  ThreatLevel::High);
    EXPECT_EQ(Parse({{"score", "75"}}),  ThreatLevel::High);
    EXPECT_EQ(Parse({{"score", "70"}}),  ThreatLevel::Medium);
    EXPECT_EQ(Parse({{"score", "50"}}),  ThreatLevel::Medium);
    EXPECT_EQ(Parse({{"score", "45"}}),  ThreatLevel::Low);
    EXPECT_EQ(Parse({{"score", "40"}}),  ThreatLevel::Low);
}

// Every score value present in the shipped ruleset, so a boundary change cannot
// silently reclassify thousands of rules.
TEST(ThreatLevelMapping_Score, EveryValueInTheShippedRulesetIsAtLeastLow) {
    for (const char* s : {"40", "45", "50", "55", "60", "65",
                          "70", "75", "80", "85", "90", "100"}) {
        const auto level = Parse({{"score", s}});
        EXPECT_NE(level, ThreatLevel::Info)
            << "score " << s << " landed on Info, which maps to Suspicious rather "
               "than Infected - that rule would stop convicting";
    }
}

// THE SCALE COLLISION. On the 0-5 ordinal 5 means Critical; as a score it is
// almost nothing. Reading a score through the ordinal branch would inflate it.
TEST(ThreatLevelMapping_Score, IsNotConfusedWithTheOrdinalScale) {
    EXPECT_EQ(Parse({{"score", "5"}}), ThreatLevel::Info);
    EXPECT_EQ(Parse({{"severity", "5"}}), ThreatLevel::Critical);
}

TEST(ThreatLevelMapping_Score, NonNumericScoreFallsBackToTheDefault) {
    EXPECT_EQ(Parse({{"score", "high"}}), ThreatLevel::Medium);
    EXPECT_EQ(Parse({{"score", ""}}),     ThreatLevel::Medium);
    EXPECT_EQ(Parse({{"score", "40x"}}),  ThreatLevel::Medium);
}

// ============================================================================
// PRECEDENCE AND DEFAULTS
// ============================================================================

// The 70 rules that carry both must keep the author's word, not the generated
// score - otherwise this change would have DOWNGRADED 57 critical rules to High.
TEST(ThreatLevelMapping_Precedence, ExplicitSeverityBeatsScore) {
    EXPECT_EQ(Parse({{"severity", "critical"}, {"score", "75"}}),
              ThreatLevel::Critical);
    EXPECT_EQ(Parse({{"severity", "high"}, {"score", "40"}}),
              ThreatLevel::High);
}

TEST(ThreatLevelMapping_Precedence, ScoreUsedWhenSeverityIsAbsent) {
    EXPECT_EQ(Parse({{"author", "someone"}, {"score", "75"}}), ThreatLevel::High);
}

TEST(ThreatLevelMapping_Default, NothingStatedMeansMedium) {
    EXPECT_EQ(Parse({}), ThreatLevel::Medium);
    EXPECT_EQ(Parse({{"author", "someone"}, {"description", "x"}}),
              ThreatLevel::Medium);
}

// Keys that look severity-ish but are not, and must not be guessed at. The
// shipped ruleset has 38 rules with `level = Experimental`, which says nothing
// about severity.
TEST(ThreatLevelMapping_Default, UnrelatedKeysAreIgnored) {
    EXPECT_EQ(Parse({{"level", "Experimental"}}), ThreatLevel::Medium);
    EXPECT_EQ(Parse({{"Confidence", "Prod"}}),    ThreatLevel::Medium);
    EXPECT_EQ(Parse({{"threat_name", "Windows.Malware.Snake"}}),
              ThreatLevel::Medium);
}

// An unrecognised severity word must not be silently treated as informational,
// which would turn a conviction into a monitored indicator.
TEST(ThreatLevelMapping_Default, UnknownSeverityWordDoesNotBecomeInfo) {
    const auto level = Parse({{"severity", "catastrophic"}});
    EXPECT_NE(level, ThreatLevel::Info);
    EXPECT_EQ(level, ThreatLevel::Medium);
}
