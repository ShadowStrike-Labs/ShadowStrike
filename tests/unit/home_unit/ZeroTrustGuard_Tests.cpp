/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/**
 * @file ZeroTrustGuard_Tests.cpp
 * @brief The execution trust decision: its hard gates, its band, and its monotonicity.
 *
 * Evaluate() decides whether a process may run. It is the most consequential pure function in the
 * Home product and it had no coverage.
 *
 * THE PROPERTY THAT MATTERS MOST IS MONOTONICITY: adding evidence that a binary is benign must
 * never make the decision worse. A scoring function assembled from weighted signals can violate
 * that silently - a sign error or a mis-ordered clamp makes a *higher* reputation produce a
 * *lower* score - and no test of individual verdicts would catch it, because each verdict on its
 * own still looks plausible. The monotonicity cases below vary exactly one input at a time and
 * assert the score never moves the wrong way.
 *
 * The hard-gate cases matter for the opposite reason: a gate that stops firing turns a policy the
 * user switched on into a no-op, while the UI still shows it enabled.
 */

#include "pch.h"

#include <gtest/gtest.h>

#include "Products/Community/PhantomHome/ZeroTrustGuard/ZeroTrustGuard.hpp"

#include <string>

namespace ShadowStrike::Products::Home::ZeroTrust::Test {
namespace {

class ZeroTrustGuardTest : public ::testing::Test {
protected:
    /// Evaluate() delegates to the PhantomCore ZeroTrust engine, so the guard must be initialised
    /// or every verdict comes from an engine that was never configured. Initialising once per
    /// suite rather than per test is deliberate: Shutdown() also stops the shared prompt queue,
    /// which a later suite in the same process depends on.
    static void SetUpTestSuite() {
        ASSERT_TRUE(ZeroTrustGuard::Instance().Initialize())
            << "the guard could not be initialised, so no verdict below would mean anything";
    }

    void SetUp() override {
        guard.SetConfig(ZeroTrustConfig{});   // documented defaults
    }

    void TearDown() override {
        guard.SetConfig(ZeroTrustConfig{});   // never leave policy changed for another suite
    }

    /// A binary with everything in its favour: signed, trusted publisher, benign on both scores.
    [[nodiscard]] static ZeroTrustInputs FullyTrusted() {
        ZeroTrustInputs in{};
        in.imagePath = L"C:\\Program Files\\Vendor\\trusted.exe";
        in.publisherSubject = L"CN=Trusted Vendor";
        in.publisherSigned = true;
        in.publisherTrusted = true;
        in.reputation = 1.0;
        in.staticBenign = 1.0;
        return in;
    }

    /// A binary about which nothing good is known.
    [[nodiscard]] static ZeroTrustInputs Unknown() {
        ZeroTrustInputs in{};
        in.imagePath = L"C:\\Users\\Public\\dropped.exe";
        in.publisherSigned = false;
        in.publisherTrusted = false;
        return in;
    }

    [[nodiscard]] double ScoreOf(const ZeroTrustInputs& in) {
        double score = -1.0;
        (void)guard.Evaluate(in, &score);
        return score;
    }

    ZeroTrustGuard& guard = ZeroTrustGuard::Instance();
};

// ============================================================================================
// The score itself
// ============================================================================================

TEST_F(ZeroTrustGuardTest, TheScoreStaysWithinItsDeclaredRange) {
    // Downstream comparisons against threshold and uncertainBand assume a normalised score. A
    // value outside [0,1] would make the band meaningless.
    for (const auto& in : {FullyTrusted(), Unknown()}) {
        const double score = ScoreOf(in);
        EXPECT_GE(score, 0.0) << "score below 0";
        EXPECT_LE(score, 1.0) << "score above 1";
    }
}

TEST_F(ZeroTrustGuardTest, TrustedEvidenceScoresAboveNoEvidence) {
    EXPECT_GT(ScoreOf(FullyTrusted()), ScoreOf(Unknown()))
        << "a signed, trusted, reputable binary does not score above one with no evidence at all, "
           "so the score does not order its inputs";
}

TEST_F(ZeroTrustGuardTest, AFullyTrustedBinaryIsAllowed) {
    EXPECT_EQ(ZeroTrustDecision::Allow, guard.Evaluate(FullyTrusted(), nullptr))
        << "a signed binary from a trusted publisher with maximum reputation is not allowed, so "
           "the default policy blocks legitimate software";
}

TEST_F(ZeroTrustGuardTest, AnUnknownBinaryIsNotAllowed) {
    // Anti-vacuity for the case above. If Evaluate returned Allow unconditionally, that test would
    // pass while the guard decided nothing.
    EXPECT_NE(ZeroTrustDecision::Allow, guard.Evaluate(Unknown(), nullptr))
        << "a binary with no signature, no trusted publisher and no reputation is allowed, so the "
           "guard admits anything";
}

TEST_F(ZeroTrustGuardTest, TheOutScorePointerIsOptional) {
    // Callers on the process-launch hot path pass nullptr; that must not be a crash or a different
    // verdict from the same inputs.
    const auto withScore = guard.Evaluate(FullyTrusted(), nullptr);
    double score = 0.0;
    const auto withoutScore = guard.Evaluate(FullyTrusted(), &score);
    EXPECT_EQ(withScore, withoutScore)
        << "the verdict depends on whether the caller asked for the score";
}

// ============================================================================================
// Monotonicity - more evidence of benignity must never score lower
// ============================================================================================

TEST_F(ZeroTrustGuardTest, HigherReputationNeverScoresLower) {
    ZeroTrustInputs in = Unknown();
    double previous = -1.0;
    for (const double reputation : {0.0, 0.25, 0.5, 0.75, 1.0}) {
        in.reputation = reputation;
        const double score = ScoreOf(in);
        EXPECT_GE(score, previous)
            << "raising reputation to " << reputation << " lowered the score from " << previous
            << " to " << score << ", so the guard punishes evidence of benignity";
        previous = score;
    }
}

TEST_F(ZeroTrustGuardTest, HigherStaticBenignityNeverScoresLower) {
    ZeroTrustInputs in = Unknown();
    double previous = -1.0;
    for (const double benign : {0.0, 0.25, 0.5, 0.75, 1.0}) {
        in.staticBenign = benign;
        const double score = ScoreOf(in);
        EXPECT_GE(score, previous)
            << "raising the static benign score to " << benign << " lowered the overall score";
        previous = score;
    }
}

TEST_F(ZeroTrustGuardTest, BeingSignedNeverScoresLowerThanBeingUnsigned) {
    ZeroTrustInputs unsignedInput = Unknown();
    ZeroTrustInputs signedInput = Unknown();
    signedInput.publisherSubject = L"CN=Some Vendor";
    signedInput.publisherSigned = true;
    EXPECT_GE(ScoreOf(signedInput), ScoreOf(unsignedInput))
        << "a signed binary scores below an unsigned one";
}

TEST_F(ZeroTrustGuardTest, ATrustedPublisherNeverScoresLowerThanAnUntrustedOne) {
    ZeroTrustInputs untrusted = Unknown();
    untrusted.publisherSubject = L"CN=Some Vendor";
    untrusted.publisherSigned = true;
    ZeroTrustInputs trusted = untrusted;
    trusted.publisherTrusted = true;
    EXPECT_GE(ScoreOf(trusted), ScoreOf(untrusted))
        << "a trusted publisher scores below an untrusted one";
}

TEST_F(ZeroTrustGuardTest, HigherAcmRiskNeverScoresHigher) {
    // acmRisk runs the other way: more risk must not improve the score.
    ZeroTrustInputs in = FullyTrusted();
    double previous = 2.0;
    for (const std::uint8_t risk : {std::uint8_t{0}, std::uint8_t{50}, std::uint8_t{100}}) {
        in.acmRisk = risk;
        const double score = ScoreOf(in);
        EXPECT_LE(score, previous)
            << "raising ACM risk to " << static_cast<int>(risk) << " raised the score";
        previous = score;
    }
}

// ============================================================================================
// Hard gates - a policy the user switched on must not be a no-op
// ============================================================================================

TEST_F(ZeroTrustGuardTest, RequiringASignatureBlocksAnUnsignedBinaryOutright) {
    ZeroTrustConfig cfg{};
    cfg.requirePublisherSigned = true;
    guard.SetConfig(cfg);

    EXPECT_EQ(ZeroTrustDecision::Block, guard.Evaluate(Unknown(), nullptr))
        << "requirePublisherSigned is enabled and an unsigned binary was not blocked, so the "
           "policy is inert while the UI reports it as on";
    EXPECT_EQ(ZeroTrustDecision::Allow, guard.Evaluate(FullyTrusted(), nullptr))
        << "requirePublisherSigned blocks a correctly signed binary too, so enabling it disables "
           "everything";
}

TEST_F(ZeroTrustGuardTest, AMinimumReputationGateRejectsAnythingBelowIt) {
    ZeroTrustConfig cfg{};
    cfg.minReputation = 0.9;
    guard.SetConfig(cfg);

    ZeroTrustInputs poor = FullyTrusted();
    poor.reputation = 0.1;
    EXPECT_NE(ZeroTrustDecision::Allow, guard.Evaluate(poor, nullptr))
        << "a reputation of 0.1 passed a minimum of 0.9";

    EXPECT_EQ(ZeroTrustDecision::Allow, guard.Evaluate(FullyTrusted(), nullptr))
        << "a reputation of 1.0 failed a minimum of 0.9";
}

TEST_F(ZeroTrustGuardTest, TheConfigRoundTripsThroughTheGuard) {
    // If the guard silently kept its previous policy, every gate case above would still pass
    // while the policy the user set was ignored.
    ZeroTrustConfig cfg{};
    cfg.threshold = 0.42;
    cfg.uncertainBand = 0.11;
    cfg.requirePublisherSigned = true;
    guard.SetConfig(cfg);

    const auto readBack = guard.GetConfig();
    EXPECT_DOUBLE_EQ(0.42, readBack.threshold);
    EXPECT_DOUBLE_EQ(0.11, readBack.uncertainBand);
    EXPECT_TRUE(readBack.requirePublisherSigned);
}

TEST_F(ZeroTrustGuardTest, TheDefaultPolicyIsTheDocumentedOne) {
    guard.SetConfig(ZeroTrustConfig{});
    const auto cfg = guard.GetConfig();
    EXPECT_DOUBLE_EQ(0.70, cfg.threshold);
    EXPECT_DOUBLE_EQ(0.05, cfg.uncertainBand);
    EXPECT_FALSE(cfg.requirePublisherSigned);
    EXPECT_FALSE(cfg.requireWhitelist);
}

}  // namespace
}  // namespace ShadowStrike::Products::Home::ZeroTrust::Test
