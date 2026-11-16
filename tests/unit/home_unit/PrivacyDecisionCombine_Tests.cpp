/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/**
 * @file PrivacyDecisionCombine_Tests.cpp
 * @brief MicrophoneGuard / WebcamProtector decision-vote combination (task 149).
 *
 * The decision hook used to (a) consult only the FIRST registrant and (b) treat
 * "no provider / no opinion" as an allow (empty list returned Prompt, and the
 * Prompt consumer counted anything that was not Block/Mute as allowed). These
 * cases pin the corrected contract of the pure combine function that now backs
 * the hook:
 *   - every vote is combined most-secure-wins, not just the first;
 *   - std::nullopt is "no opinion" and never forces an allow;
 *   - a "Prompt" vote is not actionable without a prompter UI, so it does not
 *     win and is not an allow;
 *   - an empty list, an all-nullopt list, or a Prompt-only list all return
 *     std::nullopt, which the caller resolves to its secure default.
 *
 * Audio security order: Block > Mute > AllowTimed > AllowOnce > Allow.
 * Camera security order: Block > AllowTimed > AllowOnce > Allow (no Mute).
 */

#include "pch.h"

#include <gtest/gtest.h>

#include <optional>
#include <vector>

#include "Products/Community/PhantomHome/Privacy/MicrophoneGuard.hpp"
#include "Products/Community/PhantomHome/Privacy/WebcamProtector.hpp"

namespace {

using ShadowStrike::Privacy::AudioAccessDecision;
using ShadowStrike::Privacy::CameraAccessDecision;
using ShadowStrike::Privacy::CombineAudioAccessDecisions;
using ShadowStrike::Privacy::CombineCameraAccessDecisions;

template <typename T>
using Votes = std::vector<std::optional<T>>;

// ===========================================================================
// Microphone
// ===========================================================================

TEST(PrivacyDecisionCombine, AudioEmptyListIsNoOpinion) {
    EXPECT_FALSE(CombineAudioAccessDecisions({}).has_value());
}

TEST(PrivacyDecisionCombine, AudioAllNoOpinionIsNoOpinion) {
    Votes<AudioAccessDecision> v{std::nullopt, std::nullopt};
    EXPECT_FALSE(CombineAudioAccessDecisions(v).has_value());
}

TEST(PrivacyDecisionCombine, AudioPromptOnlyIsNotActionable) {
    // "Prompt" cannot be honoured without a prompter UI, so it must not win and
    // must not become an allow: the combined result is "no opinion".
    Votes<AudioAccessDecision> v{AudioAccessDecision::Prompt};
    EXPECT_FALSE(CombineAudioAccessDecisions(v).has_value());
}

TEST(PrivacyDecisionCombine, AudioSingleAllowIsAllow) {
    Votes<AudioAccessDecision> v{AudioAccessDecision::Allow};
    const auto r = CombineAudioAccessDecisions(v);
    ASSERT_TRUE(r.has_value());
    EXPECT_EQ(*r, AudioAccessDecision::Allow);
}

TEST(PrivacyDecisionCombine, AudioBlockBeatsAllowRegardlessOfOrder) {
    // The historical bug returned the FIRST registrant's vote; Allow is first.
    Votes<AudioAccessDecision> v{AudioAccessDecision::Allow, AudioAccessDecision::Block};
    const auto r = CombineAudioAccessDecisions(v);
    ASSERT_TRUE(r.has_value());
    EXPECT_EQ(*r, AudioAccessDecision::Block);
}

TEST(PrivacyDecisionCombine, AudioMuteBeatsAllowTimed) {
    Votes<AudioAccessDecision> v{AudioAccessDecision::AllowTimed, AudioAccessDecision::Mute};
    const auto r = CombineAudioAccessDecisions(v);
    ASSERT_TRUE(r.has_value());
    EXPECT_EQ(*r, AudioAccessDecision::Mute);
}

TEST(PrivacyDecisionCombine, AudioAllowTimedBeatsAllowOnceAndAllow) {
    Votes<AudioAccessDecision> v{AudioAccessDecision::Allow, AudioAccessDecision::AllowOnce,
                                 AudioAccessDecision::AllowTimed};
    const auto r = CombineAudioAccessDecisions(v);
    ASSERT_TRUE(r.has_value());
    EXPECT_EQ(*r, AudioAccessDecision::AllowTimed);
}

TEST(PrivacyDecisionCombine, AudioNoOpinionDoesNotMaskAnEngagedVote) {
    Votes<AudioAccessDecision> v{std::nullopt, AudioAccessDecision::Allow, std::nullopt};
    const auto r = CombineAudioAccessDecisions(v);
    ASSERT_TRUE(r.has_value());
    EXPECT_EQ(*r, AudioAccessDecision::Allow);
}

TEST(PrivacyDecisionCombine, AudioBlockBeatsEverything) {
    Votes<AudioAccessDecision> v{AudioAccessDecision::Mute, AudioAccessDecision::Block,
                                 AudioAccessDecision::AllowTimed, AudioAccessDecision::Prompt};
    const auto r = CombineAudioAccessDecisions(v);
    ASSERT_TRUE(r.has_value());
    EXPECT_EQ(*r, AudioAccessDecision::Block);
}

// ===========================================================================
// Camera (no Mute)
// ===========================================================================

TEST(PrivacyDecisionCombine, CameraEmptyListIsNoOpinion) {
    EXPECT_FALSE(CombineCameraAccessDecisions({}).has_value());
}

TEST(PrivacyDecisionCombine, CameraAllNoOpinionIsNoOpinion) {
    Votes<CameraAccessDecision> v{std::nullopt, std::nullopt};
    EXPECT_FALSE(CombineCameraAccessDecisions(v).has_value());
}

TEST(PrivacyDecisionCombine, CameraPromptOnlyIsNotActionable) {
    Votes<CameraAccessDecision> v{CameraAccessDecision::Prompt};
    EXPECT_FALSE(CombineCameraAccessDecisions(v).has_value());
}

TEST(PrivacyDecisionCombine, CameraBlockBeatsAllowRegardlessOfOrder) {
    Votes<CameraAccessDecision> v{CameraAccessDecision::Allow, CameraAccessDecision::Block};
    const auto r = CombineCameraAccessDecisions(v);
    ASSERT_TRUE(r.has_value());
    EXPECT_EQ(*r, CameraAccessDecision::Block);
}

TEST(PrivacyDecisionCombine, CameraAllowTimedBeatsAllowOnceAndAllow) {
    Votes<CameraAccessDecision> v{CameraAccessDecision::AllowOnce, CameraAccessDecision::AllowTimed,
                                  CameraAccessDecision::Allow};
    const auto r = CombineCameraAccessDecisions(v);
    ASSERT_TRUE(r.has_value());
    EXPECT_EQ(*r, CameraAccessDecision::AllowTimed);
}

TEST(PrivacyDecisionCombine, CameraNoOpinionDoesNotMaskAnEngagedVote) {
    Votes<CameraAccessDecision> v{std::nullopt, CameraAccessDecision::Block};
    const auto r = CombineCameraAccessDecisions(v);
    ASSERT_TRUE(r.has_value());
    EXPECT_EQ(*r, CameraAccessDecision::Block);
}

}  // namespace
