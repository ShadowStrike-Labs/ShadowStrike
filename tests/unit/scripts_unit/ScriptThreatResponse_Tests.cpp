/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * Unit tests for the confidence-gated script-threat response policy
 * (fileless defense). The pure decision DecideScriptResponse encodes the
 * legitimate-vs-malicious separation, so it is proven here EXHAUSTIVELY over
 * every input combination: a legitimate script is never terminated, a merely
 * suspicious one is only alerted, and only a high-confidence conviction against
 * a blockable target terminates. A regression that lets a suspicious score kill
 * a process, or terminates a non-blockable (System/self) target, fails here.
 */
#include "pch.h"

#include <gtest/gtest.h>

#include "../../../src/PhantomCore/Scripts/ScriptThreatResponse.hpp"

using ShadowStrike::Scripts::DecideScriptResponse;
using ShadowStrike::Scripts::ScriptResponseAction;

namespace {

// Mirror of the policy's intent, written independently of the implementation so
// the exhaustive test is a real cross-check, not a copy of the function.
constexpr ScriptResponseAction Expected(bool blockWorthy, bool suspicious,
                                        bool blockable) {
    if (blockWorthy) {
        return blockable ? ScriptResponseAction::Terminate
                         : ScriptResponseAction::Alert;
    }
    if (suspicious) {
        return ScriptResponseAction::Alert;
    }
    return ScriptResponseAction::Allow;
}

}  // namespace

TEST(ScriptThreatResponsePolicy, ExhaustiveOverAllInputs) {
    for (int bits = 0; bits < 8; ++bits) {
        const bool blockWorthy = (bits & 0b100) != 0;
        const bool suspicious  = (bits & 0b010) != 0;
        const bool blockable   = (bits & 0b001) != 0;
        EXPECT_EQ(DecideScriptResponse(blockWorthy, suspicious, blockable),
                  Expected(blockWorthy, suspicious, blockable))
            << "blockWorthy=" << blockWorthy
            << " suspicious=" << suspicious
            << " blockable=" << blockable;
    }
}

TEST(ScriptThreatResponsePolicy, LegitimateScriptIsAllowedNeverTouched) {
    // Clean content (not block-worthy, not suspicious) must never be actioned,
    // whether or not the host happens to be terminable.
    EXPECT_EQ(DecideScriptResponse(false, false, true), ScriptResponseAction::Allow);
    EXPECT_EQ(DecideScriptResponse(false, false, false), ScriptResponseAction::Allow);
}

TEST(ScriptThreatResponsePolicy, SuspiciousIsAlertedNeverTerminated) {
    // A suspicious-but-not-block-worthy score is watched and reported; it must
    // never terminate a process - that is the false-positive guard for benign
    // but unusual admin commands.
    EXPECT_EQ(DecideScriptResponse(false, true, true), ScriptResponseAction::Alert);
    EXPECT_EQ(DecideScriptResponse(false, true, false), ScriptResponseAction::Alert);
}

TEST(ScriptThreatResponsePolicy, HighConfidenceMaliciousOnUserHostTerminates) {
    // The scanner's own high-confidence conviction against a blockable (user)
    // host terminates - this is how the fileless payload is stopped.
    EXPECT_EQ(DecideScriptResponse(true, true, true), ScriptResponseAction::Terminate);
    EXPECT_EQ(DecideScriptResponse(true, false, true), ScriptResponseAction::Terminate);
}

TEST(ScriptThreatResponsePolicy, MaliciousAttributedToInfraIsAlertedNotTerminated) {
    // A block-worthy conviction whose target is NOT blockable (PID 0, System, or
    // this service) must be downgraded to Alert - never terminate infrastructure
    // on a script verdict, even a high-confidence one.
    EXPECT_EQ(DecideScriptResponse(true, true, false), ScriptResponseAction::Alert);
    EXPECT_EQ(DecideScriptResponse(true, false, false), ScriptResponseAction::Alert);
}

TEST(ScriptThreatResponsePolicy, ActionNamesAreStable) {
    EXPECT_STREQ(ShadowStrike::Scripts::ToString(ScriptResponseAction::Allow), "Allow");
    EXPECT_STREQ(ShadowStrike::Scripts::ToString(ScriptResponseAction::Alert), "Alert");
    EXPECT_STREQ(ShadowStrike::Scripts::ToString(ScriptResponseAction::Terminate), "Terminate");
}
