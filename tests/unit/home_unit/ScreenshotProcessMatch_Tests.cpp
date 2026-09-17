/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/**
 * @file ScreenshotProcessMatch_Tests.cpp
 * @brief Matching a process name against the recorder and assistive-tool lists.
 *
 * ScreenshotBlocker's three public predicates tested with find(), so "kiosk.exe" matched the assistive
 * entry "osk.exe" and "notobs64.exe" matched the recorder entry "obs64.exe". The live exemption path never
 * used those functions - it inserts the assistive names into a set and tests membership exactly - so no
 * verdict was wrong, but the public API answered a different question from the code that decides. A caller
 * trusting IsAccessibilityTool would have exempted kiosk.exe from capture protection during a banking
 * session.
 *
 * The direction matters differently for the two lists, and the cases say so: a false RECORDER match only
 * over-blocks, while a false ASSISTIVE match removes protection.
 *
 * The assistive list is asserted for its own sake as well. Blocking a screen reader makes the product
 * unusable for a blind user, so Narrator, NVDA, JAWS, Magnifier and the on-screen keyboard must each be
 * recognised - by their real names, not by a substring that also catches unrelated software.
 *
 * ONLY ONE BANKING HEADER IS INCLUDED HERE, DELIBERATELY. Six Banking headers each declare
 * ShadowStrike::Banking::ModuleStatus and only three guard it, so most pairs cannot occupy one translation
 * unit. Filed. That is also why the IBAN cases live in a separate file.
 */

#include "pch.h"

#include <gtest/gtest.h>

#include "Products/Community/PhantomHome/Banking/ScreenshotBlocker.hpp"

#include <string>
#include <vector>

namespace ShadowStrike::Banking::ProcessMatchTest {
namespace {

/// ACCESSIBILITY_TOOLS, restated so removing one fails a case here.
const std::vector<std::wstring>& AccessibilityTools() {
    static const std::vector<std::wstring> tools = {
        L"narrator.exe", L"magnify.exe", L"osk.exe", L"nvda.exe", L"jaws.exe"};
    return tools;
}

/// A representative subset of KNOWN_SCREEN_RECORDERS.
const std::vector<std::wstring>& ScreenRecorders() {
    static const std::vector<std::wstring> recorders = {
        L"obs64.exe", L"obs32.exe", L"camtasia.exe", L"fraps.exe", L"bandicam.exe",
        L"sharex.exe", L"greenshot.exe", L"snippingtool.exe", L"gamebar.exe",
        L"teamviewer.exe", L"anydesk.exe"};
    return recorders;
}

}  // namespace

// ============================================================================================
// Accessibility tools - a false match here removes protection
// ============================================================================================

TEST(ScreenshotAccessibilityTest, EveryAssistiveToolIsRecognised) {
    // Blocking a screen reader makes the product unusable for a blind user, so each of these must be
    // recognised by name.
    for (const auto& tool : AccessibilityTools()) {
        EXPECT_TRUE(IsAccessibilityTool(tool))
            << "an assistive tool was not recognised, so it may be blocked during a banking session";
    }
}

TEST(ScreenshotAccessibilityTest, AProcessMerelyContainingAToolNameIsNotAssistive) {
    // The defect. "kiosk.exe" contains "osk.exe" starting at index two, so substring matching classified
    // kiosk-mode software - and anything an attacker chose to name that way - as an assistive tool.
    EXPECT_FALSE(IsAccessibilityTool(L"kiosk.exe"))
        << "kiosk.exe was treated as the on-screen keyboard, so a name containing osk.exe is exempt";
    EXPECT_FALSE(IsAccessibilityTool(L"taskkiosk.exe"));
    EXPECT_FALSE(IsAccessibilityTool(L"myosk.exe"));
    EXPECT_FALSE(IsAccessibilityTool(L"evil-narrator.exe"))
        << "a prefixed name was treated as Narrator";
    EXPECT_FALSE(IsAccessibilityTool(L"nvda.exextra"))
        << "a suffixed name was treated as NVDA";
    EXPECT_FALSE(IsAccessibilityTool(L"jaws.exe.tmp"));
}

TEST(ScreenshotAccessibilityTest, AFullPathToAnAssistiveToolIsStillRecognised) {
    // Substring matching tolerated a full path by accident. Extracting the filename keeps that working on
    // purpose, so a caller passing either form gets the same answer.
    EXPECT_TRUE(IsAccessibilityTool(L"C:\\Windows\\System32\\narrator.exe"));
    EXPECT_TRUE(IsAccessibilityTool(L"C:/Program Files/NVDA/nvda.exe"));
    EXPECT_TRUE(IsAccessibilityTool(L"C:\\Windows\\System32\\NARRATOR.EXE"))
        << "the case of a path component defeated the match";
}

TEST(ScreenshotAccessibilityTest, AnUnrelatedProcessIsNotAssistive) {
    // Anti-vacuity: without this the cases above would hold for a predicate that answers true for
    // everything, and every process would be exempt from capture protection.
    for (const auto& name : {L"notepad.exe", L"chrome.exe", L"svchost.exe", L"explorer.exe", L""}) {
        EXPECT_FALSE(IsAccessibilityTool(name));
    }
}

// ============================================================================================
// Screen recorders - a false match here only over-blocks
// ============================================================================================

TEST(ScreenshotRecorderTest, EveryListedRecorderIsRecognised) {
    for (const auto& rec : ScreenRecorders()) {
        EXPECT_TRUE(IsKnownScreenRecorder(rec)) << "a listed screen recorder was not recognised";
    }
}

TEST(ScreenshotRecorderTest, AProcessMerelyContainingARecorderNameIsNotARecorder) {
    // Less dangerous than the accessibility direction - this only over-blocks - but it is the same
    // mistake, and an over-block on a name an ordinary program happens to contain is still a support call.
    EXPECT_FALSE(IsKnownScreenRecorder(L"notobs64.exe"));
    EXPECT_FALSE(IsKnownScreenRecorder(L"xsharex.exe"));
    EXPECT_FALSE(IsKnownScreenRecorder(L"mygamebar.exe"));
    EXPECT_FALSE(IsKnownScreenRecorder(L"greenshot.exe.bak"));
}

TEST(ScreenshotRecorderTest, AFullPathToARecorderIsStillRecognised) {
    EXPECT_TRUE(IsKnownScreenRecorder(L"C:\\Program Files\\obs-studio\\bin\\64bit\\obs64.exe"));
    EXPECT_TRUE(IsKnownScreenRecorder(L"D:/tools/ShareX.exe"));
}

TEST(ScreenshotRecorderTest, AnOrdinaryProcessIsNotARecorder) {
    for (const auto& name : {L"notepad.exe", L"chrome.exe", L"", L"narrator.exe"}) {
        EXPECT_FALSE(IsKnownScreenRecorder(name));
    }
}

TEST(ScreenshotRecorderTest, TheTwoListsDoNotOverlap) {
    // An assistive tool that also counted as a recorder would be exempt and blocked at once, and which
    // won would depend on call order.
    for (const auto& tool : AccessibilityTools()) {
        EXPECT_FALSE(IsKnownScreenRecorder(tool))
            << "an assistive tool is also classified as a screen recorder";
    }
    for (const auto& rec : ScreenRecorders()) {
        EXPECT_FALSE(IsAccessibilityTool(rec))
            << "a screen recorder is also classified as an assistive tool";
    }
}

}  // namespace ShadowStrike::Banking::ProcessMatchTest
