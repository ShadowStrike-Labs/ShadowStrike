/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/**
 * @file ExtensionPermissionRisk_Tests.cpp
 * @brief How dangerous a browser extension permission is judged to be.
 *
 * A permission classification is what the user is shown before deciding whether to keep an extension, so
 * the severity has to be right and it has to be the same severity for the same permission whichever
 * browser the extension came from.
 *
 * FOUR CLASSIFIERS ANSWER THIS ONE QUESTION, which is why both scanners are covered in one file:
 *
 *     ChromeExtensionScanner   IsDangerousPermission, IsCriticalPermission, GetPermissionRisk
 *     FirefoxAddonScanner      IsFirefoxDangerousPermission, plus AnalyzePermissions' own tiering
 *
 * Chrome's three were measured CONSISTENT - CRITICAL_PERMISSIONS is a strict subset of
 * DANGEROUS_PERMISSIONS, and GetPermissionRisk consults the critical list first - so the cases below hold
 * that agreement rather than prove a fix. Firefox's tiering was NOT consistent: it tested the dangerous
 * list before the all-websites case, and both the all-urls token and the wildcard host pattern are in that
 * list, so the Critical arm was unreachable and the broadest permission Firefox grants was reported as
 * merely High.
 *
 * The exact permission strings are deliberately NOT spelled out in this block comment. The wildcard host
 * pattern contains the two characters that end a block comment, which terminated an earlier draft of this
 * header mid-sentence and made the remaining prose compile as code - twenty-two errors, none of them in
 * the test bodies.
 *
 * THE MODULE'S OWN SELF-TEST ALREADY ENCODED THE RIGHT ANSWER and was failing unnoticed, because nothing
 * called it. Both scanners' SelfTest() are invoked below, which is the regression guard that was missing.
 *
 * The list difference between browsers is deliberate and is asserted as such: "debugger" is a Chrome-only
 * API and "browserSettings" is a Firefox-only API, so each list naming the other's permission would be
 * describing an API that browser does not implement.
 */

#include "pch.h"

#include <gtest/gtest.h>

#include "Products/Community/PhantomHome/WebProtection/ChromeExtensionScanner.hpp"
#include "Products/Community/PhantomHome/WebProtection/FirefoxAddonScanner.hpp"

#include <string>
#include <vector>

namespace ShadowStrike::WebBrowser::PermissionTest {
namespace {

/// Permissions both browsers implement, so both must agree on their severity.
const std::vector<std::string>& SharedDangerousPermissions() {
    static const std::vector<std::string> perms = {
        "tabs", "webRequest", "webRequestBlocking", "cookies", "history", "bookmarks",
        "nativeMessaging", "clipboardRead", "clipboardWrite", "management", "proxy",
        "privacy", "downloads"};
    return perms;
}

/// Chrome's CRITICAL_PERMISSIONS, restated so dropping one fails a case here.
const std::vector<std::string>& ChromeCriticalPermissions() {
    static const std::vector<std::string> perms = {
        "webRequest", "webRequestBlocking", "<all_urls>", "*://*/*", "debugger", "nativeMessaging"};
    return perms;
}

class ChromePermissionTest : public ::testing::Test {
protected:
    static void SetUpTestSuite() {
        auto& scanner = ChromeExtensionScanner::Instance();
        if (!scanner.IsInitialized()) {
            (void)scanner.Initialize();
        }
        ASSERT_TRUE(scanner.IsInitialized()) << "the Chrome scanner could not be initialised";
    }
    static ChromeExtensionScanner& Scanner() { return ChromeExtensionScanner::Instance(); }
};

class FirefoxPermissionTest : public ::testing::Test {
protected:
    static void SetUpTestSuite() {
        auto& scanner = FirefoxAddonScanner::Instance();
        if (!scanner.IsInitialized()) {
            (void)scanner.Initialize();
        }
        ASSERT_TRUE(scanner.IsInitialized()) << "the Firefox scanner could not be initialised";
    }
    static FirefoxAddonScanner& Scanner() { return FirefoxAddonScanner::Instance(); }
};

}  // namespace

// ============================================================================================
// Chrome - three classifiers that must agree
// ============================================================================================

TEST_F(ChromePermissionTest, EveryCriticalPermissionIsAlsoDangerous) {
    // The tiers are nested, not parallel. A permission that is critical but not dangerous would be
    // invisible to any caller that asks the broader question first.
    for (const auto& perm : ChromeCriticalPermissions()) {
        EXPECT_TRUE(IsCriticalPermission(perm)) << perm << " is expected to be critical";
        EXPECT_TRUE(IsDangerousPermission(perm))
            << perm << " is critical but not dangerous, so the two lists have diverged";
    }
}

TEST_F(ChromePermissionTest, TheRiskLevelAgreesWithTheTwoBooleanClassifiers) {
    // Three functions answer one question. This requires them to answer alike for every permission the
    // lists name, so a change to one list cannot silently contradict the other classifiers.
    const std::vector<std::string> probes = {
        "webRequest", "webRequestBlocking", "<all_urls>", "*://*/*", "debugger", "nativeMessaging",
        "tabs", "cookies", "history", "bookmarks", "clipboardRead", "management", "proxy",
        "privacy", "downloads", "storage", "alarms", "notImaginary"};
    for (const auto& perm : probes) {
        const auto risk = Scanner().GetPermissionRisk(perm);
        if (IsCriticalPermission(perm)) {
            EXPECT_EQ(PermissionRisk::Critical, risk)
                << perm << " is in the critical list but its risk level is not Critical";
        } else if (IsDangerousPermission(perm)) {
            EXPECT_EQ(PermissionRisk::High, risk)
                << perm << " is dangerous but not critical, so its risk level must be High";
        } else {
            EXPECT_LT(static_cast<int>(risk), static_cast<int>(PermissionRisk::High))
                << perm << " is in neither list yet is rated High or above";
        }
    }
}

TEST_F(ChromePermissionTest, AnOrdinaryPermissionIsNotDangerous) {
    // Anti-vacuity: without this the cases above would hold for classifiers that answer true for
    // everything, and every extension would be reported as over-privileged.
    for (const auto& perm : {"storage", "alarms", "contextMenus", "idle", ""}) {
        EXPECT_FALSE(IsDangerousPermission(perm)) << perm << " was reported dangerous";
        EXPECT_FALSE(IsCriticalPermission(perm));
    }
}

TEST_F(ChromePermissionTest, AccessToAllWebsitesIsCritical) {
    EXPECT_EQ(PermissionRisk::Critical, Scanner().GetPermissionRisk("<all_urls>"));
    EXPECT_EQ(PermissionRisk::Critical, Scanner().GetPermissionRisk("*://*/*"));
}

TEST_F(ChromePermissionTest, ASpecificHostPermissionIsLessThanAllWebsites) {
    // A single site is a real grant but not comparable to every site, so it must rank lower - otherwise
    // the two are indistinguishable to a user reading the list.
    const auto single = Scanner().GetPermissionRisk("https://example.com/*");
    const auto all = Scanner().GetPermissionRisk("<all_urls>");
    EXPECT_LT(static_cast<int>(single), static_cast<int>(all))
        << "one site is rated as high as every site";
    EXPECT_GT(static_cast<int>(single), static_cast<int>(PermissionRisk::Safe))
        << "a host permission is rated Safe";
}

TEST_F(ChromePermissionTest, TheScannerSelfTestPasses) {
    EXPECT_TRUE(Scanner().SelfTest())
        << "the Chrome scanner's own self-test fails, and nothing else called it";
}

// ============================================================================================
// Firefox - the tier that could not be reached
// ============================================================================================

TEST_F(FirefoxPermissionTest, AccessToAllWebsitesIsCritical) {
    // The defect this file was written against. Both spellings are also entries in
    // DANGEROUS_PERMISSIONS, and the dangerous test used to run first, so this arm never executed and the
    // broadest permission Firefox offers was reported as High.
    const auto perms = Scanner().AnalyzePermissions({"<all_urls>", "*://*/*"});
    ASSERT_EQ(2u, perms.size());
    EXPECT_EQ(AddonRiskLevel::Critical, perms[0].riskLevel)
        << "<all_urls> is not Critical, so the dangerous list is still shadowing this case";
    EXPECT_EQ(AddonRiskLevel::Critical, perms[1].riskLevel);
    EXPECT_EQ("Grants access to all websites", perms[0].description)
        << "the specific description was not applied, so the generic dangerous arm ran instead";
    EXPECT_TRUE(perms[0].isHostPermission)
        << "<all_urls> is a host permission and must be flagged as one";
}

TEST_F(FirefoxPermissionTest, ADangerousPermissionThatIsNotAllWebsitesIsHigh) {
    const auto perms = Scanner().AnalyzePermissions({"tabs", "cookies", "nativeMessaging"});
    ASSERT_EQ(3u, perms.size());
    for (const auto& p : perms) {
        EXPECT_EQ(AddonRiskLevel::High, p.riskLevel) << p.name << " is expected to be High";
    }
}

TEST_F(FirefoxPermissionTest, ASpecificHostPermissionIsMedium) {
    const auto perms = Scanner().AnalyzePermissions({"https://example.com/*"});
    ASSERT_EQ(1u, perms.size());
    EXPECT_EQ(AddonRiskLevel::Medium, perms[0].riskLevel);
    EXPECT_TRUE(perms[0].isHostPermission);
}

TEST_F(FirefoxPermissionTest, AnOrdinaryPermissionIsLow) {
    // Anti-vacuity for the tiering: the scale must reach its bottom, or every permission would alarm.
    const auto perms = Scanner().AnalyzePermissions({"storage", "alarms"});
    ASSERT_EQ(2u, perms.size());
    for (const auto& p : perms) {
        EXPECT_EQ(AddonRiskLevel::Low, p.riskLevel) << p.name << " is expected to be Low";
        EXPECT_FALSE(p.isHostPermission);
    }
}

TEST_F(FirefoxPermissionTest, TheScannerSelfTestPasses) {
    // This is the case that proves the fix. SelfTest analyses {"tabs", "cookies", "<all_urls>"} and
    // requires the third to be Critical - an expectation the classifier contradicted, so it returned
    // false. Nothing in the tree called it, so the failure was invisible.
    EXPECT_TRUE(Scanner().SelfTest())
        << "the Firefox scanner's own self-test fails - it asserts <all_urls> is Critical";
}

// ============================================================================================
// Across browsers - the same permission must mean the same thing
// ============================================================================================

TEST(ExtensionPermissionParityTest, BothBrowsersAgreeOnTheSharedDangerousPermissions) {
    auto& chrome = ChromeExtensionScanner::Instance();
    auto& firefox = FirefoxAddonScanner::Instance();
    if (!chrome.IsInitialized()) (void)chrome.Initialize();
    if (!firefox.IsInitialized()) (void)firefox.Initialize();

    for (const auto& perm : SharedDangerousPermissions()) {
        EXPECT_TRUE(IsDangerousPermission(perm)) << perm << " is not dangerous to Chrome";
        EXPECT_TRUE(IsFirefoxDangerousPermission(perm)) << perm << " is not dangerous to Firefox";
    }
}

TEST(ExtensionPermissionParityTest, AllWebsitesIsTheTopSeverityInBothBrowsers) {
    // The concrete divergence that was fixed: the same string was Critical to Chrome and High to Firefox.
    auto& chrome = ChromeExtensionScanner::Instance();
    auto& firefox = FirefoxAddonScanner::Instance();
    if (!chrome.IsInitialized()) (void)chrome.Initialize();
    if (!firefox.IsInitialized()) (void)firefox.Initialize();

    EXPECT_EQ(PermissionRisk::Critical, chrome.GetPermissionRisk("<all_urls>"));
    const auto ff = firefox.AnalyzePermissions({"<all_urls>"});
    ASSERT_EQ(1u, ff.size());
    EXPECT_EQ(AddonRiskLevel::Critical, ff[0].riskLevel)
        << "the same permission is Critical in one browser and not the other";
}

TEST(ExtensionPermissionParityTest, EachBrowserOnlyNamesPermissionsItsOwnApiProvides) {
    // The one deliberate difference. "debugger" is a Chrome-only API and "browserSettings" is a
    // Firefox-only API, so a list naming the other browser's permission would be describing something
    // that browser cannot grant. Asserted so the lists are not "unified" by mistake.
    EXPECT_TRUE(IsDangerousPermission("debugger")) << "debugger is a Chrome API and must be listed";
    EXPECT_FALSE(IsFirefoxDangerousPermission("debugger"))
        << "Firefox does not implement the debugger API, so listing it would be noise";
    EXPECT_TRUE(IsFirefoxDangerousPermission("browserSettings"))
        << "browserSettings is a Firefox API and must be listed";
    EXPECT_FALSE(IsDangerousPermission("browserSettings"))
        << "Chrome does not implement browserSettings";
}

}  // namespace ShadowStrike::WebBrowser::PermissionTest
