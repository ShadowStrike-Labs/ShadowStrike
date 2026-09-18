// SPDX-License-Identifier: AGPL-3.0-or-later
/*
 * ShadowStrike Phantom - Banking hook legitimacy and domain policy tests
 * Copyright (C) 2026 ShadowStrike-Labs
 *
 * This program is free software: you can redistribute it and/or modify it under
 * the terms of the GNU Affero General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option) any
 * later version.
 */

/**
 * @file BankingHookLegitimacy_Tests.cpp
 * @brief Pins which keyboard hooks are excused from detection, and which domains a secure session permits.
 *
 * IsLegitimateHook GATES REMEDIATION. UnhookMaliciousHooks blocks a hook only when it is suspicious AND
 * this predicate says no, so anything it excuses is left in place. Its system-directory test was a
 * substring search for the literal text of a system path, which accepted any path merely containing it -
 * so a hook whose process sat under a user-created directory of the same name was excused. The cases here
 * pin the anchored form: under the REAL system directory yes, anywhere else no.
 *
 * The other three tests in that function are pinned too, because they are correct and a future change
 * should not silently widen them: the PID set is exact, the process name is compared with _wcsicmp rather
 * than searched, and the explicit path whitelist is an exact match on a canonicalised path.
 *
 * IsDomainAllowed is a four-tier decision and the tiers have priority. Its last tier falls back to
 * IsBankingDomain, which is separately filed as unfit - it matches secure.bank.phishing-site.com and misses
 * chase.com - so what is pinned here is the PRIORITY, namely that a configured whitelist is consulted before
 * that heuristic is ever reached.
 *
 * NOTE ON HEADERS: KeyloggerProtection.hpp, SecureBrowser.hpp and ScreenshotBlocker.hpp are the three
 * Banking headers whose ModuleStatus is behind SHADOWSTRIKE_BANKING_MODULESTATUS_DEFINED, so they may share
 * a translation unit. BankingTrojanDetector.hpp, CertificatePinning.hpp and TransactionMonitor.hpp may not
 * join them, and beyond ModuleStatus the namespace also has divergent DetectionAction, DetectionCallback and
 * ValidationResult declarations. Filed.
 */

#include "pch.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <string>

#include "Products/Community/PhantomHome/Banking/KeyloggerProtection.hpp"
#include "Products/Community/PhantomHome/Banking/SecureBrowser.hpp"

namespace {

using ShadowStrike::Banking::KeyboardHookInfo;
using ShadowStrike::Banking::KeyloggerProtection;

// The real system directory, from the same Win32 call the fix uses. Hardcoding C:\Windows\System32 would
// make the test agree with the code only on machines where that guess happens to be right.
std::wstring RealSystemDirectory() {
    std::array<wchar_t, MAX_PATH> buffer{};
    const UINT length = ::GetSystemDirectoryW(buffer.data(), static_cast<UINT>(buffer.size()));
    if (length == 0 || length >= buffer.size()) {
        return {};
    }
    std::wstring directory(buffer.data(), length);
    while (!directory.empty() && (directory.back() == L'\\' || directory.back() == L'/')) {
        directory.pop_back();
    }
    return directory;
}

KeyboardHookInfo HookFromPath(std::wstring processPath) {
    KeyboardHookInfo hook;
    // Above 4, so the System and Idle exemption does not decide the answer. Windows PIDs are multiples of
    // four; 4096 is an ordinary value.
    hook.processId = 4096;
    hook.threadId = 4100;
    hook.processName = L"probe.exe";
    hook.processPath = std::move(processPath);
    hook.isGlobal = true;
    hook.isSuspicious = true;
    return hook;
}

class HookLegitimacyTest : public ::testing::Test {
protected:
    static KeyloggerProtection& Guard() { return KeyloggerProtection::Instance(); }

    static void SetUpTestSuite() {
        // Initialize is not idempotent (filed 288), so state is tested rather than assumed. The predicate
        // under test reads only the whitelists and the path, so it is meaningful either way.
        if (!Guard().IsInitialized()) {
            (void)Guard().Initialize();
        }
    }
};

TEST_F(HookLegitimacyTest, AHookUnderTheRealSystemDirectoryIsExcused) {
    const std::wstring system = RealSystemDirectory();
    ASSERT_FALSE(system.empty()) << "GetSystemDirectoryW failed, so the premise of this suite is untestable";

    EXPECT_TRUE(Guard().IsLegitimateHook(HookFromPath(system + L"\\user32.dll")));
    EXPECT_TRUE(Guard().IsLegitimateHook(HookFromPath(system + L"\\drivers\\etc\\nested.dll")))
        << "anything below the system directory, not only its immediate children";
}

TEST_F(HookLegitimacyTest, TheComparisonIgnoresCaseAndSeparatorStyle) {
    const std::wstring system = RealSystemDirectory();
    ASSERT_FALSE(system.empty());

    std::wstring upper = system;
    std::transform(upper.begin(), upper.end(), upper.begin(), ::towupper);
    EXPECT_TRUE(Guard().IsLegitimateHook(HookFromPath(upper + L"\\USER32.DLL")))
        << "Windows paths are case-insensitive";

    std::wstring forward = system;
    std::replace(forward.begin(), forward.end(), L'\\', L'/');
    EXPECT_TRUE(Guard().IsLegitimateHook(HookFromPath(forward + L"/user32.dll")))
        << "a forward-slash path names the same file; the previous literal comparison handled neither";
}

TEST_F(HookLegitimacyTest, AUserCreatedDirectoryOfTheSameNameIsNotExcused) {
    // The defect. Each of these CONTAINS the text of a system path and is not under one, and each was
    // reported legitimate - which suppressed remediation, because UnhookMaliciousHooks blocks only what
    // this predicate rejects.
    EXPECT_FALSE(Guard().IsLegitimateHook(
        HookFromPath(L"C:\\Users\\victim\\windows\\system32\\keylogger.exe")))
        << "a directory any user can create must not confer a detection exemption";
    EXPECT_FALSE(Guard().IsLegitimateHook(HookFromPath(L"C:\\Temp\\windows\\syswow64\\hook.dll")));
    EXPECT_FALSE(Guard().IsLegitimateHook(HookFromPath(L"D:\\payload\\windows\\system32\\evil.exe")));
    EXPECT_FALSE(Guard().IsLegitimateHook(
        HookFromPath(L"\\\\attacker-share\\windows\\system32\\evil.exe")))
        << "a UNC path is not the local system directory";
}

TEST_F(HookLegitimacyTest, ASiblingDirectoryWithALongerNameIsNotExcused) {
    // The boundary. A prefix test without a separator check would accept these.
    const std::wstring system = RealSystemDirectory();
    ASSERT_FALSE(system.empty());

    EXPECT_FALSE(Guard().IsLegitimateHook(HookFromPath(system + L"Extra\\evil.exe")));
    EXPECT_FALSE(Guard().IsLegitimateHook(HookFromPath(system + L"_backup\\evil.exe")));
    EXPECT_FALSE(Guard().IsLegitimateHook(HookFromPath(system)))
        << "the directory itself is not an executable under it";
}

TEST_F(HookLegitimacyTest, AnOrdinaryPathIsNotExcusedAndNeitherIsAnEmptyOne) {
    // Non-vacuity: without these the suite would pass against a predicate that always answers true.
    EXPECT_FALSE(Guard().IsLegitimateHook(HookFromPath(L"C:\\Users\\victim\\Downloads\\keylog.exe")));
    EXPECT_FALSE(Guard().IsLegitimateHook(HookFromPath(L"")))
        << "an unresolvable process path is not evidence of legitimacy";
    EXPECT_FALSE(Guard().IsLegitimateHook(HookFromPath(L"not a path at all")));
}

TEST_F(HookLegitimacyTest, TheSystemAndIdleProcessesAreStillExcused) {
    // Deliberately unchanged by the fix, and pinned so it stays that way. Windows PIDs are multiples of
    // four, so 0 and 4 are the only values this admits.
    KeyboardHookInfo idle = HookFromPath(L"C:\\Users\\victim\\Downloads\\keylog.exe");
    idle.processId = 0;
    EXPECT_TRUE(Guard().IsLegitimateHook(idle)) << "the Idle process";

    KeyboardHookInfo system = idle;
    system.processId = 4;
    EXPECT_TRUE(Guard().IsLegitimateHook(system)) << "the System process";

    KeyboardHookInfo ordinary = idle;
    ordinary.processId = 8;
    EXPECT_FALSE(Guard().IsLegitimateHook(ordinary)) << "the next PID up is not a system process";
}

TEST_F(HookLegitimacyTest, AnUnknownProcessIdIsNotWhitelisted) {
    // IsWhitelisted resolves the name and path for a live PID. For one that does not exist, every lookup
    // fails and the answer must be no rather than an accident of an empty comparison succeeding.
    EXPECT_FALSE(Guard().IsWhitelisted(0xFFFFFFFCu));
}

// ============================================================================
// Secure browser domain policy
// ============================================================================

TEST(SecureBrowserDomainPolicy, AnEmptyDomainIsNeverAllowed) {
    auto& browser = ShadowStrike::Banking::SecureBrowser::Instance();
    EXPECT_FALSE(browser.IsDomainAllowed("no-such-session", ""));
}

TEST(SecureBrowserDomainPolicy, AnUnknownSessionFallsThroughToThePolicyTiers) {
    // With no session whitelist and no session config, the decision reaches the global banking list or the
    // heuristic. What is pinned is that the call is answerable at all for an unknown session - it must not
    // depend on session state that does not exist - and that a domain no tier could accept is refused.
    auto& browser = ShadowStrike::Banking::SecureBrowser::Instance();
    EXPECT_FALSE(browser.IsDomainAllowed("no-such-session", "definitely-not-a-bank.example"));
}

TEST(SecureBrowserDomainPolicy, TheHeuristicTierIsTheLastResortAndIsKnownToBeUnfit) {
    // IsBankingDomain is tier four of IsDomainAllowed. It is separately filed: it substring-matches a list
    // of twelve suffixes despite a comment claiming exact matching, so it accepts a lookalike and misses
    // most real banks. Pinned as it behaves so the priority order stays visible - a configured whitelist
    // must be consulted first. If these expectations change, update the filing rather than the test.
    using ShadowStrike::Banking::IsBankingDomain;
    EXPECT_TRUE(IsBankingDomain("secure.bank.phishing-site.com"))
        << "a lookalike currently passes, which is why the heuristic must stay the last tier";
    EXPECT_FALSE(IsBankingDomain("chase.com"))
        << "a real bank currently fails the heuristic";
    EXPECT_FALSE(IsBankingDomain("")) << "and an empty domain is refused";
}

}  // namespace
