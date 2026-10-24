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
 * IsDomainAllowed is a tiered decision: exact per-session lists, then the loaded banking list (an entry
 * or its subdomain). With nothing configured it refuses. It no longer falls back to IsBankingDomain, a
 * keyword heuristic any registrant can satisfy (task 293).
 *
 * NOTE ON HEADERS: every Banking header may share a translation unit. The namespace-wide types live in
 * Banking/Common.hpp, and BankingHeadersCompose_Tests.cpp includes all six to keep it that way.
 */

#include "pch.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <filesystem>
#include <fstream>
#include <string>

#include "Products/Community/PhantomHome/Banking/KeyloggerProtection.hpp"
#include "Products/Community/PhantomHome/Banking/SecureBrowser.hpp"

// DetectionAction is one type for the whole Banking namespace (Common.hpp, task 305).
// KeyloggerProtection.hpp used to declare Terminate = 3 and Quarantine = 4, the
// reverse of BankingTrojanDetector.hpp, so a serialised 3 meant a different
// response depending on which module wrote it.
static_assert(static_cast<int>(ShadowStrike::Banking::DetectionAction::Quarantine) == 3);
static_assert(static_cast<int>(ShadowStrike::Banking::DetectionAction::Terminate) == 4);
static_assert(static_cast<int>(ShadowStrike::Banking::DetectionAction::Remediate) == 5);

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

TEST(SecureBrowserDomainPolicy, TheBankingHeuristicIsAnchored) {
    using ShadowStrike::Banking::IsBankingDomain;
    // The substring rules accepted every one of these attacker-registrable names.
    for (const char* lookalike : {"secure.bank.phishing-site.com", "myibank.evil.com",
                                  "fakebanking.attacker.net", "x.bank.evil.com", "evil.bank.example"}) {
        EXPECT_FALSE(IsBankingDomain(lookalike)) << lookalike;
    }
    // TLD rule as the last label, keyword rule as a whole label.
    for (const char* looksLikeABank : {"secure.bank", "example.bank.", "Online-Banking.example.com",
                                       "ebanking.example.co.uk", "acme.insurance"}) {
        EXPECT_TRUE(IsBankingDomain(looksLikeABank)) << looksLikeABank;
    }
    EXPECT_FALSE(IsBankingDomain("chase.com")) << "a keyword heuristic cannot know real banks";
    EXPECT_FALSE(IsBankingDomain("bank")) << "a single label is not a site";
    EXPECT_FALSE(IsBankingDomain(""));
    EXPECT_FALSE(IsBankingDomain("10.0.0.1"));
}

TEST(SecureBrowserDomainPolicy, NothingConfiguredMeansNothingIsAllowed) {
    // The heuristic is not an allow decision: a name that satisfies it is still refused.
    auto& browser = ShadowStrike::Banking::SecureBrowser::Instance();
    EXPECT_FALSE(browser.IsDomainAllowed("no-such-session", "banking.attacker.example"));
    EXPECT_FALSE(browser.IsDomainAllowed("no-such-session", "evil.bank"));
}

TEST(SecureBrowserDomainPolicy, ALoadedBankAllowsItsSubdomainsAndNothingElse) {
    auto& browser = ShadowStrike::Banking::SecureBrowser::Instance();
    const auto dir = std::filesystem::temp_directory_path() / L"ss_task293";
    std::filesystem::create_directories(dir);
    const auto list = dir / L"banks.txt";
    const auto empty = dir / L"empty.txt";
    { std::ofstream(list) << "# banks\n  Chase.com.  \nhsbc.co.uk\n"; }
    { std::ofstream(empty) << "# none\n"; }
    ASSERT_TRUE(browser.LoadBankingDomains(list));
    const bool exact = browser.IsDomainAllowed("no-such-session", "chase.com");
    const bool sub = browser.IsDomainAllowed("no-such-session", "WWW.chase.com.");
    const bool other = browser.IsDomainAllowed("no-such-session", "online.hsbc.co.uk");
    const bool lookalike = browser.IsDomainAllowed("no-such-session", "chase.com.evil.test");
    const bool prefix = browser.IsDomainAllowed("no-such-session", "notchase.com");
    ASSERT_TRUE(browser.LoadBankingDomains(empty));   // leave the singleton unconfigured
    std::error_code ec;
    std::filesystem::remove_all(dir, ec);
    EXPECT_TRUE(exact);
    EXPECT_TRUE(sub);
    EXPECT_TRUE(other);
    EXPECT_FALSE(lookalike);
    EXPECT_FALSE(prefix);
}

}  // namespace
