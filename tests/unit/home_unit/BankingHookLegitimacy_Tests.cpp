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
 * this predicate says no, so anything it excuses is left in place. It used to excuse by location - first
 * by a substring of a system path, then by the real system directory. It now excuses by a verified
 * signature from a trusted publisher (task 307), checked on the image itself.
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
#include "PhantomCore/Core/Engine/ScanEngine.hpp"
#include "PhantomCore/SelfProtection/DigitalSignatureValidator.hpp"

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

class ScratchDirectory {
public:
    ScratchDirectory()
        : path(std::filesystem::temp_directory_path() /
               (L"ss_hooktrust_" + std::to_wstring(::GetCurrentProcessId()) + L"_" +
                std::to_wstring(::GetTickCount64()))) {
        std::filesystem::create_directories(path);
    }
    ~ScratchDirectory() {
        std::error_code ec;
        std::filesystem::remove_all(path, ec);
    }
    std::filesystem::path path;
};

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
        if (!Guard().IsInitialized()) {
            (void)Guard().Initialize();
        }
        // The exemption asks the engine's publisher-trust policy, which needs a signature
        // validator. Production has both; without them the predicate fails closed.
        (void)ShadowStrike::Core::Engine::ScanEngine::Instance();
        s_validatorReady = ShadowStrike::Security::DigitalSignatureValidator::Instance().Initialize() ||
                           ShadowStrike::Security::DigitalSignatureValidator::Instance().IsInitialized();
    }

    void SetUp() override { ASSERT_TRUE(s_validatorReady) << "DigitalSignatureValidator did not initialise"; }

    static inline bool s_validatorReady = false;
};

// Task 307: the exemption is decided by a verified signature from a trusted publisher, through
// ScanEngine::EvaluatePublisherTrust. Location used to decide it, which excused anything an
// administrator-level attacker placed in System32 and refused signed binaries elsewhere.

TEST_F(HookLegitimacyTest, AMicrosoftSignedSystemBinaryIsExcused) {
    const std::wstring system = RealSystemDirectory();
    ASSERT_FALSE(system.empty());
    EXPECT_TRUE(Guard().IsLegitimateHook(HookFromPath(system + L"\\user32.dll")));
    std::wstring upper = system + L"\\USER32.DLL";
    std::transform(upper.begin(), upper.end(), upper.begin(), ::towupper);
    EXPECT_TRUE(Guard().IsLegitimateHook(HookFromPath(upper))) << "Windows paths are case-insensitive";
}

TEST_F(HookLegitimacyTest, BeingUnderTheSystemDirectoryNoLongerExcusesAHook) {
    const std::wstring system = RealSystemDirectory();
    ASSERT_FALSE(system.empty());
    EXPECT_FALSE(Guard().IsLegitimateHook(HookFromPath(system + L"\\drivers\\etc\\nested.dll")))
        << "a path under System32 with no signed image behind it was excused by location alone";
}

TEST_F(HookLegitimacyTest, TheSignatureIsCheckedOnTheImageNotItsNameOrFolder) {
    const std::wstring system = RealSystemDirectory();
    ASSERT_FALSE(system.empty());
    ScratchDirectory scratch;
    const std::filesystem::path copy = scratch.path / L"user32.dll";
    // Same file name as the signed one, so trusting by name cannot pass this case.
    std::filesystem::create_directories(scratch.path / L"tampered");
    const std::filesystem::path tampered = scratch.path / L"tampered" / L"user32.dll";
    const std::filesystem::path unsignedImage = scratch.path / L"svchost.exe";
    std::error_code ec;
    ASSERT_TRUE(std::filesystem::copy_file(system + L"\\user32.dll", copy, ec)) << ec.message();
    ASSERT_TRUE(std::filesystem::copy_file(copy, tampered, ec)) << ec.message();
    {
        std::fstream f(tampered, std::ios::in | std::ios::out | std::ios::binary);
        ASSERT_TRUE(f.good());
        f.seekg(0x400);
        const char byte = static_cast<char>(f.get());
        f.seekp(0x400);
        f.put(static_cast<char>(byte ^ 0x5A));
    }
    {
        std::ofstream f(unsignedImage, std::ios::binary);
        f << "MZ not a signed image";
    }

    EXPECT_TRUE(Guard().IsLegitimateHook(HookFromPath(copy.wstring())))
        << "a Microsoft-signed image is trusted wherever it runs";
    EXPECT_FALSE(Guard().IsLegitimateHook(HookFromPath(tampered.wstring())))
        << "one changed byte must break the trust, or the check is not on the image";
    EXPECT_FALSE(Guard().IsLegitimateHook(HookFromPath(unsignedImage.wstring())))
        << "a system process NAME confers nothing";
}

TEST_F(HookLegitimacyTest, AUserCreatedDirectoryOfTheSameNameIsNotExcused) {
    EXPECT_FALSE(Guard().IsLegitimateHook(
        HookFromPath(L"C:\\Users\\victim\\windows\\system32\\keylogger.exe")));
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
