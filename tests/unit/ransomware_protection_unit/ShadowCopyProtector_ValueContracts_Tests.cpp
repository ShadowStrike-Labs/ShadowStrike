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
/**
 * @file ShadowCopyProtector_ValueContracts_Tests.cpp
 * @brief Value-contract coverage for Ransomware::ShadowCopyProtector.
 */

#include "pch.h"
#include <gtest/gtest.h>
#include <gmock/gmock.h>

#include "../../../src/PhantomCore/RansomwareProtection/ShadowCopyProtector.hpp"

namespace {

using namespace ShadowStrike::Ransomware;
using ::testing::HasSubstr;

TEST(ShadowCopyProtectorValueContractTests, ConfigStatisticsSerializationHelpersAndVersionRemainStable) {
    ShadowCopyProtectorConfiguration config;
    EXPECT_TRUE(config.IsValid());

    auto invalidEntry = config;
    invalidEntry.whitelist.push_back(L"");
    EXPECT_FALSE(invalidEntry.IsValid());

    auto invalidLimit = config;
    invalidLimit.whitelist.assign(ShadowCopyConstants::MAX_WHITELIST_ENTRIES + 1, L"C:\\safe.exe");
    EXPECT_FALSE(invalidLimit.IsValid());

    auto validLimit = config;
    validLimit.whitelist.assign(ShadowCopyConstants::MAX_WHITELIST_ENTRIES, L"C:\\safe.exe");
    EXPECT_TRUE(validLimit.IsValid());

    ShadowCopyStatistics stats;
    stats.attacksBlocked.store(3, std::memory_order_relaxed);
    stats.processesKilled.store(2, std::memory_order_relaxed);
    stats.processesBlockedKernel.store(1, std::memory_order_relaxed);
    stats.snapshotDecreaseAlerts.store(4, std::memory_order_relaxed);
    stats.currentShadowCopies.store(5, std::memory_order_relaxed);
    stats.byAttackType[static_cast<size_t>(VSSAttackType::CommandLineDelete)].store(
        7, std::memory_order_relaxed);
    EXPECT_THAT(stats.ToJson(), HasSubstr("CommandLineDelete"));
    stats.Reset();

    EXPECT_EQ(stats.attacksBlocked.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.processesKilled.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.processesBlockedKernel.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.snapshotDecreaseAlerts.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.currentShadowCopies.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(
        stats.byAttackType[static_cast<size_t>(VSSAttackType::CommandLineDelete)].load(
            std::memory_order_relaxed),
        0u);
    EXPECT_LT(
        std::chrono::duration_cast<std::chrono::seconds>(Clock::now() - stats.startTime).count(),
        2);

    ShadowCopyInfo info;
    info.shadowId = L"shadow-1";
    info.volume = L"C:\\";
    info.isProtected = true;
    info.providerId = L"provider-1";
    EXPECT_THAT(info.ToJson(), HasSubstr("\"shadowId\": \"shadow-1\""));
    EXPECT_THAT(info.ToJson(), HasSubstr("\"providerId\": \"provider-1\""));

    VSSAttackEvent event;
    event.attackType = VSSAttackType::WMIDelete;
    event.processName = L"wmic.exe";
    event.details = L"delete shadow copies";
    EXPECT_THAT(event.ToJson(), HasSubstr("\"attackTypeName\": \"WMIDelete\""));
    EXPECT_THAT(event.ToJson(), HasSubstr("\"details\": \"delete shadow copies\""));

    ShadowCopyStatisticsSnapshot snapshot;
    snapshot.attacksBlocked = 5;
    snapshot.currentShadowCopies = 3;
    snapshot.uptimeSeconds = 11;
    snapshot.byAttackType[static_cast<size_t>(VSSAttackType::WMIDelete)] = 2;
    EXPECT_THAT(snapshot.ToJson(), HasSubstr("\"WMIDelete\": 2"));
    EXPECT_THAT(snapshot.ToJson(), HasSubstr("\"uptimeSeconds\": 11"));

    EXPECT_EQ(GetVSSAttackTypeName(VSSAttackType::ProviderDisable), "ProviderDisable");
    EXPECT_EQ(GetShadowCopyStateName(ShadowCopyState::Corrupted), "Corrupted");
    EXPECT_EQ(GetVSSAttackTypeName(static_cast<VSSAttackType>(0xFF)), "Unknown");
    EXPECT_EQ(ShadowCopyProtector::GetVersionString(), "3.1.0");
}

// ============================================================================
// Outcome-reporting contract
//
// VSSAttackEvent::wasBlocked used to default to TRUE, so any event that simply
// forgot to assign it claimed a block - and ReportThreatToAlertSystem turns a
// true value into a Critical alert titled "Blocked". A default cannot be found
// by grepping for an assignment, which is precisely what hid it, so the default
// itself is asserted here.
// ============================================================================
TEST(ShadowCopyProtectorValueContractTests, ADefaultConstructedEventClaimsNothing) {
    VSSAttackEvent event;

    // THE DISCRIMINATOR: fails against the previous header, where wasBlocked
    // defaulted to true.
    EXPECT_FALSE(event.wasBlocked)
        << "a default-constructed VSS attack event must not claim a block";
    EXPECT_FALSE(event.blockRequested)
        << "a default-constructed VSS attack event must not claim a block was requested";

    // Both flags must reach the JSON, because that payload is what an operator
    // and the alert pipeline actually read.
    const std::string json = event.ToJson();
    EXPECT_THAT(json, HasSubstr("\"blockRequested\""));
    EXPECT_THAT(json, HasSubstr("\"wasBlocked\""));
}

// The gap counter must survive a COPY, not merely exist. ShadowCopyStatistics
// hand-writes its copy constructor and assignment operator to load atomics
// safely, so a member added to the declaration alone is silently dropped on
// every copy - and GetStatistics() copies. That turns the counter into a
// structural zero that looks healthy from outside, which is the same failure
// mode as a saturation metric nothing ever writes.
TEST(ShadowCopyProtectorValueContractTests, TheUnperformedBlockCounterSurvivesCopyAndReset) {
    ShadowCopyStatistics stats;
    stats.attacksBlocked.store(2, std::memory_order_relaxed);
    stats.blockRequestedNotPerformed.store(9, std::memory_order_relaxed);

    const ShadowCopyStatistics copied(stats);
    EXPECT_EQ(copied.blockRequestedNotPerformed.load(std::memory_order_relaxed), 9u)
        << "the hand-written copy constructor dropped the counter";

    ShadowCopyStatistics assigned;
    assigned = stats;
    EXPECT_EQ(assigned.blockRequestedNotPerformed.load(std::memory_order_relaxed), 9u)
        << "the hand-written assignment operator dropped the counter";

    EXPECT_THAT(stats.ToJson(), HasSubstr("blockRequestedNotPerformed"));

    stats.Reset();
    EXPECT_EQ(stats.blockRequestedNotPerformed.load(std::memory_order_relaxed), 0u)
        << "Reset() must clear the counter or it becomes a stale delta baseline";

    ShadowCopyStatisticsSnapshot snapshot;
    snapshot.blockRequestedNotPerformed = 4;
    EXPECT_THAT(snapshot.ToJson(), HasSubstr("blockRequestedNotPerformed"));
}

// ============================================================================
// ENCODED-COMMAND EXTRACTION
//
// These cases exist because the -EncodedCommand arm decoded a LOWERCASED
// payload. Base64 is case-sensitive ('A' is 0, 'a' is 26), so lowercasing
// remaps every six-bit group - and because every character stays a legal base64
// character the decode SUCCEEDED, the recursive analysis examined the resulting
// garbage, matched no VSS keyword, and reported no attack. Nothing failed, so
// nothing logged: what it looked like when broken was identical to what it
// looks like when working, which is exactly why this needs a behavioural test.
// ============================================================================

// Minimal base64 encoder so every payload below is COMPUTED from the command it
// represents rather than typed as a literal. One wrong character would produce a
// payload that decodes to something harmless and a test that passes for the
// wrong reason - the discipline the shipped EICAR pattern was authored under.
std::wstring Base64OfUtf16(std::wstring_view inner) {
    static constexpr char kAlphabet[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    const auto* bytes = reinterpret_cast<const unsigned char*>(inner.data());
    const size_t len = inner.size() * sizeof(wchar_t);  // UTF-16LE, as PowerShell requires
    std::string out;
    for (size_t i = 0; i < len; i += 3) {
        const unsigned b0 = bytes[i];
        const unsigned b1 = (i + 1 < len) ? bytes[i + 1] : 0u;
        const unsigned b2 = (i + 2 < len) ? bytes[i + 2] : 0u;
        out.push_back(kAlphabet[b0 >> 2]);
        out.push_back(kAlphabet[((b0 & 0x03u) << 4) | (b1 >> 4)]);
        out.push_back((i + 1 < len) ? kAlphabet[((b1 & 0x0Fu) << 2) | (b2 >> 6)] : '=');
        out.push_back((i + 2 < len) ? kAlphabet[b2 & 0x3Fu] : '=');
    }
    return std::wstring(out.begin(), out.end());
}

// Phase 3 of the analyzer matches vssadmin plus "delete shadows", so a correct
// decode MUST classify this and an incorrect one cannot.
constexpr const wchar_t* kInnerVssDelete = L"vssadmin delete shadows /all /quiet";

TEST(ShadowCopyProtectorEncodedCommandTests, TheEncoderItselfIsCorrect) {
    // UTF-16LE "A" is the two bytes 0x41 0x00, whose base64 is "QQA=". Asserting
    // the helper against a known vector is what stops a broken encoder from
    // making every case below vacuous.
    EXPECT_EQ(Base64OfUtf16(L"A"), L"QQA=");
}

TEST(ShadowCopyProtectorEncodedCommandTests, PlainShadowDeletionIsClassified) {
    // POSITIVE CONTROL, deliberately NOT a discriminator - it passes before and
    // after the fix. Its job is to prove the analyzer runs at all, so that a
    // nullopt in the encoded cases means "not decoded" rather than "inert".
    auto& p = ShadowCopyProtector::Instance();
    EXPECT_TRUE(p.AnalyzeCommand(L"vssadmin delete shadows /all /quiet").has_value());
}

TEST(ShadowCopyProtectorEncodedCommandTests, DocumentedMixedCaseFlagSpellingIsDecoded) {
    // THE DISCRIMINATOR. "-EncodedCommand" is the spelling Microsoft documents
    // and every tool emits. The old flag search used std::wstring::find against
    // lowercase literals, so it never matched this spelling and the caller fell
    // back to the lowercased payload, decoding remapped bytes.
    auto& p = ShadowCopyProtector::Instance();
    const std::wstring cmd =
        L"powershell.exe -EncodedCommand " + Base64OfUtf16(kInnerVssDelete);
    EXPECT_TRUE(p.AnalyzeCommand(cmd).has_value())
        << "encoded T1490 shadow deletion must be classified when the flag "
           "carries its documented capitalisation";
}

TEST(ShadowCopyProtectorEncodedCommandTests, ShortFlagFormIsDecoded) {
    // THE SECOND DISCRIMINATOR. The Phase 12 comment has always claimed to catch
    // "powershell -e <base64>" while the flag list contained no bare -e entry.
    auto& p = ShadowCopyProtector::Instance();
    const std::wstring cmd = L"powershell -e " + Base64OfUtf16(kInnerVssDelete);
    EXPECT_TRUE(p.AnalyzeCommand(cmd).has_value())
        << "the most compact form of this obfuscation must be classified";
}

TEST(ShadowCopyProtectorEncodedCommandTests, AllLowerCaseFlagStillDecodes) {
    // REGRESSION GUARD, not a discriminator: this is the one spelling that
    // worked before, and it must keep working now the search is case-insensitive.
    auto& p = ShadowCopyProtector::Instance();
    const std::wstring cmd =
        L"powershell.exe -encodedcommand " + Base64OfUtf16(kInnerVssDelete);
    EXPECT_TRUE(p.AnalyzeCommand(cmd).has_value());
}

TEST(ShadowCopyProtectorEncodedCommandTests, ExecutionPolicyIsNotMistakenForAnEncodedFlag) {
    // THE SAFETY PROPERTY THAT MAKES A BARE -e ACCEPTABLE AT ALL. "-e" occurs
    // inside "-ExecutionPolicy", and the extraction returns on its first match,
    // so without the complete-token rule this ordinary command line would yield
    // the token "xecutionpolicy" and the real flag would never be looked for -
    // turning a missing capability into a shadowed one.
    auto& p = ShadowCopyProtector::Instance();
    EXPECT_FALSE(
        p.AnalyzeCommand(L"powershell -ExecutionPolicy Bypass -File C:\\tmp\\x.ps1")
            .has_value())
        << "an ordinary -ExecutionPolicy invocation must not be classified as a "
           "VSS attack";
}

TEST(ShadowCopyProtectorEncodedCommandTests, ExecutionPolicyDoesNotShadowARealEncodedFlag) {
    // The complete-token rule must also let the real flag win when both appear,
    // which is the arrangement an attacker would actually use. Also a
    // discriminator: the old case-sensitive search failed on -EncodedCommand
    // here too and fell back to the lowercased payload.
    auto& p = ShadowCopyProtector::Instance();
    const std::wstring cmd = L"powershell -ExecutionPolicy Bypass -EncodedCommand " +
                             Base64OfUtf16(kInnerVssDelete);
    EXPECT_TRUE(p.AnalyzeCommand(cmd).has_value())
        << "a benign flag earlier in the command line must not shadow the "
           "encoded payload";
}

}  // namespace
