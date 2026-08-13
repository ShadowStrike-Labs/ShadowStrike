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
// SELF-EXCLUSION TESTS
// ============================================================================
//
// The product must not scan its own detection databases. They contain malware
// indicators verbatim - compiled YARA rules embed thousands of literal malware
// strings and the pattern section stores raw byte sequences - so scanning them
// finds our own content and reports it as a threat, and a detection on
// signatures.sdb can quarantine the database and take all detection with it.
//
// WHY THESE TESTS EXIST, AND WHY THEY TEST THE WIRING RATHER THAN THE LIST.
// Before this, there were FOUR separate exclusion mechanisms in the product -
// RealTimeProtection's path/extension/process lists, ScanEngine's ExclusionRule
// vector, FileSystemFilter's list plus its driver sync, and ProfileManager's
// config lists - and not one of them had a single production caller.
// ScanEngine's list was populated only by its own self-test, using a fake path.
// So the on-access handler ran an exclusion check on every file operation that
// iterated an empty vector, and looked exactly like a working exclusion tier.
//
// That is the failure mode this codebase keeps producing: the capability is
// implemented, the call site looks right, and nothing connects them. A test on
// the contents of the list alone would have passed the whole time the product
// excluded nothing. So the load-bearing assertion here is that the engine has
// ACTUALLY REGISTERED the exclusions after Initialize, and that IsExcluded
// answers true for our database and false for a neighbouring file.
// ============================================================================

#include <algorithm>
#include <string>
#include <vector>

// ============================================================================
// GTEST
// ============================================================================

#include <gtest/gtest.h>

// ============================================================================
// SHADOWSTRIKE MODULE HEADERS
// ============================================================================

#include "src/PhantomCore/Utils/DataStorePaths.hpp"
#include "src/PhantomCore/Core/Engine/ScanEngine.hpp"

namespace Paths = ShadowStrike::Utils::DataStorePaths;
using ShadowStrike::Core::Engine::ScanEngine;
using ShadowStrike::Core::Engine::ExclusionRule;

namespace {

bool ContainsPath(const std::vector<std::wstring>& list, const std::wstring& value) {
    return std::find(list.begin(), list.end(), value) != list.end();
}

std::wstring ToLower(std::wstring s) {
    std::transform(s.begin(), s.end(), s.begin(),
                   [](wchar_t c) { return static_cast<wchar_t>(::towlower(c)); });
    return s;
}

} // namespace

// ============================================================================
// THE LIST ITSELF
// ============================================================================

TEST(SelfExclusion_OwnedFiles, ListIsNotEmpty) {
    EXPECT_FALSE(Paths::GetOwnedDataFiles().empty());
}

TEST(SelfExclusion_OwnedFiles, IncludesEveryDetectionStore) {
    const auto owned = Paths::GetOwnedDataFiles();

    // Each store holds detection content and each would self-match.
    EXPECT_TRUE(ContainsPath(owned, Paths::SignatureDatabase()));
    EXPECT_TRUE(ContainsPath(owned, Paths::WhitelistDatabase()));
    EXPECT_TRUE(ContainsPath(owned, Paths::ThreatIntelDatabase()));
    EXPECT_TRUE(ContainsPath(owned, Paths::HashReputationDatabase()));
}

TEST(SelfExclusion_OwnedFiles, EveryEntryIsAnAbsolutePath) {
    for (const auto& p : Paths::GetOwnedDataFiles()) {
        ASSERT_FALSE(p.empty());
        // A relative pattern could never match the DOS path the on-access handler
        // produces, so it would be a silently inert exclusion.
        EXPECT_GT(p.size(), size_t{3}) << "suspiciously short path";
        EXPECT_EQ(p[1], L':') << "not an absolute path: it could never match";
    }
}

// This is the security property, not a style preference. A pattern ending in '*'
// is treated as a PREFIX match by the on-access matcher, which would turn an
// entry into a whole-directory exclusion - a location an attacker can drop a
// payload into and have it never examined.
TEST(SelfExclusion_OwnedFiles, NoEntryIsAWildcardOrDirectory) {
    for (const auto& p : Paths::GetOwnedDataFiles()) {
        ASSERT_FALSE(p.empty());
        EXPECT_NE(p.back(), L'*') << "wildcard exclusion would cover a whole directory";
        EXPECT_NE(p.back(), L'\\') << "trailing separator names a directory, not a file";
        EXPECT_EQ(p.find(L'?'), std::wstring::npos) << "no globbing in an exact path list";
    }
}

TEST(SelfExclusion_OwnedFiles, NeverExcludesTheDataDirectoryItself) {
    const auto owned = Paths::GetOwnedDataFiles();
    const std::wstring dataDir = ToLower(Paths::GetDataDirectory());

    for (const auto& p : owned) {
        EXPECT_NE(ToLower(p), dataDir)
            << "excluding the data directory would exempt anything dropped into it";
    }
}

// The quarantine vault holds real malware. Its contents are AES-256-GCM
// encrypted so nothing can match them anyway, which makes excluding it both
// unnecessary and the worst possible exclusion in this product.
TEST(SelfExclusion_OwnedFiles, DoesNotCoverQuarantineOrLogs) {
    for (const auto& p : Paths::GetOwnedDataFiles()) {
        const std::wstring lower = ToLower(p);
        EXPECT_EQ(lower.find(L"\\quarantine"), std::wstring::npos)
            << "the quarantine vault must never be excluded";
        EXPECT_EQ(lower.find(L"\\logs"), std::wstring::npos)
            << "the log directory is deliberately not excluded";
    }
}

TEST(SelfExclusion_OwnedFiles, HasNoDuplicates) {
    auto owned = Paths::GetOwnedDataFiles();
    std::vector<std::wstring> lowered;
    lowered.reserve(owned.size());
    for (auto& p : owned) lowered.push_back(ToLower(p));

    std::sort(lowered.begin(), lowered.end());
    EXPECT_EQ(std::adjacent_find(lowered.begin(), lowered.end()), lowered.end())
        << "a duplicated exclusion means the list was assembled by hand somewhere";
}

// ============================================================================
// THE WIRING - the part that was actually missing
// ============================================================================

class SelfExclusion_EngineWiring : public ::testing::Test {
protected:
    static void SetUpTestSuite() {
        // Deliberately no signature database path: this test is about exclusion
        // registration, which happens before any store is opened, and opening a
        // 64 MB database here would make the test about something else.
        ShadowStrike::Core::Engine::EngineConfig cfg{};
        cfg.signatureDbPath.clear();
        s_initialized = ScanEngine::Instance().Initialize(cfg);
    }

    static void TearDownTestSuite() {
        // MUST shut down explicitly. Leaving the engine initialised crashed the
        // process at exit with an access violation AFTER every test had reported
        // passing (measured: exit code 0xC0000005 with this teardown absent, 0 with
        // it present, and 0 when these tests are filtered out). Initialize starts a
        // worker pool, and letting a running pool be torn down by static
        // destruction at process exit is unordered with respect to everything else
        // the singleton owns.
        //
        // Worth keeping in mind beyond this test: a non-zero exit code that appears
        // only after "PASSED" is exactly the kind of signal a CI run reports as a
        // failure with no failing test to point at.
        if (s_initialized) {
            ScanEngine::Instance().Shutdown();
            s_initialized = false;
        }
    }

    static bool s_initialized;
};

bool SelfExclusion_EngineWiring::s_initialized = false;

TEST_F(SelfExclusion_EngineWiring, EngineInitialized) {
    ASSERT_TRUE(s_initialized)
        << "engine did not initialize; the assertions below would be vacuous";
}

TEST_F(SelfExclusion_EngineWiring, EveryOwnedFileIsRegisteredAsAnExclusion) {
    ASSERT_TRUE(s_initialized);

    const auto rules = ScanEngine::Instance().GetExclusions();
    ASSERT_FALSE(rules.empty())
        << "no exclusions registered at all - this is the original defect";

    for (const auto& ownFile : Paths::GetOwnedDataFiles()) {
        const std::wstring wanted = ToLower(ownFile);
        const bool found = std::any_of(rules.begin(), rules.end(),
            [&](const ExclusionRule& r) {
                return r.enabled &&
                       r.type == ExclusionRule::Type::Path &&
                       ToLower(r.pattern) == wanted;
            });
        EXPECT_TRUE(found) << "own data file is not registered as an exact-path exclusion";
    }
}

TEST_F(SelfExclusion_EngineWiring, RegisteredRulesAreExactPathsNotPrefixes) {
    ASSERT_TRUE(s_initialized);

    // A PathPrefix rule over one of our files' directories would re-open the
    // drop-zone hole that the exact-path design exists to avoid.
    for (const auto& r : ScanEngine::Instance().GetExclusions()) {
        if (r.description.find("own data file") == std::string::npos) continue;
        EXPECT_EQ(r.type, ExclusionRule::Type::Path);
        ASSERT_FALSE(r.pattern.empty());
        EXPECT_NE(r.pattern.back(), L'*');
    }
}

TEST_F(SelfExclusion_EngineWiring, SignatureDatabaseIsExcluded) {
    ASSERT_TRUE(s_initialized);
    EXPECT_TRUE(ScanEngine::Instance().IsExcluded(Paths::SignatureDatabase()));
}

// Case-insensitivity is not cosmetic here: the path the scan path produces comes
// from a kernel device path conversion, so its casing is not under our control.
TEST_F(SelfExclusion_EngineWiring, ExclusionMatchIsCaseInsensitive) {
    ASSERT_TRUE(s_initialized);

    std::wstring upper = Paths::SignatureDatabase();
    std::transform(upper.begin(), upper.end(), upper.begin(),
                   [](wchar_t c) { return static_cast<wchar_t>(::towupper(c)); });

    EXPECT_TRUE(ScanEngine::Instance().IsExcluded(upper));
}

// The other half of the contract, and the reason this is not a directory
// exclusion: a file sitting next to our database is still scanned.
TEST_F(SelfExclusion_EngineWiring, NeighbouringFileInTheDataDirectoryIsNotExcluded) {
    ASSERT_TRUE(s_initialized);

    const std::wstring intruder = Paths::GetDataDirectory() + L"\\dropped_payload.exe";
    EXPECT_FALSE(ScanEngine::Instance().IsExcluded(intruder))
        << "the data directory is excluded as a whole - anything dropped there is invisible";
}

TEST_F(SelfExclusion_EngineWiring, DataDirectoryItselfIsNotExcluded) {
    ASSERT_TRUE(s_initialized);
    EXPECT_FALSE(ScanEngine::Instance().IsExcluded(Paths::GetDataDirectory()));
}

TEST_F(SelfExclusion_EngineWiring, UnrelatedPathIsNotExcluded) {
    ASSERT_TRUE(s_initialized);
    EXPECT_FALSE(ScanEngine::Instance().IsExcluded(L"C:\\Windows\\System32\\cmd.exe"));
}
