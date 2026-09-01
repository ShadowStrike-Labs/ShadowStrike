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
        // Shut down explicitly. This is the engine's documented contract - a caller
        // that succeeds at Initialize() owes a Shutdown() while the process is still
        // running - and it is what RealTimeProtection::Stop does at step 4.
        //
        // It was originally added here as a workaround: leaving the engine initialised
        // crashed the process at exit with an access violation AFTER every test had
        // reported passing (measured: 0xC0000005 without this call, 0 with it, and 0
        // with these tests filtered out).
        //
        // THE DIAGNOSIS RECORDED HERE FIRST WAS INCOMPLETE and is corrected for
        // anyone reading it later. It was not the worker pool being destroyed by
        // static destruction. ScanEngine::Impl borrows SEVEN other singletons as raw
        // pointers, all first touched by Initialize(), so all of them complete
        // construction after ScanEngine and are destroyed BEFORE it - and the teardown
        // called ->Shutdown() through every one. The destructor now releases borrowed
        // subsystems without calling into them, and the invariant is checked on every
        // run by tests/unit/scan_engine_teardown, which deliberately leaves the engine
        // initialized at process exit.
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

// ============================================================================
// WINDOWS CATALOG STORE
//
// Scanning the catalog store deadlocks our own signature verification: the
// pipeline memory-mapped C:\Windows\System32\catroot2\edb.log, which stopped ESE
// rolling that log over, which stalled CryptSvc, which our trust determination
// then waited on for 35.0 seconds at a time. Measured in the field on 1.0.103.
//
// These assert the WIRING, not the list, for the same reason the tests above do:
// a test over the returned strings would have passed throughout the entire period
// nothing was registered.
// ============================================================================

namespace {

// Derive a sibling path from a catalog prefix so these tests need no hardcoded
// volume and stay correct on a machine whose Windows directory is not C:\Windows.
std::wstring System32DirectoryOf(const std::wstring& prefix) {
    const std::wstring marker = L"\\system32\\";
    const std::wstring lowered = ToLower(prefix);
    const auto pos = lowered.rfind(marker);
    if (pos == std::wstring::npos) {
        return L"";
    }
    return prefix.substr(0, pos + marker.size());
}

}  // namespace

TEST(SelfExclusion_CatalogStore, PrefixesAreProvidedAndWellFormed) {
    const auto prefixes = Paths::GetCatalogStoreDirectoryPrefixes();

    ASSERT_FALSE(prefixes.empty())
        << "empty means the Windows directory could not be resolved, so the "
           "catalog store is not excluded and the verification stall is live";

    size_t plain = 0;
    size_t extended = 0;

    for (const auto& p : prefixes) {
        ASSERT_FALSE(p.empty());

        // A prefix match is only safe if it cannot run past the directory it
        // names, so every entry must end at a separator.
        EXPECT_EQ(p.back(), L'\\')
            << "a prefix not ending at a separator would match sibling directories";

        if (p.rfind(L"\\\\?\\", 0) == 0) {
            ++extended;
        } else {
            ++plain;
            EXPECT_NE(p.find(L':'), std::wstring::npos) << "expected an absolute path";
        }
    }

    // Both forms are required: the pipeline uses plain DOS paths in some places
    // and \\?\-extended paths in others for the same file.
    EXPECT_GT(plain, 0u);
    EXPECT_GT(extended, 0u);
    EXPECT_EQ(plain, extended);
}

TEST_F(SelfExclusion_EngineWiring, CatalogStoreIsExcludedFromScanning) {
    ASSERT_TRUE(s_initialized);

    const auto prefixes = Paths::GetCatalogStoreDirectoryPrefixes();
    ASSERT_FALSE(prefixes.empty());

    for (const auto& prefix : prefixes) {
        // edb.log is the exact file the field run memory-mapped.
        EXPECT_TRUE(ScanEngine::Instance().IsExcluded(prefix + L"edb.log"))
            << "the catalog store is still scannable; this is the field defect";

        // A per-GUID subdirectory, to prove the exclusion is recursive rather
        // than covering only files sitting directly in the directory.
        EXPECT_TRUE(ScanEngine::Instance().IsExcluded(
            prefix + L"{127D0A1D-4EF2-11D1-8608-00C04FC295EE}\\catdb.jfm"))
            << "catalog subdirectories must be covered too";
    }
}

TEST_F(SelfExclusion_EngineWiring, CatalogRulesArePrefixRulesAndNothingElseIs) {
    ASSERT_TRUE(s_initialized);

    size_t catalogRules = 0;

    for (const auto& r : ScanEngine::Instance().GetExclusions()) {
        const bool isCatalog = r.description.find("catalog store") != std::string::npos;
        if (!isCatalog) {
            // Nothing outside the catalog category may be a prefix rule. This is
            // what stops a future change from turning our own data directory, the
            // log directory or the quarantine vault into a drop zone.
            EXPECT_NE(r.type, ExclusionRule::Type::PathPrefix)
                << "an unexpected prefix exclusion was registered";
            continue;
        }
        ++catalogRules;
        EXPECT_EQ(r.type, ExclusionRule::Type::PathPrefix);
        EXPECT_TRUE(r.enabled);
        EXPECT_TRUE(r.recursive);
        ASSERT_FALSE(r.pattern.empty());
        EXPECT_EQ(r.pattern.back(), L'\\');
    }

    EXPECT_EQ(catalogRules, Paths::GetCatalogStoreDirectoryPrefixes().size())
        << "every provided prefix must reach the engine";
}

TEST_F(SelfExclusion_EngineWiring, SiblingSystem32ContentIsStillScanned) {
    ASSERT_TRUE(s_initialized);

    const auto prefixes = Paths::GetCatalogStoreDirectoryPrefixes();
    ASSERT_FALSE(prefixes.empty());

    const std::wstring system32 = System32DirectoryOf(prefixes.front());
    ASSERT_FALSE(system32.empty()) << "could not derive System32 from the prefix";

    // The exclusion must cover the catalog store and nothing more. If the
    // prefixes ever lose their trailing separator, or are widened to the
    // driver's substring form, these two fail.
    EXPECT_FALSE(ScanEngine::Instance().IsExcluded(system32 + L"kernel32.dll"))
        << "excluding System32 at large would blind the scanner";
    EXPECT_FALSE(ScanEngine::Instance().IsExcluded(system32 + L"CatRootOther\\payload.exe"))
        << "a sibling directory whose name merely starts with CatRoot must be scanned";
    EXPECT_FALSE(ScanEngine::Instance().IsExcluded(system32 + L"catroot2backup\\payload.exe"))
        << "a sibling directory whose name merely starts with catroot2 must be scanned";
}

TEST(SelfExclusion_CatalogStore, IsDisjointFromTheOwnedFileList) {
    // The two lists exist for different reasons and are matched differently.
    // Merging them is the one change that would silently reintroduce a drop zone,
    // so their disjointness is pinned here rather than left to review.
    const auto owned = Paths::GetOwnedDataFiles();
    const auto catalog = Paths::GetCatalogStoreDirectoryPrefixes();

    for (const auto& o : owned) {
        const std::wstring lo = ToLower(o);
        for (const auto& c : catalog) {
            EXPECT_NE(lo, ToLower(c));
            EXPECT_FALSE(lo.rfind(ToLower(c), 0) == 0)
                << "an owned data file must not sit under a catalog prefix";
        }
    }

    // And no catalog prefix may be an owned-file path, which would make it
    // subject to the exact-match rule and silently stop covering the directory.
    for (const auto& c : catalog) {
        EXPECT_NE(c.back(), L'b');  // cheap shape check: ends at a separator
        EXPECT_EQ(c.back(), L'\\');
    }
}
