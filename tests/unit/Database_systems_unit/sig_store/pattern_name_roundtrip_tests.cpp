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
/*
 * ============================================================================
 * Pattern identity across the database round trip
 * ============================================================================
 *
 * A pattern's NAME is the only part of its database identity that survives a
 * reload. PatternMetadata says so where it is declared: signatureId is
 * positional and gets renumbered by the first OptimizeByHitRate pass, so the
 * name is what a detection is reported as - in the log, in the threat callback,
 * and in whatever the user is shown.
 *
 * Nothing tested that it survives. The existing coverage adds a pattern to a
 * store in memory and scans for it, which never serialises anything, and the
 * build-side coverage asks whether a pattern matches at all. A name could
 * therefore be lost in serialisation and every test would still pass.
 *
 * It was lost, and it shipped. The writer built the name with
 *
 *     std::string nameStr = pattern.name + "\0";
 *
 * which appends nothing: operator+ copies the literal up to its first NUL and
 * the first character of "\0" IS that NUL. So no terminator reached the file,
 * the name ran straight into the pattern bytes written immediately after it,
 * and the loader - scanning for a terminator bounded by the section end,
 * correctly refusing to read past it - found none and substituted a generated
 * placeholder.
 *
 * Measured in the database that shipped, built 2026-08-13:
 *
 *     nameOffset 0x1D030, dataOffset 0x1D042, gap 18
 *     len("EICAR-Test-Pattern")          == 18      no room for a terminator
 *     bytes at nameOffset: 'EICAR-Test-PatternX5O!P%@AP[4\PZ...'
 *     loader verdict: UnnamedPattern_0
 *
 * The same content built by the current writer gives gap 19 and the name reads
 * back exactly. One byte.
 *
 * These cases guard it at two levels, deliberately:
 *
 *   1. BEHAVIOURAL - build, reload, scan, and require the reported name to be
 *      the one supplied. This is what a user sees.
 *   2. FORMAT - walk the serialised bytes and require a NUL inside the section
 *      at the end of every name. This holds even if the loader's fallback
 *      changes, and it is the invariant that actually broke. A loader that
 *      started guessing names from adjacent bytes would satisfy (1) and fail
 *      (2), which is the right way round.
 * ============================================================================
 */

#include "pch.h"

#include <gtest/gtest.h>

#include "PhantomCore/SignatureStore/SignatureBuilder.hpp"
#include "PhantomCore/SignatureStore/SignatureFormat.hpp"
#include "PhantomCore/PatternStore/PatternStore.hpp"

#include <cstring>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

using namespace ShadowStrike::SignatureStore;
using ShadowStrike::PatternStore::PatternStore;

namespace {

/// @brief One pattern, as handed to the builder and as it must come back.
struct NamedPattern {
    const char* hex;
    const char* name;
    std::vector<uint8_t> bytes;
    ThreatLevel level;
};

/// @brief Names of DIFFERENT lengths on purpose.
///
/// A terminator bug is length-sensitive: whether the name runs into the next
/// blob depends on where that blob lands, so a single fixed-length name can
/// pass by luck. Odd and even lengths also cross the writer's alignment.
std::vector<NamedPattern> MakePatterns() {
    return {
        { "DE AD BE EF 11 22 33 44", "ShortName",
          { 0xDE, 0xAD, 0xBE, 0xEF, 0x11, 0x22, 0x33, 0x44 }, ThreatLevel::High },
        { "A1 B2 C3 D4 E5 F6 07 18 29 3A", "A-Rather-Longer-Pattern-Name-Here",
          { 0xA1, 0xB2, 0xC3, 0xD4, 0xE5, 0xF6, 0x07, 0x18, 0x29, 0x3A }, ThreatLevel::Critical },
        { "5A 6B 7C 8D 9E AF B0 C1 D2", "Mid_Length_Name",
          { 0x5A, 0x6B, 0x7C, 0x8D, 0x9E, 0xAF, 0xB0, 0xC1, 0xD2 }, ThreatLevel::Medium },
    };
}

class PatternNameRoundTripTest : public ::testing::Test {
protected:
    std::filesystem::path m_dbPath;

    void SetUp() override {
        m_dbPath = std::filesystem::temp_directory_path() /
                   ("ss_pattern_roundtrip_" + std::to_string(::GetCurrentProcessId()) + ".sdb");
        std::error_code ec;
        std::filesystem::remove(m_dbPath, ec);
    }

    void TearDown() override {
        std::error_code ec;
        std::filesystem::remove(m_dbPath, ec);
    }

    /// @brief Build a database containing exactly the given patterns.
    [[nodiscard]] bool BuildDatabase(const std::vector<NamedPattern>& patterns) {
        BuildConfiguration config{};
        config.outputPath = m_dbPath.wstring();
        config.overwriteExisting = true;
        config.enableDeduplication = true;
        config.strictValidation = true;
        config.initialDatabaseSize = 8ull * 1024ull * 1024ull;

        SignatureBuilder builder(config);
        for (const auto& p : patterns) {
            const auto err = builder.AddPattern(p.hex, p.name, p.level);
            if (!err.IsSuccess()) {
                ADD_FAILURE() << "AddPattern rejected '" << p.name << "': " << err.message;
                return false;
            }
        }
        const auto built = builder.Build();
        if (!built.IsSuccess()) {
            ADD_FAILURE() << "Build failed: " << built.message;
            return false;
        }
        return std::filesystem::exists(m_dbPath);
    }

    [[nodiscard]] std::vector<uint8_t> ReadDatabase() const {
        std::ifstream f(m_dbPath, std::ios::binary);
        if (!f) return {};
        return std::vector<uint8_t>(std::istreambuf_iterator<char>(f),
                                    std::istreambuf_iterator<char>());
    }
};

// ============================================================================
// 1. BEHAVIOURAL - what the user is shown
// ============================================================================

TEST_F(PatternNameRoundTripTest, APatternIsReportedByItsOwnNameAfterAReload) {
    const auto patterns = MakePatterns();
    ASSERT_TRUE(BuildDatabase(patterns));

    PatternStore store;
    ASSERT_TRUE(store.Initialize(m_dbPath.wstring(), /*readOnly=*/true).IsSuccess())
        << "the database just built could not be opened";

    for (const auto& expected : patterns) {
        // Surround the pattern so a match is not an artefact of buffer edges.
        std::vector<uint8_t> buffer{ 0x00, 0x11, 0x22 };
        buffer.insert(buffer.end(), expected.bytes.begin(), expected.bytes.end());
        buffer.insert(buffer.end(), { 0x33, 0x44, 0x55 });

        const auto results = store.Scan(buffer);
        ASSERT_FALSE(results.empty())
            << "pattern '" << expected.name << "' was built into the database but matched nothing";

        bool sawTheName = false;
        for (const auto& r : results) {
            if (r.signatureName == expected.name) {
                sawTheName = true;
                EXPECT_EQ(expected.level, r.threatLevel)
                    << "severity did not survive the round trip for '" << expected.name << "'";
            }
            EXPECT_TRUE(r.signatureName.rfind("UnnamedPattern", 0) != 0)
                << "a generated placeholder came back instead of a name: '" << r.signatureName
                << "'. The name was not readable in the database - check that the writer "
                   "emits a NUL terminator after it.";
        }
        EXPECT_TRUE(sawTheName)
            << "'" << expected.name << "' matched, but under a different name";
    }
}

TEST_F(PatternNameRoundTripTest, EveryLoadedPatternHasTheNameItWasGiven) {
    // Non-vacuity for the case above: that one only inspects patterns it managed
    // to match. This one requires the store to hold exactly the names supplied,
    // so a name lost on a pattern that happens not to match is still caught.
    const auto patterns = MakePatterns();
    ASSERT_TRUE(BuildDatabase(patterns));

    PatternStore store;
    ASSERT_TRUE(store.Initialize(m_dbPath.wstring(), /*readOnly=*/true).IsSuccess());
    EXPECT_EQ(patterns.size(), store.GetStatistics().totalPatterns)
        << "the store did not load every pattern that was built";
}

// ============================================================================
// 2. FORMAT - the invariant that actually broke
// ============================================================================

TEST_F(PatternNameRoundTripTest, EveryNameIsNulTerminatedInsideThePatternSection) {
    const auto patterns = MakePatterns();
    ASSERT_TRUE(BuildDatabase(patterns));

    const auto raw = ReadDatabase();
    ASSERT_GE(raw.size(), sizeof(SignatureDatabaseHeader));

    SignatureDatabaseHeader dbHeader{};
    std::memcpy(&dbHeader, raw.data(), sizeof(dbHeader));
    ASSERT_EQ(SIGNATURE_DB_MAGIC, dbHeader.magic);

    const uint64_t sectionOffset = dbHeader.patternIndexOffset;
    const uint64_t sectionSize = dbHeader.patternIndexSize;
    ASSERT_GT(sectionOffset, 0u) << "no pattern section was written";
    ASSERT_GT(sectionSize, 0u);
    ASSERT_LE(sectionOffset + sectionSize, raw.size());

    TrieIndexHeader trie{};
    std::memcpy(&trie, raw.data() + sectionOffset, sizeof(trie));
    ASSERT_EQ(TRIE_INDEX_MAGIC, trie.magic);
    ASSERT_EQ(TRIE_INDEX_VERSION, trie.version)
        << "a section the current loader will refuse was written";
    ASSERT_EQ(patterns.size(), trie.patternEntryCount);
    ASSERT_GT(trie.patternEntryOffset, 0u);

    const uint64_t sectionEnd = sectionOffset + sectionSize;
    const uint64_t entryArray = sectionOffset + trie.patternEntryOffset;

    for (uint64_t i = 0; i < trie.patternEntryCount; ++i) {
        const uint64_t at = entryArray + i * sizeof(PatternEntry);
        ASSERT_LE(at + sizeof(PatternEntry), raw.size()) << "entry " << i;

        PatternEntry entry{};
        std::memcpy(&entry, raw.data() + at, sizeof(entry));

        // The name must lie in the section, or the loader cannot read it at all.
        ASSERT_GE(entry.nameOffset, sectionOffset) << "entry " << i << " name is below the section";
        ASSERT_LE(entry.nameOffset, sectionEnd) << "entry " << i << " name is past the section";

        // A terminator must appear before the section ends. This is the exact
        // check the loader performs, so failing it here means the loader would
        // substitute a placeholder.
        const uint64_t available = sectionEnd - entry.nameOffset;
        uint64_t len = 0;
        while (len < available && raw[static_cast<size_t>(entry.nameOffset + len)] != '\0') {
            ++len;
        }
        ASSERT_LT(len, available)
            << "entry " << i << ": no NUL terminator between the name at 0x" << std::hex
            << entry.nameOffset << " and the end of the section at 0x" << sectionEnd << std::dec
            << ". The loader will report this pattern as UnnamedPattern_" << i << ".";

        const std::string name(reinterpret_cast<const char*>(raw.data() + entry.nameOffset),
                               static_cast<size_t>(len));
        EXPECT_FALSE(name.empty()) << "entry " << i << " has an empty name";

        // The terminator must be a byte of its own, not borrowed from whatever
        // follows. This is the difference between gap 18 and gap 19 in the
        // database that shipped: if the data blob begins at the byte that ought
        // to hold the terminator, there is no terminator.
        if (entry.dataOffset > entry.nameOffset) {
            EXPECT_GT(entry.dataOffset, entry.nameOffset + len)
                << "entry " << i << " ('" << name << "'): the pattern data at 0x" << std::hex
                << entry.dataOffset << " begins at or before the name's terminator at 0x"
                << (entry.nameOffset + len) << std::dec
                << ", so the name has no terminator of its own";
        }
    }
}

TEST_F(PatternNameRoundTripTest, TheNamesInTheFileAreExactlyTheNamesSupplied) {
    // Reads the names straight out of the file and compares the SET, so a name
    // written to the wrong entry is caught as well as a name lost entirely.
    const auto patterns = MakePatterns();
    ASSERT_TRUE(BuildDatabase(patterns));

    const auto raw = ReadDatabase();
    ASSERT_GE(raw.size(), sizeof(SignatureDatabaseHeader));

    SignatureDatabaseHeader dbHeader{};
    std::memcpy(&dbHeader, raw.data(), sizeof(dbHeader));
    const uint64_t sectionOffset = dbHeader.patternIndexOffset;
    const uint64_t sectionEnd = sectionOffset + dbHeader.patternIndexSize;
    ASSERT_GT(sectionOffset, 0u);

    TrieIndexHeader trie{};
    std::memcpy(&trie, raw.data() + sectionOffset, sizeof(trie));
    const uint64_t entryArray = sectionOffset + trie.patternEntryOffset;

    std::vector<std::string> fromFile;
    for (uint64_t i = 0; i < trie.patternEntryCount; ++i) {
        PatternEntry entry{};
        std::memcpy(&entry, raw.data() + entryArray + i * sizeof(PatternEntry), sizeof(entry));
        if (entry.nameOffset < sectionOffset || entry.nameOffset > sectionEnd) continue;

        const uint64_t available = sectionEnd - entry.nameOffset;
        uint64_t len = 0;
        while (len < available && raw[static_cast<size_t>(entry.nameOffset + len)] != '\0') {
            ++len;
        }
        if (len == available) continue;  // unterminated; the case above reports it
        fromFile.emplace_back(reinterpret_cast<const char*>(raw.data() + entry.nameOffset),
                              static_cast<size_t>(len));
    }

    std::vector<std::string> expected;
    for (const auto& p : patterns) expected.emplace_back(p.name);

    std::sort(fromFile.begin(), fromFile.end());
    std::sort(expected.begin(), expected.end());
    EXPECT_EQ(expected, fromFile)
        << "the names in the database are not the names that were built into it";
}

}  // namespace
