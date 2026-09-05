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
//  ARCHIVE DISPATCH ON THE SCAN PATH
//
//  WHAT WAS BROKEN. FileTypeAnalyzer classified .zip / .rar / .7z as
//  FileCategory::Archive and nothing consumed the classification.
//  ScanEngine::ScanFile dispatches on Document (stage 4.5) and Script (stage
//  4.6); Archive had no equivalent stage, so an archive was hashed and
//  pattern-scanned AS A CONTAINER. Compressed bytes match no signature, so a
//  1.0.109 field run reported "No threats found." for a real EICAR sample
//  inside eicar_com.zip.
//
//  ScanEngine::ScanArchive was already complete and correct - zip-bomb
//  refusal, path-traversal detection, nested extraction, and every entry
//  pushed through SignatureStore::ScanBuffer. Measured across 1,272
//  translation units, its only caller was Fuzzer/src/ScanEngineHarness.cpp,
//  so the entire capability had run exclusively inside a fuzz harness.
//
//  WHAT THESE TESTS ASSERT, AND WHY IT IS THE RIGHT THING TO ASSERT.
//  The defect is DISPATCH, so the tests observe dispatch:
//    archivesScanned      - ScanArchive was entered at all
//    archiveFilesScanned  - an entry was actually EXTRACTED and handed to the
//                           per-entry scan callback
//  Together those two cover the whole mechanical chain that was missing. The
//  remaining link - that SignatureStore matches EICAR's bytes once they are
//  extracted - is independently proven at build time by phantom-sigbuild,
//  which reports "1 of 1 pattern(s) matched by scan" against the shipped
//  content and fails the build otherwise.
//
//  🔴 THE ARCHIVE CONTENT HERE IS DELIBERATELY BENIGN, AND THAT IS NOT
//  LAZINESS. Putting the EICAR string in a test source would plant a live
//  test-virus signature in the repository and in phantom-tests.exe, where our
//  own scanner and the maintainer's resident AV would both act on it - the
//  same AV that already quarantines our signed driver and has cost a build
//  cycle. None of these assertions need malicious content, because none of
//  them is about signature matching.
// ============================================================================

#include <gtest/gtest.h>

#include <array>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <string>
#include <system_error>
#include <vector>

#include "src/PhantomCore/Core/Engine/ScanEngine.hpp"
#include "src/PhantomCore/Core/FileSystem/FileTypeAnalyzer.hpp"

using ShadowStrike::Core::Engine::EngineConfig;
using ShadowStrike::Core::Engine::ScanContext;
using ShadowStrike::Core::Engine::ScanEngine;
using ShadowStrike::Core::Engine::ScanType;

namespace {

    // Mirrors ScanPoolHealth_Tests.cpp: the smallest configuration the engine
    // accepts. Initialize() is idempotent, so if another suite initialized the
    // singleton first this is ignored - which does not matter, because archive
    // dispatch does not depend on any store being loaded.
    EngineConfig MinimalConfig() {
        EngineConfig cfg{};
        cfg.signatureDbPath.clear();
        cfg.enableHeuristics = false;
        cfg.enableMachineLearning = false;
        cfg.enableBehaviorAnalysis = false;
        cfg.enableCloudLookup = false;
        return cfg;
    }

    // CRC-32 (reflected, polynomial 0xEDB88320) with the table GENERATED rather
    // than transcribed. A mistyped table constant would produce a zip whose
    // entry the extractor rejects, and this suite would then report a dispatch
    // failure for a reason that has nothing to do with dispatch.
    std::uint32_t Crc32(const std::vector<std::uint8_t>& data) {
        std::array<std::uint32_t, 256> table{};
        for (std::uint32_t i = 0; i < 256; ++i) {
            std::uint32_t c = i;
            for (int k = 0; k < 8; ++k) {
                c = (c & 1u) ? (0xEDB88320u ^ (c >> 1)) : (c >> 1);
            }
            table[i] = c;
        }
        std::uint32_t crc = 0xFFFFFFFFu;
        for (const auto b : data) {
            crc = table[(crc ^ b) & 0xFFu] ^ (crc >> 8);
        }
        return crc ^ 0xFFFFFFFFu;
    }

    void PutU16(std::vector<std::uint8_t>& out, std::uint16_t v) {
        out.push_back(static_cast<std::uint8_t>(v & 0xFFu));
        out.push_back(static_cast<std::uint8_t>((v >> 8) & 0xFFu));
    }

    void PutU32(std::vector<std::uint8_t>& out, std::uint32_t v) {
        out.push_back(static_cast<std::uint8_t>(v & 0xFFu));
        out.push_back(static_cast<std::uint8_t>((v >> 8) & 0xFFu));
        out.push_back(static_cast<std::uint8_t>((v >> 16) & 0xFFu));
        out.push_back(static_cast<std::uint8_t>((v >> 24) & 0xFFu));
    }

    // A single-entry ZIP using STORED (method 0). Stored is used deliberately so
    // the test needs no deflate implementation of its own and the archive's
    // bytes are fully determined by this function.
    std::vector<std::uint8_t> BuildStoredZip(const std::string& entryName,
                                             const std::string& contentText) {
        const std::vector<std::uint8_t> content(contentText.begin(), contentText.end());
        const std::uint32_t crc = Crc32(content);
        const auto size = static_cast<std::uint32_t>(content.size());
        const auto nameLen = static_cast<std::uint16_t>(entryName.size());

        std::vector<std::uint8_t> zip;

        // ---- local file header ----
        PutU32(zip, 0x04034B50u);
        PutU16(zip, 20);    // version needed
        PutU16(zip, 0);     // flags
        PutU16(zip, 0);     // method: stored
        PutU16(zip, 0);     // mod time
        PutU16(zip, 0);     // mod date
        PutU32(zip, crc);
        PutU32(zip, size);  // compressed
        PutU32(zip, size);  // uncompressed
        PutU16(zip, nameLen);
        PutU16(zip, 0);     // extra length
        zip.insert(zip.end(), entryName.begin(), entryName.end());
        zip.insert(zip.end(), content.begin(), content.end());

        const auto centralOffset = static_cast<std::uint32_t>(zip.size());

        // ---- central directory ----
        PutU32(zip, 0x02014B50u);
        PutU16(zip, 20);    // version made by
        PutU16(zip, 20);    // version needed
        PutU16(zip, 0);     // flags
        PutU16(zip, 0);     // method
        PutU16(zip, 0);     // mod time
        PutU16(zip, 0);     // mod date
        PutU32(zip, crc);
        PutU32(zip, size);
        PutU32(zip, size);
        PutU16(zip, nameLen);
        PutU16(zip, 0);     // extra
        PutU16(zip, 0);     // comment
        PutU16(zip, 0);     // disk number start
        PutU16(zip, 0);     // internal attributes
        PutU32(zip, 0);     // external attributes
        PutU32(zip, 0);     // offset of local header
        zip.insert(zip.end(), entryName.begin(), entryName.end());

        const auto centralSize =
            static_cast<std::uint32_t>(zip.size()) - centralOffset;

        // ---- end of central directory ----
        PutU32(zip, 0x06054B50u);
        PutU16(zip, 0);     // this disk
        PutU16(zip, 0);     // disk with central directory
        PutU16(zip, 1);     // entries on this disk
        PutU16(zip, 1);     // total entries
        PutU32(zip, centralSize);
        PutU32(zip, centralOffset);
        PutU16(zip, 0);     // comment length

        return zip;
    }

    // Writes the archive into the suite's own temp directory and removes it on
    // destruction, so a failing test cannot leave an artefact behind that a
    // later run would scan.
    //
    // 🔴 EVERY TEST MUST PASS A DISTINCT tag. ScanContext::useCache defaults to
    // true, so a second scan of the same path and bytes is answered from the
    // result cache and never reaches stage 4.7 at all. When all four tests
    // shared one path and one payload, the two GATE tests passed by never
    // dispatching rather than by being gated - the mutation proof caught it:
    // removing the RealTime exclusion and removing the scanArchives gate both
    // produced ZERO failures. A test that cannot fail is worse than no test.
    class TempZip {
    public:
        TempZip(const std::string& tag,
                const std::string& entryName,
                const std::string& content) {
            std::error_code ec;
            m_dir = std::filesystem::temp_directory_path(ec) /
                    L"phantom-archive-dispatch";
            std::filesystem::create_directories(m_dir, ec);
            m_path = m_dir / (L"probe-" + std::wstring(tag.begin(), tag.end()) +
                              L".zip");

            // The payload carries the tag too, so the two archives differ by
            // CONTENT as well as by path - the cache cannot be keyed on either
            // in a way that makes one test answer for another.
            const auto bytes =
                BuildStoredZip(entryName, content + " [" + tag + "]");
            std::ofstream f(m_path, std::ios::binary | std::ios::trunc);
            f.write(reinterpret_cast<const char*>(bytes.data()),
                    static_cast<std::streamsize>(bytes.size()));
            f.close();
            m_written = bytes.size();
        }

        ~TempZip() {
            std::error_code ec;
            std::filesystem::remove(m_path, ec);
        }

        TempZip(const TempZip&) = delete;
        TempZip& operator=(const TempZip&) = delete;

        [[nodiscard]] std::wstring Path() const { return m_path.wstring(); }
        [[nodiscard]] std::size_t Written() const { return m_written; }

    private:
        std::filesystem::path m_dir;
        std::filesystem::path m_path;
        std::size_t m_written{ 0 };
    };

    struct ArchiveCounters {
        std::uint64_t archives{ 0 };
        std::uint64_t entries{ 0 };
    };

    ArchiveCounters ReadCounters() {
        const auto stats = ScanEngine::Instance().GetStatistics();
        return ArchiveCounters{ stats.archivesScanned, stats.archiveFilesScanned };
    }

} // namespace

// ---------------------------------------------------------------------------
// POSITIVE CONTROL. Not a discriminator - it passes before and after the fix.
// Its job is to make the other three interpretable: without it, "the archive
// was not dispatched" and "the archive this suite built is malformed" produce
// the same failure, and the second would send the reader after a defect that
// does not exist.
// ---------------------------------------------------------------------------
TEST(ArchiveDispatchTest, TheProbeArchiveIsRecognisedAsAnArchive) {
    // Initialize FIRST. FileTypeAnalyzer answers from a default-constructed
    // (Unknown) classification until the engine has brought it up, so without
    // this the control fails for a reason that has nothing to do with the
    // archive - which is exactly what happened on the first run of this suite.
    auto& engine = ScanEngine::Instance();
    ASSERT_TRUE(engine.Initialize(MinimalConfig()))
        << "precondition: the engine must initialize before the type analyzer "
           "can classify anything";

    const TempZip zip("control", "harmless.txt",
                      "phantom archive dispatch probe payload");

    ASSERT_GT(zip.Written(), 0u) << "the probe archive was not written";
    ASSERT_TRUE(std::filesystem::exists(zip.Path()));

    auto& analyzer = ShadowStrike::Core::FileSystem::FileTypeAnalyzer::Instance();

    // The CATEGORY is what stage 4.7 keys on, so that is what is asserted here.
    const auto info = analyzer.Analyze(zip.Path());
    EXPECT_EQ(info.category, ShadowStrike::Core::FileSystem::FileCategory::Archive)
        << "the hand-built ZIP is not classified as FileCategory::Archive, which "
           "is the exact predicate stage 4.7 dispatches on, so every dispatch "
           "assertion in this suite would be meaningless";

    // 🔴 DELIBERATELY NOT ASSERTED HERE: FileTypeAnalyzer::IsArchive().
    //
    // MEASURED on this exact file: Analyze().category answers Archive while
    // IsArchive() answers FALSE. They are documented as the same question and
    // both end in MagicDB::GetCategoryForFormat, but they reach it by different
    // routes - Analyze uses the format it resolved into FileTypeInfo::format
    // (FileTypeAnalyzer.cpp:2034), whereas IsArchive goes through
    // GetCategory (:1554), which re-derives the format with DetectFormat().
    // The same divergence necessarily affects IsScript() and IsDocument(),
    // which are built on GetCategory in the same way.
    //
    // That is a genuine defect and it is FILED SEPARATELY rather than fixed
    // here: it lives in a different module, GetCategory has other consumers
    // (FileSystemChain_Integration_Tests.cpp:527 and FileTypeAnalyzer_Tests.cpp
    // :224 both call IsArchive and pass, so it works for their input), and it
    // needs DetectFormat measured on its own terms. Asserting the broken half
    // here would make this suite red for a defect it is not fixing, and
    // asserting the WORKING half only is what keeps it honest - stage 4.7 uses
    // Analyze(), so Analyze() is what this control has to prove.
}

// ---------------------------------------------------------------------------
// THE DISCRIMINATOR. Fails against the pre-fix tree, where ScanFile had no
// Archive branch and both counters stayed at their previous values.
// ---------------------------------------------------------------------------
TEST(ArchiveDispatchTest, AnOnDemandScanExtractsAndExaminesArchiveContents) {
    auto& engine = ScanEngine::Instance();
    ASSERT_TRUE(engine.Initialize(MinimalConfig()))
        << "precondition: the engine must initialize";

    const TempZip zip("ondemand", "harmless.txt",
                      "phantom archive dispatch probe payload");
    ASSERT_TRUE(std::filesystem::exists(zip.Path()));

    const auto before = ReadCounters();

    ScanContext context{};
    context.type = ScanType::OnDemand;   // what CustomScan and FullSystemScan use
    (void)engine.ScanFile(zip.Path(), context);

    const auto after = ReadCounters();

    EXPECT_GT(after.archives, before.archives)
        << "an on-demand scan of a ZIP did not enter ScanEngine::ScanArchive, so "
           "the archive was signature-scanned as a container and its contents "
           "were never examined - the 1.0.109 EICAR-in-a-zip miss";

    EXPECT_GT(after.entries, before.entries)
        << "ScanArchive was entered but no entry reached the per-entry scan "
           "callback, so nothing inside the archive was actually examined";
}

// ---------------------------------------------------------------------------
// THE SAFETY GATE, and it matters as much as the dispatch itself. The on-access
// path builds a ScanContext and sets only .type = RealTime, inheriting
// scanArchives = true, and it runs while the minifilter holds IRP_MJ_CREATE
// pending. Extracting up to maxExtractedSize there is the mechanism that wedged
// a machine for 180 seconds in 1.0.86 and 1.0.91.
// ---------------------------------------------------------------------------
TEST(ArchiveDispatchTest, AnOnAccessScanDoesNotExtractArchiveContents) {
    auto& engine = ScanEngine::Instance();
    ASSERT_TRUE(engine.Initialize(MinimalConfig()));

    const TempZip zip("onaccess", "harmless.txt",
                      "phantom archive dispatch probe payload");
    ASSERT_TRUE(std::filesystem::exists(zip.Path()));

    const auto before = ReadCounters();

    ScanContext context{};
    context.type = ScanType::RealTime;
    // scanArchives is left at its struct default of true ON PURPOSE: that is
    // exactly what RealTimeProtection passes, so this test fails if the gate
    // ever relies on the caller remembering to clear it.
    ASSERT_TRUE(context.scanArchives)
        << "precondition: this test is only meaningful while the default is true";

    (void)engine.ScanFile(zip.Path(), context);

    const auto after = ReadCounters();

    EXPECT_EQ(after.archives, before.archives)
        << "the on-access path extracted an archive while the kernel was waiting "
           "on the verdict; that is the 180-second freeze mechanism, and archive "
           "contents are reached anyway when an extraction produces creates";

    EXPECT_EQ(after.entries, before.entries)
        << "archive entries were extracted on the kernel-blocking path";
}

// ---------------------------------------------------------------------------
// The per-request control must be honoured. QuickScanFile clears scanArchives
// for its one-second budget, so this is the assertion that keeps that promise.
// ---------------------------------------------------------------------------
TEST(ArchiveDispatchTest, ClearingScanArchivesSuppressesExtraction) {
    auto& engine = ScanEngine::Instance();
    ASSERT_TRUE(engine.Initialize(MinimalConfig()));

    const TempZip zip("flagoff", "harmless.txt",
                      "phantom archive dispatch probe payload");
    ASSERT_TRUE(std::filesystem::exists(zip.Path()));

    const auto before = ReadCounters();

    ScanContext context{};
    context.type = ScanType::OnDemand;
    context.scanArchives = false;
    (void)engine.ScanFile(zip.Path(), context);

    const auto after = ReadCounters();

    EXPECT_EQ(after.archives, before.archives)
        << "scanArchives = false did not suppress extraction, so QuickScanFile's "
           "one-second budget can be spent extracting a nested archive";
}
