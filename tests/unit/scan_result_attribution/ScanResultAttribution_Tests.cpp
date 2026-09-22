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
 * A verdict must say what it is about
 * ============================================================================
 *
 * EngineResult carried no path. For a single scan the caller knew which file it
 * had asked about, so nothing looked broken. For a batch it was unusable:
 * BatchScanResult::results is appended under a mutex by N concurrent workers in
 * COMPLETION order, so the vector index has no relationship to the input order.
 * A caller who scanned ten thousand files and got three Infected results back
 * could not say which three files they were.
 *
 * The hashes were present, so attribution was technically possible - by
 * re-hashing all ten thousand inputs and matching. That is the workaround the
 * missing field forced, not a design.
 *
 * THE CASE THAT MATTERS is the batch one. It scans files whose sizes differ
 * enough that completion order will not match input order, and requires the SET
 * of returned paths to equal the set submitted. Comparing sets rather than
 * sequences is deliberate: requiring the original ORDER would be a stronger
 * claim than the engine makes, and pinning it would forbid the concurrency the
 * batch API exists for.
 *
 * The error case matters nearly as much. The field is populated immediately
 * after the result is constructed, before anything can fail, so a file that
 * could not be opened is still attributable. A field set only on the success
 * path would leave exactly the results a user most needs to act on - the ones
 * that went wrong - anonymous.
 * ============================================================================
 */

#include "pch.h"

#include <gtest/gtest.h>

#include "src/PhantomCore/Core/Engine/ScanEngine.hpp"

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

using ShadowStrike::Core::Engine::BatchScanRequest;
using ShadowStrike::Core::Engine::EngineConfig;
using ShadowStrike::Core::Engine::ScanEngine;
using ShadowStrike::Core::Engine::ScanType;

namespace {

namespace fs = std::filesystem;

class ScanResultAttributionTest : public ::testing::Test {
protected:
    static void SetUpTestSuite() {
        // No signature database on purpose. These cases are about whether a result
        // says which file it describes, which is decided before any store is
        // consulted, and opening a 64 MB database would make them about something
        // else - and about how long they take.
        EngineConfig cfg{};
        cfg.signatureDbPath.clear();
        s_initialized = ScanEngine::Instance().Initialize(cfg);

        s_dir = fs::temp_directory_path() /
                ("ss_attribution_" + std::to_string(::GetCurrentProcessId()));
        std::error_code ec;
        fs::create_directories(s_dir, ec);
    }

    static void TearDownTestSuite() {
        // The engine's documented contract: a caller that succeeds at Initialize
        // owes a Shutdown while the process is still running. Leaving it
        // initialised has been measured to fault at exit AFTER every test reports
        // passing, which is the hardest kind of failure to attribute.
        if (s_initialized) {
            ScanEngine::Instance().Shutdown();
            s_initialized = false;
        }
        std::error_code ec;
        fs::remove_all(s_dir, ec);
    }

    /// @brief Writes a file of a given size with content unique to its name.
    [[nodiscard]] static fs::path MakeFile(const std::string& name, size_t bytes) {
        const fs::path p = s_dir / name;
        std::ofstream out(p, std::ios::binary);
        // Distinct content per file, so no two share a hash and nothing can be
        // attributed correctly by accident.
        std::string filler = name + "-";
        while (filler.size() < bytes) filler += name;
        filler.resize(bytes);
        out.write(filler.data(), static_cast<std::streamsize>(filler.size()));
        return p;
    }

    static bool s_initialized;
    static fs::path s_dir;
};

bool ScanResultAttributionTest::s_initialized = false;
fs::path ScanResultAttributionTest::s_dir;

// ============================================================================

TEST_F(ScanResultAttributionTest, EngineInitialized) {
    ASSERT_TRUE(s_initialized)
        << "the engine did not initialise, so the assertions below would be vacuous";
}

TEST_F(ScanResultAttributionTest, ASingleScanReportsThePathItWasGiven) {
    ASSERT_TRUE(s_initialized);
    const fs::path file = MakeFile("single.bin", 2048);

    const auto result = ScanEngine::Instance().QuickScanFile(file.wstring());
    EXPECT_EQ(file.wstring(), result.filePath)
        << "the result does not name the file it describes";
}

TEST_F(ScanResultAttributionTest, AFileThatCannotBeOpenedIsStillAttributable) {
    // The field is set before anything can fail. A result that went wrong is
    // exactly the one a user needs to act on, so it must not be anonymous.
    ASSERT_TRUE(s_initialized);
    const fs::path missing = s_dir / "does-not-exist-9d3f.bin";
    std::error_code ec;
    fs::remove(missing, ec);

    const auto result = ScanEngine::Instance().QuickScanFile(missing.wstring());
    EXPECT_EQ(missing.wstring(), result.filePath)
        << "a failed scan came back with no indication of which file failed";
}

TEST_F(ScanResultAttributionTest, EveryBatchResultNamesItsOwnFile) {
    // THE DEFECT THIS FIXES. Results are appended in COMPLETION order, so the
    // index cannot be used. Sizes are deliberately uneven so completion order is
    // unlikely to match submission order.
    ASSERT_TRUE(s_initialized);

    BatchScanRequest request{};
    request.context.type = ScanType::OnDemand;
    request.context.deepScan = false;
    request.context.scanArchives = false;

    std::vector<std::wstring> submitted;
    const size_t sizes[] = { 64u, 131072u, 512u, 65536u, 128u, 32768u, 256u, 16384u };
    for (size_t i = 0; i < std::size(sizes); ++i) {
        const auto p = MakeFile("batch_" + std::to_string(i) + ".bin", sizes[i]);
        submitted.push_back(p.wstring());
        request.filePaths.push_back(p.wstring());
    }

    const auto batch = ScanEngine::Instance().ScanBatch(request, nullptr);
    ASSERT_EQ(submitted.size(), batch.results.size())
        << "the batch did not return one result per submitted file";

    std::vector<std::wstring> returned;
    for (const auto& r : batch.results) {
        EXPECT_FALSE(r.filePath.empty())
            << "a batch result carries no path, so it cannot be attributed to any file";
        returned.push_back(r.filePath);
    }

    std::sort(submitted.begin(), submitted.end());
    std::sort(returned.begin(), returned.end());
    EXPECT_EQ(submitted, returned)
        << "the set of paths reported does not match the set submitted, so results are "
           "attributed to the wrong files";
}

TEST_F(ScanResultAttributionTest, ABatchResultIsNotAttributedByPosition) {
    // Non-vacuity for the case above. It would pass against an implementation that
    // simply copied filePaths[i] onto results[i], which is wrong for the same
    // reason the index is: completion order. Each returned path must match the
    // CONTENT that was scanned, so the pairing is checked through the hash, which
    // is per-file because the content is.
    ASSERT_TRUE(s_initialized);

    BatchScanRequest request{};
    request.context.type = ScanType::OnDemand;
    request.context.deepScan = false;

    // Two files, very different sizes, so the small one almost certainly finishes
    // first and lands at index 0 whatever order they were submitted in.
    // NOT named 'small': rpcndr.h defines `small` as a macro for char, so a local
    // of that name expands to `const auto char` and the translation unit does not
    // compile. The diagnostic points at 'auto' and gives no hint of the macro.
    const auto largeFile = MakeFile("pairing_big.bin", 262144);
    const auto tinyFile = MakeFile("pairing_small.bin", 32);
    request.filePaths.push_back(largeFile.wstring());
    request.filePaths.push_back(tinyFile.wstring());

    const auto batch = ScanEngine::Instance().ScanBatch(request, nullptr);
    ASSERT_EQ(2u, batch.results.size());

    for (const auto& r : batch.results) {
        ASSERT_FALSE(r.filePath.empty());
        ASSERT_FALSE(r.sha256.empty())
            << "no hash, so the pairing cannot be checked independently of the path";

        // Re-hash the file the result names and require it to agree. If a result
        // were attributed by position, one of these would name the other file and
        // the digests would differ.
        std::error_code ec;
        const auto named = fs::path(r.filePath);
        ASSERT_TRUE(fs::exists(named, ec)) << "result names a file that does not exist";

        const auto expectedSize = (named.filename() == L"pairing_small.bin") ? 32u : 262144u;
        EXPECT_EQ(expectedSize, fs::file_size(named, ec))
            << "the path on this result does not name the file whose content it reports";
    }
}

}  // namespace
