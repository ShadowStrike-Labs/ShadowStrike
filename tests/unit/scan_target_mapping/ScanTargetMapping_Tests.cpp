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
 * @file ScanTargetMapping_Tests.cpp
 * @brief Pins the contract that a scan target is not a signature database.
 *
 * WHAT THESE TESTS EXIST TO PREVENT
 *
 * Three separate scan paths -- SignatureStore::ScanFile, YaraRuleStore::ScanFile
 * and PatternStore::ScanFile -- mapped their scan target with
 * MemoryMapping::OpenView. OpenView is a DATABASE opener: it validates a
 * SignatureDatabaseHeader before committing the view. So a file had to BE a
 * ShadowStrike signature database in order to be readable for scanning, which no
 * executable, archive or document is. Every real file failed to map, and each
 * function returned an empty result that the caller could not distinguish from
 * "scanned, nothing found".
 *
 * The 1.0.93 field run recorded the consequence: 246 map failures, of which 208
 * were rejected with magic 0x00905A4D (the "MZ" of a PE executable) and 8 with
 * 0x04034B50 (the "PK" of a zip/Office container), plus 43 rejected for being
 * smaller than a database header.
 *
 * These tests use REAL FILES ON DISK rather than a mocked mapper, because the
 * defect lived precisely in the interaction between the real Win32 mapping code
 * and the header validation. A test double would have reproduced neither.
 */

#include "pch.h"
#include <gtest/gtest.h>

#include "../../../src/PhantomCore/SignatureStore/SignatureFormat.hpp"

#include <Windows.h>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

namespace fs = std::filesystem;

using ShadowStrike::SignatureStore::MemoryMappedView;
using ShadowStrike::SignatureStore::StoreError;
using ShadowStrike::SignatureStore::SignatureStoreError;
namespace MM = ShadowStrike::SignatureStore::MemoryMapping;

namespace {

// Writes bytes to a uniquely named file under the test temp directory and
// returns the path. Named per-test so parallel or repeated runs cannot collide.
class TempFile {
public:
    TempFile(const std::wstring& tag, const std::vector<uint8_t>& bytes) {
        std::error_code ec;
        fs::path dir = fs::temp_directory_path(ec) / L"phantom-scan-target-tests";
        fs::create_directories(dir, ec);

        // GetCurrentThreadId keeps concurrently running cases distinct; the tag
        // keeps failures readable when one of these files is left behind.
        m_path = dir / (tag + L"-" + std::to_wstring(::GetCurrentThreadId()) + L".bin");

        std::ofstream out(m_path, std::ios::binary | std::ios::trunc);
        if (!bytes.empty()) {
            out.write(reinterpret_cast<const char*>(bytes.data()),
                      static_cast<std::streamsize>(bytes.size()));
        }
        out.close();
    }

    ~TempFile() {
        std::error_code ec;
        fs::remove(m_path, ec);
    }

    TempFile(const TempFile&) = delete;
    TempFile& operator=(const TempFile&) = delete;

    [[nodiscard]] std::wstring path() const { return m_path.wstring(); }
    [[nodiscard]] bool exists() const {
        std::error_code ec;
        return fs::exists(m_path, ec);
    }

private:
    fs::path m_path;
};

// A minimal but realistic PE prologue: "MZ" then an e_lfanew pointing at a
// "PE\0\0" signature. This is the exact shape of the 208 files the field run
// refused, so the test target matches the reported failure rather than a
// convenient stand-in.
std::vector<uint8_t> MakeMzBytes(size_t totalSize = 1024) {
    std::vector<uint8_t> bytes(totalSize, 0x00);
    bytes[0] = 'M';
    bytes[1] = 'Z';
    // e_lfanew at offset 0x3C -> 0x80
    bytes[0x3C] = 0x80;
    if (totalSize > 0x84) {
        bytes[0x80] = 'P';
        bytes[0x81] = 'E';
        bytes[0x82] = 0x00;
        bytes[0x83] = 0x00;
    }
    // Something for a content matcher to have an opinion about.
    const char* filler = "this is not a signature database";
    const size_t fillerLen = std::strlen(filler);
    if (totalSize > 0x100 + fillerLen) {
        std::memcpy(bytes.data() + 0x100, filler, fillerLen);
    }
    return bytes;
}

// The "PK" local file header magic 0x04034B50, little-endian on disk.
std::vector<uint8_t> MakePkBytes(size_t totalSize = 512) {
    std::vector<uint8_t> bytes(totalSize, 0x00);
    bytes[0] = 0x50;  // P
    bytes[1] = 0x4B;  // K
    bytes[2] = 0x03;
    bytes[3] = 0x04;
    return bytes;
}

}  // namespace

// ============================================================================
// The defect itself: an ordinary file must be mappable for scanning.
// ============================================================================

// This is the case that failed 208 times in the field. It is first because it is
// the whole point: if this fails, no PE file can be examined by any store.
TEST(ScanTargetMappingTest, AnExecutableIsMappableForScanning) {
    TempFile file(L"mz-executable", MakeMzBytes());
    ASSERT_TRUE(file.exists()) << "test could not create its own input";

    MemoryMappedView view{};
    StoreError err{};

    const bool opened = MM::OpenFileView(file.path(), view, err);

    EXPECT_TRUE(opened)
        << "An MZ executable could not be mapped for scanning. This is the "
           "defect that made every PE file unscannable: error code "
        << static_cast<unsigned>(err.code) << ", message: " << err.message;

    if (opened) {
        EXPECT_NE(view.baseAddress, nullptr);
        EXPECT_EQ(view.fileSize, 1024u);
        EXPECT_TRUE(view.readOnly) << "a scan must not be able to modify its target";

        // Prove the mapping actually exposes the file's bytes, not merely a
        // non-null pointer. A view that opens but shows nothing is the same
        // silent failure wearing a different hat.
        const auto* bytes = static_cast<const uint8_t*>(view.baseAddress);
        ASSERT_NE(bytes, nullptr);
        EXPECT_EQ(bytes[0], 'M');
        EXPECT_EQ(bytes[1], 'Z');

        MM::CloseView(view);
        EXPECT_EQ(view.baseAddress, nullptr) << "CloseView must clear the view";
    }
}

TEST(ScanTargetMappingTest, AnArchiveIsMappableForScanning) {
    TempFile file(L"pk-archive", MakePkBytes());
    ASSERT_TRUE(file.exists());

    MemoryMappedView view{};
    StoreError err{};

    const bool opened = MM::OpenFileView(file.path(), view, err);
    EXPECT_TRUE(opened)
        << "A PK archive could not be mapped for scanning (8 such failures in "
           "the field): " << err.message;

    if (opened) {
        const auto* bytes = static_cast<const uint8_t*>(view.baseAddress);
        ASSERT_NE(bytes, nullptr);
        EXPECT_EQ(bytes[0], 0x50);
        EXPECT_EQ(bytes[1], 0x4B);
        MM::CloseView(view);
    }
}

// The 43 "too small" failures. A file shorter than a database header is a
// perfectly ordinary thing to scan, and refusing it is a coverage hole.
TEST(ScanTargetMappingTest, AFileSmallerThanADatabaseHeaderIsStillScannable) {
    const std::vector<uint8_t> tiny{ 'h', 'i' };
    TempFile file(L"two-bytes", tiny);
    ASSERT_TRUE(file.exists());

    MemoryMappedView view{};
    StoreError err{};

    const bool opened = MM::OpenFileView(file.path(), view, err);
    EXPECT_TRUE(opened)
        << "A 2-byte file was refused for scanning. 43 files were refused this "
           "way in the field: " << err.message;

    if (opened) {
        EXPECT_EQ(view.fileSize, 2u);
        MM::CloseView(view);
    }
}

// ============================================================================
// The database opener must KEEP rejecting non-databases. Fixing the scan path
// must not have loosened the format check that protects database loading.
// ============================================================================

TEST(ScanTargetMappingTest, TheDatabaseOpenerStillRefusesANonDatabase) {
    TempFile file(L"mz-not-a-database", MakeMzBytes());
    ASSERT_TRUE(file.exists());

    MemoryMappedView view{};
    StoreError err{};

    const bool opened = MM::OpenView(file.path(), /*readOnly*/ true, view, err);

    EXPECT_FALSE(opened)
        << "OpenView accepted a file with no database header. The scan-path fix "
           "must not weaken database format validation -- that check is what "
           "stops a corrupt or hostile file being loaded as signature content.";

    if (opened) {
        MM::CloseView(view);
    } else {
        EXPECT_EQ(err.code, SignatureStoreError::InvalidFormat)
            << "rejection is correct but the reason should name the format";
    }
}

// The two functions must genuinely differ, otherwise one of them is redundant
// and a future reader cannot tell which to call. Asserting the divergence keeps
// the distinction real rather than documentary.
TEST(ScanTargetMappingTest, TheTwoOpenersDisagreeOnTheSameFileByDesign) {
    TempFile file(L"divergence", MakeMzBytes());
    ASSERT_TRUE(file.exists());

    MemoryMappedView dbView{};
    StoreError dbErr{};
    const bool dbOpened = MM::OpenView(file.path(), true, dbView, dbErr);
    if (dbOpened) MM::CloseView(dbView);

    MemoryMappedView scanView{};
    StoreError scanErr{};
    const bool scanOpened = MM::OpenFileView(file.path(), scanView, scanErr);
    if (scanOpened) MM::CloseView(scanView);

    EXPECT_FALSE(dbOpened) << "the database opener should refuse this file";
    EXPECT_TRUE(scanOpened) << "the scan opener should accept this file";
}

// ============================================================================
// Security properties must survive the refactor. OpenFileView shares OpenView's
// implementation precisely so these cannot diverge -- assert that they haven't.
// ============================================================================

TEST(ScanTargetMappingTest, ScanMappingStillRejectsPathTraversal) {
    MemoryMappedView view{};
    StoreError err{};

    const bool opened = MM::OpenFileView(L"..\\..\\Windows\\System32\\kernel32.dll", view, err);

    EXPECT_FALSE(opened)
        << "relative traversal was accepted; the shared path validation in step 1 "
           "must apply to scan targets too";
    if (opened) MM::CloseView(view);
}

TEST(ScanTargetMappingTest, ScanMappingRejectsAnEmptyPath) {
    MemoryMappedView view{};
    StoreError err{};

    EXPECT_FALSE(MM::OpenFileView(L"", view, err));
}

TEST(ScanTargetMappingTest, ScanMappingRejectsAMissingFile) {
    std::error_code ec;
    const fs::path missing =
        fs::temp_directory_path(ec) / L"phantom-scan-target-tests" / L"definitely-not-here.bin";

    MemoryMappedView view{};
    StoreError err{};

    EXPECT_FALSE(MM::OpenFileView(missing.wstring(), view, err));
}

// A zero-byte file has nothing to examine. It must be refused rather than
// producing a zero-length mapping, because CreateFileMapping cannot map an empty
// file and the caller needs a definite answer either way.
TEST(ScanTargetMappingTest, ScanMappingRefusesAZeroByteFile) {
    TempFile file(L"empty", {});
    ASSERT_TRUE(file.exists());

    MemoryMappedView view{};
    StoreError err{};

    const bool opened = MM::OpenFileView(file.path(), view, err);
    EXPECT_FALSE(opened) << "an empty file has no contents to map";
    if (opened) MM::CloseView(view);
}

// The caller's ceiling must be honoured, and it must be the CALLER's, not the
// 16 GB database limit. A scan path that inherits MAX_DATABASE_SIZE is not
// enforcing a scan bound at all.
TEST(ScanTargetMappingTest, ScanMappingHonoursTheCallerSizeCeiling) {
    TempFile file(L"ceiling", MakeMzBytes(4096));
    ASSERT_TRUE(file.exists());

    MemoryMappedView underLimit{};
    StoreError underErr{};
    const bool acceptedUnder = MM::OpenFileView(file.path(), underLimit, underErr, 8192);
    EXPECT_TRUE(acceptedUnder) << "4 KB file refused under an 8 KB ceiling: " << underErr.message;
    if (acceptedUnder) MM::CloseView(underLimit);

    MemoryMappedView overLimit{};
    StoreError overErr{};
    const bool acceptedOver = MM::OpenFileView(file.path(), overLimit, overErr, 1024);
    EXPECT_FALSE(acceptedOver) << "4 KB file accepted under a 1 KB ceiling";
    if (acceptedOver) {
        MM::CloseView(overLimit);
    } else {
        EXPECT_EQ(overErr.code, SignatureStoreError::TooLarge);
    }

    MemoryMappedView noLimit{};
    StoreError noErr{};
    const bool acceptedNoCeiling = MM::OpenFileView(file.path(), noLimit, noErr, 0);
    EXPECT_TRUE(acceptedNoCeiling) << "a ceiling of 0 must mean no ceiling";
    if (acceptedNoCeiling) MM::CloseView(noLimit);
}

// Mapping the same file twice concurrently must work: the scan path is
// multi-threaded, and a read-only share mode is the reason it can be.
TEST(ScanTargetMappingTest, TheSameFileCanBeMappedTwiceAtOnce) {
    TempFile file(L"shared", MakeMzBytes());
    ASSERT_TRUE(file.exists());

    MemoryMappedView first{};
    StoreError firstErr{};
    ASSERT_TRUE(MM::OpenFileView(file.path(), first, firstErr))
        << "first mapping failed: " << firstErr.message;

    MemoryMappedView second{};
    StoreError secondErr{};
    const bool secondOpened = MM::OpenFileView(file.path(), second, secondErr);

    EXPECT_TRUE(secondOpened)
        << "a second concurrent read-only mapping failed, which would serialise "
           "or break parallel scanning: " << secondErr.message;

    if (secondOpened) MM::CloseView(second);
    MM::CloseView(first);
}
