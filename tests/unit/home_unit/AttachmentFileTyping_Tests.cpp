// SPDX-License-Identifier: AGPL-3.0-or-later
/*
 * ShadowStrike Phantom - Attachment file typing tests
 * Copyright (C) 2026 ShadowStrike-Labs
 *
 * This program is free software: you can redistribute it and/or modify it under
 * the terms of the GNU Affero General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option) any
 * later version.
 */

/**
 * @file AttachmentFileTyping_Tests.cpp
 * @brief Pins magic-byte typing, and that a container's envelope is not a mismatch.
 *
 * ClassifyByMagic compared all eight bytes of a fixed-width array rather than the signatureLen the struct
 * carries, so matching MZ required a file to begin 4D 5A 00 00 00 00 00 00 - which no real PE does. Only the
 * eight-byte OLE signature could ever match, so attachment typing was extension-only and
 * extension-versus-content verification never fired.
 *
 * These cases run against the PUBLIC DetectFileType(buffer, fileName) overload, so they exercise the real
 * decision path rather than a helper. The bytes are real file prefixes, written out so that a signature
 * whose length is wrong is visible here rather than inferred.
 *
 * The container cases are as important as the signature cases. A .docx IS a ZIP and a .msi IS an OLE compound
 * document, and macro scanning keys on Document, Spreadsheet and Presentation - so typing a .docx as Archive
 * would silently stop macro scanning on every modern Office attachment. That is why a consistent container
 * pairing resolves to the extension.
 */

#include "pch.h"

#include <gtest/gtest.h>

#include <cstdint>
#include <string>
#include <vector>

#include "Products/Community/PhantomHome/Email/AttachmentScanner.hpp"

namespace {

using ShadowStrike::Email::AttachmentScanner;
using ShadowStrike::Email::FileTypeCategory;

// Real prefixes. A PE does not continue with zeros after MZ, and that is the whole point.
const std::vector<uint8_t> kPe{0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00, 0x04, 0x00};
const std::vector<uint8_t> kElf{0x7F, 0x45, 0x4C, 0x46, 0x02, 0x01, 0x01, 0x00};
const std::vector<uint8_t> kZip{0x50, 0x4B, 0x03, 0x04, 0x14, 0x00, 0x00, 0x00, 0x08, 0x00};
const std::vector<uint8_t> kZipEmpty{0x50, 0x4B, 0x05, 0x06, 0x00, 0x00, 0x00, 0x00};
const std::vector<uint8_t> kRar{0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x00};
const std::vector<uint8_t> kSevenZip{0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C, 0x00, 0x04};
const std::vector<uint8_t> kGzip{0x1F, 0x8B, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00};
const std::vector<uint8_t> kOle{0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1, 0x00, 0x00};
const std::vector<uint8_t> kPdf{0x25, 0x50, 0x44, 0x46, 0x2D, 0x31, 0x2E, 0x37};  // %PDF-1.7
const std::vector<uint8_t> kJpeg{0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46};

class AttachmentTypingTest : public ::testing::Test {
protected:
    static AttachmentScanner& Scanner() { return AttachmentScanner::Instance(); }

    static void SetUpTestSuite() {
        // Initialize is not idempotent (filed 288), so state is tested rather than assumed.
        if (!Scanner().IsInitialized()) {
            (void)Scanner().Initialize();
        }
    }

    static FileTypeCategory TypeOf(const std::vector<uint8_t>& bytes, const std::string& name) {
        return Scanner().DetectFileType(bytes, name);
    }
};

// ============================================================================
// Signatures that could never match before
// ============================================================================

TEST_F(AttachmentTypingTest, ARealExecutableIsTypedByItsBytes) {
    // The defect in one line: matching MZ required six trailing zero bytes that no PE carries.
    EXPECT_EQ(FileTypeCategory::Executable, TypeOf(kPe, "notes.txt"));
    EXPECT_EQ(FileTypeCategory::Executable, TypeOf(kElf, "notes.txt"));
}

TEST_F(AttachmentTypingTest, ContentWinsOverAMisleadingName) {
    // What the function is for. An executable named to look harmless must type as an executable.
    EXPECT_EQ(FileTypeCategory::Executable, TypeOf(kPe, "invoice.pdf"));
    EXPECT_EQ(FileTypeCategory::Executable, TypeOf(kPe, "photo.jpg"));
    EXPECT_EQ(FileTypeCategory::PDF, TypeOf(kPdf, "report.exe"))
        << "and the reverse: a genuine PDF named .exe is a PDF";
}

TEST_F(AttachmentTypingTest, EachArchiveSignatureIsRecognisedAtItsOwnLength) {
    // Two, four and six byte signatures, each of which required trailing zeros before.
    EXPECT_EQ(FileTypeCategory::Archive, TypeOf(kZip, "data.bin"));
    EXPECT_EQ(FileTypeCategory::Archive, TypeOf(kZipEmpty, "data.bin"));
    EXPECT_EQ(FileTypeCategory::Archive, TypeOf(kRar, "data.bin"));
    EXPECT_EQ(FileTypeCategory::Archive, TypeOf(kSevenZip, "data.bin"));
    EXPECT_EQ(FileTypeCategory::Archive, TypeOf(kGzip, "data.bin"));
}

TEST_F(AttachmentTypingTest, TheEightByteOleSignatureStillWorks) {
    // The only signature that could match before the fix, so it is the regression check.
    EXPECT_EQ(FileTypeCategory::Document, TypeOf(kOle, "data.bin"));
}

TEST_F(AttachmentTypingTest, APdfIsTypedFromItsVersionedHeader) {
    // "%PDF-1.7" - byte four is a hyphen, not a zero, which is why this never matched.
    EXPECT_EQ(FileTypeCategory::PDF, TypeOf(kPdf, "data.bin"));
}

// ============================================================================
// A container's envelope is not a mismatch
// ============================================================================

TEST_F(AttachmentTypingTest, AnOoxmlDocumentTypesByItsExtensionNotItsZipEnvelope) {
    // THE CASE THAT PROTECTS MACRO SCANNING. Macro scanning runs only for Document, Spreadsheet and
    // Presentation, so typing these as Archive - which is what their bytes say - would silently stop it.
    EXPECT_EQ(FileTypeCategory::Document, TypeOf(kZip, "report.docx"));
    EXPECT_EQ(FileTypeCategory::Spreadsheet, TypeOf(kZip, "budget.xlsx"));
    EXPECT_EQ(FileTypeCategory::Presentation, TypeOf(kZip, "deck.pptx"));
    EXPECT_EQ(FileTypeCategory::Document, TypeOf(kZip, "notes.odt"));
    EXPECT_EQ(FileTypeCategory::Spreadsheet, TypeOf(kZip, "sheet.ods"));
}

TEST_F(AttachmentTypingTest, LegacyOfficeTypesByItsExtensionOverTheOleEnvelope) {
    // An OLE compound document is categorised Document, so .xls and .ppt would otherwise lose their own
    // category and, with it, macro scanning.
    EXPECT_EQ(FileTypeCategory::Spreadsheet, TypeOf(kOle, "budget.xls"));
    EXPECT_EQ(FileTypeCategory::Presentation, TypeOf(kOle, "deck.ppt"));
    EXPECT_EQ(FileTypeCategory::Document, TypeOf(kOle, "letter.doc"));
}

TEST_F(AttachmentTypingTest, AnInstallerTypesAsExecutableDespiteItsOleEnvelope) {
    EXPECT_EQ(FileTypeCategory::Executable, TypeOf(kOle, "setup.msi"));
    EXPECT_EQ(FileTypeCategory::Executable, TypeOf(kOle, "patch.msp"));
}

TEST_F(AttachmentTypingTest, AZipNamedAsAnArchiveStaysAnArchive) {
    // Non-vacuity for the container rule: it must not be reached when the two already agree.
    EXPECT_EQ(FileTypeCategory::Archive, TypeOf(kZip, "files.zip"));
    EXPECT_EQ(FileTypeCategory::Archive, TypeOf(kRar, "files.rar"));
}

TEST_F(AttachmentTypingTest, AZipRenamedToAnExecutableIsStillReportedAsWhatItIs) {
    // The container rule must not become a general excuse. An Archive paired with an Executable extension is
    // NOT a documented container relationship, so the bytes win.
    EXPECT_EQ(FileTypeCategory::Archive, TypeOf(kZip, "dropper.exe"));
    EXPECT_EQ(FileTypeCategory::Archive, TypeOf(kZip, "script.ps1"));
}

// ============================================================================
// No signature matched
// ============================================================================

TEST_F(AttachmentTypingTest, AnUnrecognisedSignatureFallsBackToTheExtension) {
    // There is no JPEG signature in the table, so an image types by name. Pinned as it behaves: if this
    // starts returning something else, a signature was added and the container rules need revisiting.
    EXPECT_EQ(FileTypeCategory::Document, TypeOf(kJpeg, "photo.doc"))
        << "no JPEG signature exists in the table, so the extension decides";

    const std::vector<uint8_t> plain{'h', 'e', 'l', 'l', 'o', ' ', 'w', 'o'};
    EXPECT_EQ(FileTypeCategory::Executable, TypeOf(plain, "tool.exe"));
}

TEST_F(AttachmentTypingTest, AShortOrEmptyHeaderDoesNotCrashOrMisclassify) {
    // A two-byte header used to disqualify every signature, because the length test compared against the
    // array width rather than the signature length - which is exactly why SelfTest failed.
    const std::vector<uint8_t> twoBytes{0x4D, 0x5A};
    EXPECT_EQ(FileTypeCategory::Executable, TypeOf(twoBytes, "notes.txt"))
        << "two bytes are enough for a two-byte signature";

    const std::vector<uint8_t> oneByte{0x4D};
    EXPECT_EQ(FileTypeCategory::Document, TypeOf(oneByte, "letter.doc"))
        << "one byte matches nothing, so the extension decides";

    const std::vector<uint8_t> empty;
    EXPECT_EQ(FileTypeCategory::Document, TypeOf(empty, "letter.doc"));
}

TEST_F(AttachmentTypingTest, AllZeroBytesAreNotTypedByTheSentinel) {
    // The table ends with a zero-length, all-zero sentinel that a range-based loop never needed. Comparing
    // zero bytes succeeds trivially, so it must be skipped rather than matched.
    const std::vector<uint8_t> zeros(16, 0x00);
    EXPECT_EQ(FileTypeCategory::Document, TypeOf(zeros, "letter.doc"))
        << "the extension decides, rather than the sentinel claiming the file";
}

// ============================================================================
// The module's own self-test
// ============================================================================

TEST_F(AttachmentTypingTest, TheModulesOwnSelfTestPasses) {
    // It never has. Test 1 builds a two-byte MZ header and requires Executable, which the old length
    // comparison made impossible - and nothing in the tree calls SelfTest, so the permanent failure went
    // unnoticed. Calling it here is the point.
    ASSERT_TRUE(Scanner().IsInitialized()) << "SelfTest reports failure when uninitialised";
    EXPECT_TRUE(Scanner().SelfTest());
}

}  // namespace
