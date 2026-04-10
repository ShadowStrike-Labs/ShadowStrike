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
 * @file FileTypeAnalyzer_Tests.cpp
 * @brief Comprehensive GTest coverage for Core::FileSystem::FileTypeAnalyzer.
 *
 * Coverage focus:
 * - configuration presets and runtime statistics
 * - PE, OOXML/ZIP, script, text, and empty-file classification
 * - spoofing detection for double extensions, RTL override, and content mismatch
 * - extension mapping and custom signature registration
 */

#include "pch.h"

#include "CoreFileSystem_TestUtils.hpp"
#include "../../../src/Shared_modules/Core/FileSystem/FileTypeAnalyzer.hpp"

#include <algorithm>

namespace {

using namespace ShadowStrike::Core::FileSystem;
using namespace ShadowStrike::Tests::CoreFileSystem;
using ::testing::Contains;
using ::testing::HasSubstr;

class FileTypeAnalyzerTest : public TempDirectoryFixture {
protected:
    void SetUp() override {
        TempDirectoryFixture::SetUp();

        auto& analyzer = FileTypeAnalyzer::Instance();
        analyzer.Shutdown();
        ASSERT_TRUE(analyzer.Initialize(FileTypeAnalyzerConfig::CreateDefault()));
        analyzer.ResetStatistics();
    }

    void TearDown() override {
        auto& analyzer = FileTypeAnalyzer::Instance();
        analyzer.Shutdown();
        TempDirectoryFixture::TearDown();
    }
};

TEST(FileTypeAnalyzerValueTests, ConfigPresetsAndStatisticsResetExposeExpectedDefaults) {
    const auto defaults = FileTypeAnalyzerConfig::CreateDefault();
    const auto full = FileTypeAnalyzerConfig::CreateFull();
    const auto minimal = FileTypeAnalyzerConfig::CreateMinimal();

    EXPECT_EQ(defaults.headerSize, FileTypeAnalyzerConstants::DEFAULT_HEADER_SIZE);
    EXPECT_EQ(full.headerSize, FileTypeAnalyzerConstants::MAX_HEADER_SIZE);
    EXPECT_FALSE(minimal.detectScripts);
    EXPECT_FALSE(minimal.detectSpoofing);
    EXPECT_FALSE(minimal.analyzeNestedTypes);

    FileTypeAnalyzerStatistics stats;
    stats.filesAnalyzed.store(9, std::memory_order_relaxed);
    stats.scriptsDetected.store(2, std::memory_order_relaxed);
    stats.Reset();
    EXPECT_EQ(stats.filesAnalyzed.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.scriptsDetected.load(std::memory_order_relaxed), 0u);
}

TEST_F(FileTypeAnalyzerTest, ExtensionFallbackHelpersAndUnsupportedSignatureLoadingStayDeterministic) {
    auto& analyzer = FileTypeAnalyzer::Instance();
    const auto unknownBinary = Bytes("\x01\x02\x03\x04");

    EXPECT_EQ(analyzer.DetectScriptType(unknownBinary), FileFormat::Unknown);

    const auto pdfByExtension = analyzer.AnalyzeBuffer(unknownBinary, L".pdf");
    EXPECT_TRUE(pdfByExtension.detected);
    EXPECT_EQ(pdfByExtension.format, FileFormat::PDF);
    EXPECT_EQ(pdfByExtension.category, FileCategory::Document);
    EXPECT_DOUBLE_EQ(pdfByExtension.confidence, 0.3);

    const auto macroDoc = WriteBytes(L"report.docx", BuildZipOfficeBuffer("word"));
    const auto plainText = WriteText(L"notes.txt", "just notes");
    EXPECT_TRUE(analyzer.CanContainMacros(macroDoc.wstring()));
    EXPECT_FALSE(analyzer.CanContainMacros(plainText.wstring()));

    EXPECT_EQ(analyzer.GetExtensionForFormat(FileFormat::PDF), ".pdf");
    EXPECT_EQ(analyzer.GetExtensionForFormat(FileFormat::Unknown), "");
    EXPECT_EQ(analyzer.GetExtensionRisk("exe"), analyzer.GetExtensionInfo("exe").riskLevel);
    EXPECT_EQ(analyzer.LoadSignatures(MakePath(L"unsupported.sig").wstring()), 0u);
}

TEST_F(FileTypeAnalyzerTest, AnalyzeRejectsEmbeddedNullBytePathsAsUnicodeAbuse) {
    auto& analyzer = FileTypeAnalyzer::Instance();

    std::wstring craftedPath = MakePath(L"normal.txt").wstring();
    craftedPath.push_back(L'\0');
    craftedPath += L".exe";

    const auto info = analyzer.Analyze(craftedPath);

    EXPECT_FALSE(info.detected);
    EXPECT_TRUE(info.isSpoofed);
    EXPECT_EQ(info.spoofingType, SpoofingType::UnicodeAbuse);
}

TEST_F(FileTypeAnalyzerTest, AnalyzeBufferClassifiesMinimalPe64Executable) {
    auto& analyzer = FileTypeAnalyzer::Instance();
    const auto buffer = BuildMinimalPe64Image();

    const auto info = analyzer.AnalyzeBuffer(buffer);

    EXPECT_TRUE(info.detected);
    EXPECT_EQ(info.format, FileFormat::PE64);
    EXPECT_EQ(info.category, FileCategory::Executable);
    EXPECT_TRUE(info.isExecutable);
    EXPECT_EQ(info.extension, ".exe");
    EXPECT_FALSE(info.isSpoofed);
}

TEST_F(FileTypeAnalyzerTest, AnalyzeBufferClassifiesZipBasedDocxFromExtensionHint) {
    auto& analyzer = FileTypeAnalyzer::Instance();
    const auto buffer = BuildZipOfficeBuffer("word");

    const auto info = analyzer.AnalyzeBuffer(buffer, L".docx");

    EXPECT_TRUE(info.detected);
    EXPECT_EQ(info.format, FileFormat::DOCX);
    EXPECT_EQ(info.category, FileCategory::Document);
    EXPECT_TRUE(info.canContainMacros);
    EXPECT_EQ(info.extension, ".docx");
    EXPECT_THAT(info.mimeType, HasSubstr("officedocument"));
}

TEST_F(FileTypeAnalyzerTest, AnalyzeScriptDetectsPythonShebangAndKeywords) {
    auto& analyzer = FileTypeAnalyzer::Instance();
    const auto script = Bytes("#!/usr/bin/env python\nimport os\n\ndef main():\n    return __name__\n");

    const auto indicators = analyzer.AnalyzeScript(script);

    EXPECT_TRUE(indicators.hasShebang);
    EXPECT_TRUE(indicators.hasScriptKeywords);
    EXPECT_THAT(indicators.shebangInterpreter, HasSubstr("python"));
    EXPECT_THAT(indicators.detectedKeywords, Contains("Python"));
    EXPECT_EQ(analyzer.DetectScriptType(script), FileFormat::Python);
}

TEST_F(FileTypeAnalyzerTest, DetectScriptTypeIdentifiesPowerShellContent) {
    auto& analyzer = FileTypeAnalyzer::Instance();
    const auto buffer = Bytes("param($value)\nWrite-Host $value\n");

    EXPECT_EQ(analyzer.DetectScriptType(buffer), FileFormat::PowerShell);

    const auto info = analyzer.AnalyzeBuffer(buffer, L".txt");
    EXPECT_TRUE(info.detected);
    EXPECT_EQ(info.category, FileCategory::Script);
    EXPECT_TRUE(info.isScript);
}

TEST_F(FileTypeAnalyzerTest, AnalyzeBufferFallsBackToPlainTextForNonScriptText) {
    auto& analyzer = FileTypeAnalyzer::Instance();
    const auto notes = Bytes("plain text file\nwith no script markers\n");

    const auto info = analyzer.AnalyzeBuffer(notes, L".txt");

    EXPECT_TRUE(info.detected);
    EXPECT_EQ(info.category, FileCategory::Text);
    EXPECT_EQ(info.mimeType, "text/plain");
    EXPECT_FALSE(info.isScript);
}

TEST_F(FileTypeAnalyzerTest, SpoofingHelpersDetectRTLAndDoubleExtensionPatterns) {
    auto& analyzer = FileTypeAnalyzer::Instance();

    EXPECT_TRUE(analyzer.HasRTLOverride(L"invoice\u202Etxt.exe"));
    EXPECT_TRUE(analyzer.HasDoubleExtension(L"invoice.pdf.exe"));
    EXPECT_FALSE(analyzer.HasDoubleExtension(L"archive.tar.gz"));
    EXPECT_EQ(analyzer.DetectSpoofing(L"invoice.pdf.exe"), SpoofingType::DoubleExtension);
}

TEST_F(FileTypeAnalyzerTest, AnalyzeFileDetectsContentExtensionMismatch) {
    auto& analyzer = FileTypeAnalyzer::Instance();
    const auto filePath = WriteBytes(L"invoice.exe", BuildZipOfficeBuffer("word"));

    const auto info = analyzer.Analyze(filePath.wstring());

    EXPECT_TRUE(info.detected);
    EXPECT_EQ(info.format, FileFormat::DOCX);
    EXPECT_EQ(info.category, FileCategory::Document);
    EXPECT_TRUE(info.isSpoofed);
    EXPECT_EQ(info.spoofingType, SpoofingType::ExtensionMismatch);
    EXPECT_EQ(info.suggestedExtension, L".docx");
}

TEST_F(FileTypeAnalyzerTest, DetectionHelpersStayAlignedAcrossExecutableAndArchiveInputs) {
    auto& analyzer = FileTypeAnalyzer::Instance();

    const auto peBuffer = BuildMinimalPe64Image();
    const std::array<uint8_t, 8> zipBuffer{ 'P', 'K', 0x03, 0x04, 0x14, 0x00, 0x00, 0x00 };
    const auto zipPath = WriteBytes(L"archive.zip", zipBuffer);
    const auto exePath = WriteBytes(L"helper.exe", peBuffer);

    EXPECT_EQ(analyzer.DetectFormat(peBuffer), FileFormat::PE64);
    EXPECT_TRUE(analyzer.IsExecutable(peBuffer));

    EXPECT_EQ(analyzer.DetectFormat(exePath.wstring()), FileFormat::PE64);
    EXPECT_EQ(analyzer.GetCategory(exePath.wstring()), FileCategory::Executable);
    EXPECT_TRUE(analyzer.IsExecutable(exePath.wstring()));

    EXPECT_EQ(analyzer.DetectFormat(zipPath.wstring()), FileFormat::ZIP);
    EXPECT_EQ(analyzer.GetCategory(zipPath.wstring()), FileCategory::Archive);
    EXPECT_TRUE(analyzer.IsArchive(zipPath.wstring()));
    EXPECT_FALSE(analyzer.IsScript(zipPath.wstring()));
    EXPECT_THAT(analyzer.GetMimeType(zipPath.wstring()), HasSubstr("zip"));
    EXPECT_EQ(analyzer.DetectSpoofing(zipPath.wstring()), SpoofingType::None);
}

TEST_F(FileTypeAnalyzerTest, ValidAlternateExtensionsDoNotTriggerSpoofing) {
    auto& analyzer = FileTypeAnalyzer::Instance();

    const auto screenSaverPath = WriteBytes(L"payload.scr", BuildMinimalPe64Image());
    const auto officeZipPath = WriteBytes(L"report.docx", BuildZipOfficeBuffer("word"));

    const auto screenSaverInfo = analyzer.Analyze(screenSaverPath.wstring());
    EXPECT_TRUE(screenSaverInfo.detected);
    EXPECT_EQ(screenSaverInfo.format, FileFormat::PE64);
    EXPECT_FALSE(screenSaverInfo.isSpoofed);
    EXPECT_EQ(analyzer.DetectSpoofing(screenSaverPath.wstring()), SpoofingType::None);

    const auto officeZipInfo = analyzer.Analyze(officeZipPath.wstring());
    EXPECT_TRUE(officeZipInfo.detected);
    EXPECT_FALSE(officeZipInfo.isSpoofed);
    EXPECT_EQ(analyzer.DetectSpoofing(officeZipPath.wstring()), SpoofingType::None);
}

TEST_F(FileTypeAnalyzerTest, AnalyzeEmptyFileReturnsDedicatedEmptyClassification) {
    auto& analyzer = FileTypeAnalyzer::Instance();
    const auto filePath = WriteBytes(L"empty.bin", std::span<const uint8_t>{});

    const auto info = analyzer.Analyze(filePath.wstring());

    EXPECT_TRUE(info.detected);
    EXPECT_EQ(info.category, FileCategory::Empty);
    EXPECT_EQ(info.confidence, 1.0);
}

TEST_F(FileTypeAnalyzerTest, AddSignatureRegistersCustomMagicPattern) {
    auto& analyzer = FileTypeAnalyzer::Instance();

    MagicSignature signature;
    signature.offset = 4;
    signature.pattern = { 0x13, 0x37 };
    signature.format = FileFormat::PDF;
    signature.description = "Custom sentinel";

    ASSERT_TRUE(analyzer.AddSignature(signature));

    std::vector<uint8_t> buffer(16, 0);
    buffer[4] = 0x13;
    buffer[5] = 0x37;

    const auto info = analyzer.AnalyzeBuffer(buffer);
    EXPECT_TRUE(info.detected);
    EXPECT_EQ(info.format, FileFormat::PDF);
    EXPECT_EQ(info.matchedSignature, "Custom sentinel");
}

TEST_F(FileTypeAnalyzerTest, ExtensionInfoNormalizesInputAndStatisticsTrackAnalyses) {
    auto& analyzer = FileTypeAnalyzer::Instance();

    const auto extInfo = analyzer.GetExtensionInfo("EXE");
    EXPECT_EQ(extInfo.extension, ".exe");
    EXPECT_EQ(extInfo.format, FileFormat::PE32);
    EXPECT_EQ(extInfo.category, FileCategory::Executable);
    EXPECT_TRUE(extInfo.isCommon);

    (void)analyzer.AnalyzeBuffer(Bytes("hello"), L".txt");
    EXPECT_EQ(analyzer.GetStatistics().buffersAnalyzed.load(std::memory_order_relaxed), 1u);

    analyzer.ResetStatistics();
    EXPECT_EQ(analyzer.GetStatistics().buffersAnalyzed.load(std::memory_order_relaxed), 0u);
}

TEST_F(FileTypeAnalyzerTest, UnknownBinaryBuffersIncrementUnknownCounters) {
    auto& analyzer = FileTypeAnalyzer::Instance();

    const auto info = analyzer.AnalyzeBuffer(Bytes("\x90\x91\x92\x93"));
    EXPECT_FALSE(info.detected);
    EXPECT_EQ(info.category, FileCategory::Unknown);

    const auto& stats = analyzer.GetStatistics();
    EXPECT_EQ(stats.buffersAnalyzed.load(std::memory_order_relaxed), 1u);
    EXPECT_EQ(stats.unknownTypes.load(std::memory_order_relaxed), 1u);
}

}  // namespace
