/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * Unit coverage for PEParser public parsing API.
 *
 * Focus:
 *   - zero-copy parsing of synthetic PE32/PE32+ images
 *   - address translation, checksum, signature, overlay, and anomaly contracts
 *   - lazy-directory parsing and ParseFile behavior without live system dependencies
 */

#include "pch.h"

#include <gtest/gtest.h>

#include <string>
#include <vector>

#include "../../../src/PhantomCore/PEParser/PEParser.hpp"
#include "PEParser_TestUtils.hpp"

namespace ShadowStrike::PEParser::Test {

class PEParserApiTest : public ::testing::Test {
protected:
    ScopedTempDir tempDir{L"ShadowStrike_PEParserTests_"};
};

TEST_F(PEParserApiTest, ParsingRequiresValidInputAndUnparsedStateReportsExplicitErrors) {
    ::ShadowStrike::PEParser::PEParser parser;
    PEInfo info;
    PEError error;

    EXPECT_FALSE(parser.ParseBuffer(nullptr, 0, info, &error));
    EXPECT_EQ(error.code, ValidationResult::NullPointer);
    EXPECT_FALSE(parser.IsParsed());
    EXPECT_EQ(parser.GetReader(), nullptr);
    EXPECT_EQ(parser.GetInfo(), nullptr);
    EXPECT_FALSE(parser.RvaToOffset(0x1000).has_value());
    EXPECT_FALSE(parser.OffsetToRva(0x200).has_value());
    EXPECT_FALSE(parser.IsValidRva(0x1000));
    EXPECT_EQ(parser.CalculateSectionEntropy(0), -1.0);
    EXPECT_FALSE(parser.VerifyChecksum());
    EXPECT_FALSE(parser.HasAnomaly(AnomalyType::OverlayPresent));

    std::vector<ValidationResult> issues;
    EXPECT_FALSE(parser.ValidatePE(issues));
    ASSERT_EQ(issues.size(), 1u);
    EXPECT_EQ(issues.front(), ValidationResult::UnknownError);

    std::vector<ImportInfo> imports;
    ExportDirectoryInfo exports;
    TLSInfo tls;
    std::vector<ResourceEntry> resources;
    std::vector<RelocationBlock> relocations;
    std::vector<DebugInfo> debugInfo;
    RichHeaderInfo richHeader;
    std::vector<DelayImportInfo> delayImports;
    LoadConfigInfo loadConfig;
    std::vector<ExceptionEntry> exceptions;

    EXPECT_FALSE(parser.ParseImports(imports, &error));
    EXPECT_EQ(error.code, ValidationResult::UnknownError);
    EXPECT_FALSE(parser.ParseExports(exports, &error));
    EXPECT_FALSE(parser.ParseTLS(tls, &error));
    EXPECT_FALSE(parser.ParseResources(resources, 4, &error));
    EXPECT_FALSE(parser.ParseRelocations(relocations, &error));
    EXPECT_FALSE(parser.ParseDebugInfo(debugInfo, &error));
    EXPECT_FALSE(parser.ParseRichHeader(richHeader, &error));
    EXPECT_FALSE(parser.ParseDelayImports(delayImports, &error));
    EXPECT_FALSE(parser.ParseLoadConfig(loadConfig, &error));
    EXPECT_FALSE(parser.ParseExceptionDirectory(exceptions, &error));

    EXPECT_FALSE(parser.ParseFile(L"", info, &error));
    EXPECT_EQ(error.code, ValidationResult::NullPointer);

    std::wstring longPath(MAX_PATH + 1, L'a');
    EXPECT_FALSE(parser.ParseFile(longPath, info, &error));
    EXPECT_EQ(error.code, ValidationResult::UnknownError);

    EXPECT_FALSE(parser.ParseFile(L"\\\\?\\C:\\Temp\\file.exe", info, &error));
    EXPECT_EQ(error.code, ValidationResult::UnknownError);
}

TEST_F(PEParserApiTest, MinimalPe32ParsingPopulatesMetadataAndTranslationContracts) {
    ::ShadowStrike::PEParser::PEParser parser;
    const auto image = BuildMinimalPE32();

    PEInfo info;
    PEError error;
    ASSERT_TRUE(parser.ParseBuffer(image.data(), image.size(), info, &error));
    EXPECT_TRUE(parser.IsParsed());
    EXPECT_TRUE(info.valid);
    EXPECT_FALSE(info.is64Bit);
    EXPECT_FALSE(info.isDotNet);
    EXPECT_FALSE(info.isSigned);
    EXPECT_FALSE(info.isDLL);
    EXPECT_FALSE(info.isDriver);
    EXPECT_EQ(info.machine, Machine::I386);
    EXPECT_EQ(info.machineString, L"Intel 386");
    EXPECT_EQ(info.entryPointRva, kSectionVirtualAddress);
    EXPECT_EQ(info.sizeOfHeaders, kSizeOfHeaders);
    EXPECT_EQ(info.fileAlignment, kFileAlignment);
    EXPECT_EQ(info.sectionAlignment, kSectionAlignment);
    ASSERT_EQ(info.sections.size(), 1u);
    EXPECT_EQ(info.sections[0].name, ".text");
    EXPECT_TRUE(info.sections[0].isExecutable);
    EXPECT_FALSE(info.sections[0].isWritable);
    EXPECT_TRUE(info.sections[0].isReadable);
    EXPECT_TRUE(info.sections[0].hasCode);
    EXPECT_FALSE(info.sections[0].isPackedHeuristic);
    EXPECT_EQ(info.entryPointSectionIndex, 0u);
    EXPECT_TRUE(info.entryPointInExecutableSection);

    ASSERT_NE(parser.GetReader(), nullptr);
    ASSERT_NE(parser.GetInfo(), nullptr);
    EXPECT_EQ(parser.GetInfo()->machine, Machine::I386);

    EXPECT_EQ(parser.RvaToOffset(kSectionVirtualAddress), static_cast<size_t>(kSectionRawAddress));
    EXPECT_EQ(parser.OffsetToRva(kSectionRawAddress), kSectionVirtualAddress);
    EXPECT_EQ(parser.OffsetToRva(0x100), 0x100u);
    EXPECT_EQ(parser.GetSectionByRva(kSectionVirtualAddress + 0x10), 0u);
    EXPECT_EQ(parser.GetSectionByName(".text"), 0u);
    EXPECT_TRUE(parser.IsValidRva(kSectionVirtualAddress + 0x10));
    EXPECT_FALSE(parser.RvaToOffset(kSectionVirtualAddress + 0x250).has_value());
    EXPECT_EQ(parser.GetSectionByRva(kSectionVirtualAddress + 0x250), 0u);

    EXPECT_GE(parser.CalculateSectionEntropy(0), 0.0);
    EXPECT_LT(parser.CalculateSectionEntropy(0), 2.0);
    EXPECT_EQ(parser.CalculateSectionEntropy(99), -1.0);
    EXPECT_TRUE(parser.VerifyChecksum());

    std::vector<ValidationResult> issues;
    EXPECT_TRUE(parser.ValidatePE(issues));
    EXPECT_TRUE(issues.empty());

    std::vector<ImportInfo> imports;
    ExportDirectoryInfo exports;
    TLSInfo tls;
    std::vector<ResourceEntry> resources;
    std::vector<RelocationBlock> relocations;
    std::vector<DebugInfo> debugInfo;
    RichHeaderInfo richHeader;
    std::vector<DelayImportInfo> delayImports;
    LoadConfigInfo loadConfig;
    std::vector<ExceptionEntry> exceptions;

    EXPECT_TRUE(parser.ParseImports(imports, &error));
    EXPECT_TRUE(imports.empty());
    EXPECT_TRUE(parser.ParseExports(exports, &error));
    EXPECT_TRUE(exports.exports.empty());
    EXPECT_TRUE(parser.ParseTLS(tls, &error));
    EXPECT_TRUE(tls.callbacks.empty());
    EXPECT_TRUE(parser.ParseResources(resources, 0, &error));
    EXPECT_TRUE(resources.empty());
    EXPECT_TRUE(parser.ParseRelocations(relocations, &error));
    EXPECT_TRUE(relocations.empty());
    EXPECT_TRUE(parser.ParseDebugInfo(debugInfo, &error));
    EXPECT_TRUE(debugInfo.empty());
    EXPECT_TRUE(parser.ParseRichHeader(richHeader, &error));
    EXPECT_FALSE(richHeader.present);
    EXPECT_TRUE(parser.ParseDelayImports(delayImports, &error));
    EXPECT_TRUE(delayImports.empty());
    EXPECT_TRUE(parser.ParseLoadConfig(loadConfig, &error));
    EXPECT_FALSE(loadConfig.hasSEH);
    EXPECT_FALSE(loadConfig.hasSecurityCookie);
    EXPECT_TRUE(parser.ParseExceptionDirectory(exceptions, &error));
    EXPECT_TRUE(exceptions.empty());

    EXPECT_EQ(::ShadowStrike::PEParser::PEParser::MachineToString(Machine::AMD64), L"AMD64 (x64)");
    EXPECT_EQ(::ShadowStrike::PEParser::PEParser::MachineToString(0xFFFF), L"Unknown");
    EXPECT_EQ(::ShadowStrike::PEParser::PEParser::SubsystemToString(Subsystem::WINDOWS_GUI), L"Windows GUI");
    EXPECT_EQ(::ShadowStrike::PEParser::PEParser::SubsystemToString(0xFFFF), L"Unknown");
}

TEST_F(PEParserApiTest, RichHeaderImportParsingAndParseFileWorkOnConcreteArtifacts) {
    ::ShadowStrike::PEParser::PEParser parser;
    SyntheticPEOptions options;
    options.includeImportDirectory = true;
    options.includeRichHeader = true;
    const auto image = BuildMinimalPE32(options);

    PEInfo info;
    PEError error;
    ASSERT_TRUE(parser.ParseBuffer(std::span<const uint8_t>(image), info, &error));

    RichHeaderInfo richHeader;
    ASSERT_TRUE(parser.ParseRichHeader(richHeader, &error));
    EXPECT_TRUE(richHeader.present);
    ASSERT_EQ(richHeader.entries.size(), 1u);
    EXPECT_EQ(richHeader.entries[0].buildId, 0x1234u);
    EXPECT_EQ(richHeader.entries[0].productId, 0x5678u);
    EXPECT_EQ(richHeader.entries[0].useCount, 9u);

    std::vector<ImportInfo> imports;
    ASSERT_TRUE(parser.ParseImports(imports, &error));
    ASSERT_EQ(imports.size(), 1u);
    EXPECT_EQ(imports[0].dllName, L"KERNEL32.dll");
    ASSERT_EQ(imports[0].functions.size(), 1u);
    EXPECT_EQ(imports[0].functions[0].name, "ExitProcess");
    EXPECT_EQ(imports[0].functions[0].hint, 0u);
    EXPECT_FALSE(imports[0].functions[0].byOrdinal);
    EXPECT_EQ(imports[0].functions[0].iatRva, kSectionVirtualAddress + 0x30u);

    const auto path = tempDir.File(L"sample32.exe");
    WriteAllBytes(path, image);

    ::ShadowStrike::PEParser::PEParser fileParser;
    ASSERT_TRUE(fileParser.ParseFile(path.wstring(), info, &error));
    EXPECT_TRUE(info.valid);
    EXPECT_EQ(info.machine, Machine::I386);
    EXPECT_TRUE(fileParser.IsParsed());
}

TEST_F(PEParserApiTest, DotNetSignatureOverlayAndChecksumSignalsSurfaceThroughPublicApi) {
    ::ShadowStrike::PEParser::PEParser parser;
    SyntheticPEOptions options;
    options.includeDotNetDirectory = true;
    options.includeSecurityDirectory = true;
    options.includeOverlay = true;
    options.useInvalidChecksum = true;

    const auto image = BuildMinimalPE32(options);
    PEInfo info;
    PEError error;
    ASSERT_TRUE(parser.ParseBuffer(image, info, &error));
    EXPECT_TRUE(info.isDotNet);
    EXPECT_TRUE(info.isSigned);
    EXPECT_GT(info.overlayOffset, 0u);
    EXPECT_GT(info.overlaySize, 0u);
    EXPECT_FALSE(parser.VerifyChecksum());
    EXPECT_TRUE(parser.HasAnomaly(AnomalyType::OverlayPresent));
    EXPECT_TRUE(parser.HasAnomaly(AnomalyType::OverlayHighEntropy));
    EXPECT_TRUE(parser.HasAnomaly(AnomalyType::ChecksumMismatch));
}

TEST_F(PEParserApiTest, DriverAndHighEntropyHeuristicsAreDetectedOnPe64Images) {
    ::ShadowStrike::PEParser::PEParser parser;
    SyntheticPEOptions options;
    options.driver = true;
    options.highEntropyText = true;

    const auto image = BuildMinimalPE64(options);
    PEInfo info;
    PEError error;
    ASSERT_TRUE(parser.ParseBuffer(image, info, &error));
    EXPECT_TRUE(info.valid);
    EXPECT_TRUE(info.is64Bit);
    EXPECT_TRUE(info.isDriver);
    ASSERT_EQ(info.sections.size(), 1u);
    EXPECT_GT(info.sections[0].entropy, 7.0);
    EXPECT_TRUE(info.sections[0].isPackedHeuristic);
    EXPECT_TRUE(parser.HasAnomaly(AnomalyType::SectionHighEntropy));
    EXPECT_TRUE(parser.HasAnomaly(AnomalyType::WeakChecksum));

    std::vector<ExceptionEntry> exceptions;
    EXPECT_TRUE(parser.ParseExceptionDirectory(exceptions, &error));
    EXPECT_TRUE(exceptions.empty());
}

TEST_F(PEParserApiTest, SignedImagesExposeSecurityFileOffsetWithoutOverlayFalsePositive) {
    ::ShadowStrike::PEParser::PEParser parser;
    SyntheticPEOptions options;
    options.includeSecurityDirectory = true;

    const auto image = BuildMinimalPE32(options);
    PEInfo info;
    PEError error;
    ASSERT_TRUE(parser.ParseBuffer(image, info, &error));

    const auto& securityDir = info.dataDirectories[DataDirectory::SECURITY];
    EXPECT_TRUE(info.isSigned);
    EXPECT_TRUE(securityDir.present);
    ASSERT_TRUE(securityDir.fileOffset.has_value());
    EXPECT_EQ(*securityDir.fileOffset, static_cast<size_t>(securityDir.rva));
    EXPECT_EQ(info.overlayOffset, 0u);
    EXPECT_EQ(info.overlaySize, 0u);
    EXPECT_FALSE(parser.HasAnomaly(AnomalyType::OverlayPresent));
}

TEST_F(PEParserApiTest, WritableExecutableSectionsRemainVisibleAsSectionLevelAnomalies) {
    ::ShadowStrike::PEParser::PEParser parser;
    SyntheticPEOptions options;
    options.writableExecutableText = true;

    const auto image = BuildMinimalPE32(options);
    PEInfo info;
    PEError error;
    ASSERT_TRUE(parser.ParseBuffer(image, info, &error));
    ASSERT_EQ(info.sections.size(), 1u);
    EXPECT_TRUE(info.sections[0].isExecutable);
    EXPECT_TRUE(info.sections[0].isWritable);
    EXPECT_NE(std::find_if(
                  info.sections[0].anomalies.begin(),
                  info.sections[0].anomalies.end(),
                  [](const Anomaly& anomaly) {
                      return anomaly.type == AnomalyType::SectionWritableExecutable;
                  }),
              info.sections[0].anomalies.end());
}

TEST_F(PEParserApiTest, ResetReparseAndDeepValidationRemainUsableAfterMalformedSections) {
    ::ShadowStrike::PEParser::PEParser parser;
    PEInfo info;
    PEError error;

    ASSERT_TRUE(parser.ParseBuffer(BuildMinimalPE32(), info, &error));
    EXPECT_TRUE(parser.IsParsed());
    parser.Reset();
    EXPECT_FALSE(parser.IsParsed());
    EXPECT_EQ(parser.GetReader(), nullptr);
    EXPECT_EQ(parser.GetInfo(), nullptr);

    auto invalidImage = BuildMinimalPE32();
    SectionHeader header{};
    const size_t sectionHeaderOffset = SectionTableOffset(false);
    ASSERT_LT(sectionHeaderOffset + sizeof(SectionHeader), invalidImage.size());
    std::memcpy(&header, invalidImage.data() + sectionHeaderOffset, sizeof(header));
    header.SizeOfRawData = 0x500;
    WriteObject(invalidImage, sectionHeaderOffset, header);

    EXPECT_FALSE(parser.ParseBuffer(invalidImage, info, &error));
    EXPECT_EQ(error.code, ValidationResult::SectionBeyondFile);
    EXPECT_FALSE(parser.IsParsed());

    SyntheticPEOptions secure64;
    secure64.pe64 = true;
    secure64.useValidChecksum = true;
    const auto valid64 = BuildMinimalPE64(secure64);
    ASSERT_TRUE(parser.ParseBuffer(valid64.data(), valid64.size(), info, &error));
    EXPECT_TRUE(info.is64Bit);
    EXPECT_TRUE(parser.VerifyChecksum());
    EXPECT_FALSE(parser.HasAnomaly(AnomalyType::ChecksumMismatch));
}

}  // namespace ShadowStrike::PEParser::Test
