/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * Unit coverage for standalone PE validation routines.
 *
 * Focus:
 *   - DOS/NT/optional-header validation guardrails against malformed inputs
 *   - section overlap and data-directory rules used to harden PE parsing
 *   - error-reporting and anomaly-recording contracts
 */

#include "pch.h"

#include <gtest/gtest.h>

#include <array>
#include <limits>
#include <string>
#include <vector>

#include "../../../src/Shared_modules/PEParser/PEValidation.hpp"
#include "PEParser_TestUtils.hpp"

namespace ShadowStrike::PEParser::Test {

TEST(PEValidationTest, ResultStringsAndErrorObjectsRemainActionable) {
    EXPECT_STREQ(ValidationResultToString(ValidationResult::Valid), L"Valid");
    EXPECT_STREQ(ValidationResultToString(ValidationResult::InvalidDosSignature),
                 L"Invalid DOS signature (expected MZ)");
    EXPECT_STREQ(ValidationResultToString(static_cast<ValidationResult>(9999)),
                 L"Unknown validation result");

    PEError error;
    EXPECT_FALSE(error.HasError());

    error.Set(ValidationResult::FileTooSmall, L"too small", 17);
    EXPECT_TRUE(error.HasError());
    EXPECT_EQ(error.code, ValidationResult::FileTooSmall);
    EXPECT_EQ(error.message, L"too small");
    EXPECT_EQ(error.offset, 17u);

    error.SetWithContext(ValidationResult::InvalidNtSignature, L"bad sig", L"NT headers", 128);
    EXPECT_EQ(error.code, ValidationResult::InvalidNtSignature);
    EXPECT_EQ(error.message, L"bad sig");
    EXPECT_EQ(error.context, L"NT headers");
    EXPECT_EQ(error.offset, 128u);

    error.Clear();
    EXPECT_FALSE(error.HasError());
    EXPECT_TRUE(error.message.empty());
    EXPECT_TRUE(error.context.empty());
    EXPECT_EQ(error.offset, 0u);
}

TEST(PEValidationTest, DosHeaderValidationRejectsMalformedInputsAndAcceptsValidHeaders) {
    int32_t lfanew = 0;
    PEError error;

    const std::vector<uint8_t> tiny(64, 0);
    EXPECT_EQ(ValidateDosHeader(SafeReader(tiny), lfanew, &error), ValidationResult::FileTooSmall);
    EXPECT_EQ(error.code, ValidationResult::FileTooSmall);

    auto image = BuildMinimalPE32();
    EXPECT_EQ(ValidateDosHeader(SafeReader(image), lfanew, &error), ValidationResult::Valid);
    EXPECT_EQ(lfanew, static_cast<int32_t>(kNtHeadersOffset));

    auto invalidSignature = image;
    const uint16_t badMagic = 0x1234;
    WriteObject(invalidSignature, 0, badMagic);
    EXPECT_EQ(ValidateDosHeader(SafeReader(invalidSignature), lfanew, &error),
              ValidationResult::InvalidDosSignature);

    auto negativeLfanew = image;
    const int32_t negative = -4;
    WriteObject(negativeLfanew, offsetof(DosHeader, e_lfanew), negative);
    EXPECT_EQ(ValidateDosHeader(SafeReader(negativeLfanew), lfanew, &error),
              ValidationResult::LfanewNegative);

    auto shortLfanew = image;
    const int32_t tooSmall = 0x20;
    WriteObject(shortLfanew, offsetof(DosHeader, e_lfanew), tooSmall);
    EXPECT_EQ(ValidateDosHeader(SafeReader(shortLfanew), lfanew, &error),
              ValidationResult::LfanewTooSmall);

    auto outOfBounds = image;
    const int32_t hugeOffset = static_cast<int32_t>(outOfBounds.size() - 8);
    WriteObject(outOfBounds, offsetof(DosHeader, e_lfanew), hugeOffset);
    EXPECT_EQ(ValidateDosHeader(SafeReader(outOfBounds), lfanew, &error),
              ValidationResult::LfanewOutOfBounds);
}

TEST(PEValidationTest, NtHeaderValidationEnforcesSignatureMachineAndArchitectureContracts) {
    PEError error;
    FileHeader fileHeader{};
    bool is64Bit = false;

    auto image32 = BuildMinimalPE32();
    EXPECT_EQ(ValidateNtHeaders(SafeReader(image32), kNtHeadersOffset, is64Bit, fileHeader, &error),
              ValidationResult::Valid);
    EXPECT_FALSE(is64Bit);
    EXPECT_EQ(fileHeader.Machine, Machine::I386);
    EXPECT_EQ(fileHeader.NumberOfSections, 1u);

    auto badSignature = image32;
    const uint32_t badNt = 0;
    WriteObject(badSignature, kNtHeadersOffset, badNt);
    EXPECT_EQ(ValidateNtHeaders(SafeReader(badSignature), kNtHeadersOffset, is64Bit, fileHeader, &error),
              ValidationResult::InvalidNtSignature);

    auto badMachine = image32;
    const size_t machineOffset = kNtHeadersOffset + sizeof(uint32_t) + offsetof(FileHeader, Machine);
    const uint16_t invalidMachine = 0xFFFF;
    WriteObject(badMachine, machineOffset, invalidMachine);
    EXPECT_EQ(ValidateNtHeaders(SafeReader(badMachine), kNtHeadersOffset, is64Bit, fileHeader, &error),
              ValidationResult::InvalidMachine);

    auto image64 = BuildMinimalPE64();
    EXPECT_EQ(ValidateNtHeaders(SafeReader(image64), kNtHeadersOffset, is64Bit, fileHeader, &error),
              ValidationResult::Valid);
    EXPECT_TRUE(is64Bit);
    EXPECT_EQ(fileHeader.Machine, Machine::AMD64);
}

TEST(PEValidationTest, OptionalHeaderValidationRejectsAlignmentSizingAndSubsystemViolations) {
    PEError error;

    std::vector<uint8_t> buffer(0x400, 0);
    SafeReader reader(buffer);
    OptionalHeader32 opt32{};
    opt32.Magic = PE32_MAGIC;
    opt32.AddressOfEntryPoint = kSectionVirtualAddress;
    opt32.BaseOfCode = kSectionVirtualAddress;
    opt32.BaseOfData = kSectionVirtualAddress;
    opt32.ImageBase = 0x400000;
    opt32.SectionAlignment = kSectionAlignment;
    opt32.FileAlignment = kFileAlignment;
    opt32.SizeOfImage = 0x2000;
    opt32.SizeOfHeaders = 0x200;
    opt32.Subsystem = Subsystem::WINDOWS_CUI;
    opt32.SizeOfStackReserve = 0x100000;
    opt32.SizeOfStackCommit = 0x1000;
    opt32.SizeOfHeapReserve = 0x100000;
    opt32.SizeOfHeapCommit = 0x1000;
    opt32.NumberOfRvaAndSizes = DataDirectory::MAX_ENTRIES;
    WriteObject(buffer, 0, opt32);

    OptionalHeader32 parsed32{};
    EXPECT_EQ(ValidateOptionalHeader32(reader, 0, sizeof(OptionalHeader32), parsed32, &error),
              ValidationResult::Valid);
    EXPECT_EQ(parsed32.ImageBase, 0x400000u);
    const auto valid32 = parsed32;

    opt32 = valid32;
    opt32.FileAlignment = 300;
    WriteObject(buffer, 0, opt32);
    EXPECT_EQ(ValidateOptionalHeader32(reader, 0, sizeof(OptionalHeader32), parsed32, &error),
              ValidationResult::InvalidFileAlignment);

    opt32 = valid32;
    opt32.SizeOfStackCommit = opt32.SizeOfStackReserve + 1;
    WriteObject(buffer, 0, opt32);
    EXPECT_EQ(ValidateOptionalHeader32(reader, 0, sizeof(OptionalHeader32), parsed32, &error),
              ValidationResult::SizeOfStackCommitExceedsReserve);

    opt32 = valid32;
    opt32.Subsystem = 99;
    WriteObject(buffer, 0, opt32);
    EXPECT_EQ(ValidateOptionalHeader32(reader, 0, sizeof(OptionalHeader32), parsed32, &error),
              ValidationResult::InvalidSubsystem);

    opt32 = valid32;
    opt32.SizeOfImage = 0x2101;
    WriteObject(buffer, 0, opt32);
    EXPECT_EQ(ValidateOptionalHeader32(reader, 0, sizeof(OptionalHeader32), parsed32, &error),
              ValidationResult::SizeOfImageNotAligned);

    opt32 = valid32;
    opt32.SizeOfHeaders = 0x180;
    WriteObject(buffer, 0, opt32);
    EXPECT_EQ(ValidateOptionalHeader32(reader, 0, sizeof(OptionalHeader32), parsed32, &error),
              ValidationResult::SizeOfHeadersNotAligned);

    OptionalHeader64 opt64{};
    opt64.Magic = PE64_MAGIC;
    opt64.AddressOfEntryPoint = kSectionVirtualAddress;
    opt64.BaseOfCode = kSectionVirtualAddress;
    opt64.ImageBase = 0x140000000ULL;
    opt64.SectionAlignment = kSectionAlignment;
    opt64.FileAlignment = kFileAlignment;
    opt64.SizeOfImage = 0x2000;
    opt64.SizeOfHeaders = 0x200;
    opt64.Subsystem = Subsystem::WINDOWS_GUI;
    opt64.SizeOfStackReserve = 0x100000;
    opt64.SizeOfStackCommit = 0x1000;
    opt64.SizeOfHeapReserve = 0x100000;
    opt64.SizeOfHeapCommit = 0x1000;
    opt64.NumberOfRvaAndSizes = DataDirectory::MAX_ENTRIES;
    WriteObject(buffer, 0x100, opt64);

    OptionalHeader64 parsed64{};
    EXPECT_EQ(ValidateOptionalHeader64(reader, 0x100, sizeof(OptionalHeader64), parsed64, &error),
              ValidationResult::Valid);

    opt64.ImageBase = 0x140000001ULL;
    WriteObject(buffer, 0x100, opt64);
    EXPECT_EQ(ValidateOptionalHeader64(reader, 0x100, sizeof(OptionalHeader64), parsed64, &error),
              ValidationResult::InvalidImageBase);
}

TEST(PEValidationTest, SectionOverlapAndDirectoryChecksPreserveSecurityInvariants) {
    PEError error;
    SectionHeader section{};
    constexpr std::array<uint8_t, 8> kTextName = {'.', 't', 'e', 'x', 't', 0, 0, 0};
    std::copy(kTextName.begin(), kTextName.end(), section.Name);
    section.VirtualAddress = 0x1000;
    section.VirtualSize = 0x200;
    section.SizeOfRawData = 0x200;
    section.PointerToRawData = 0x200;
    section.Characteristics = SectionCharacteristics::CNT_CODE |
                              SectionCharacteristics::MEM_EXECUTE |
                              SectionCharacteristics::MEM_READ;

    std::vector<Anomaly> anomalies;
    EXPECT_EQ(ValidateSectionHeader(section, 0x600, 0x3000, 0x200, 0, &error, &anomalies),
              ValidationResult::Valid);
    EXPECT_TRUE(anomalies.empty());

    SectionHeader misaligned = section;
    misaligned.PointerToRawData = 0x210;
    anomalies.clear();
    EXPECT_EQ(ValidateSectionHeader(misaligned, 0x600, 0x3000, 0x200, 0, &error, &anomalies),
              ValidationResult::Valid);
    ASSERT_EQ(anomalies.size(), 1u);
    EXPECT_EQ(anomalies.front().type, AnomalyType::SectionAlignmentViolation);

    SectionHeader beyondFile = section;
    beyondFile.SizeOfRawData = 0x500;
    EXPECT_EQ(ValidateSectionHeader(beyondFile, 0x400, 0x3000, 0x200, 0, &error, nullptr),
              ValidationResult::SectionBeyondFile);

    SectionHeader beyondImage = section;
    beyondImage.VirtualSize = 0x5000;
    EXPECT_EQ(ValidateSectionHeader(beyondImage, 0x800, 0x2000, 0x200, 0, &error, nullptr),
              ValidationResult::SectionBeyondImage);

    std::vector<SectionHeader> sections(2, section);
    sections[1].PointerToRawData = 0x280;
    sections[1].VirtualAddress = 0x1100;
    std::vector<std::pair<size_t, size_t>> overlaps;
    ASSERT_TRUE(CheckSectionOverlaps(sections, overlaps));
    ASSERT_EQ(overlaps.size(), 1u);
    EXPECT_EQ(overlaps[0].first, 0u);
    EXPECT_EQ(overlaps[0].second, 1u);

    EXPECT_EQ(ValidateDataDirectory(DataDirectory::IMPORT, 0, 0, 0x3000, 0x1000, &error),
              ValidationResult::Valid);
    EXPECT_EQ(ValidateDataDirectory(DataDirectory::IMPORT, 0, 16, 0x3000, 0x1000, &error),
              ValidationResult::DataDirectoryRvaInvalid);
    EXPECT_EQ(ValidateDataDirectory(DataDirectory::SECURITY, 0x900, 0x200, 0x3000, 0x1000, &error),
              ValidationResult::Valid);
    EXPECT_EQ(ValidateDataDirectory(DataDirectory::SECURITY, 0x900, 4, 0x3000, 0x1000, &error),
              ValidationResult::SecurityDirectoryInvalid);
    EXPECT_EQ(ValidateDataDirectory(DataDirectory::SECURITY, 0xF80, 0x100, 0x3000, 0x1000, &error),
              ValidationResult::SecurityDirectoryInvalid);
    EXPECT_EQ(ValidateDataDirectory(DataDirectory::IMPORT, 0x1000, 8, 0x3000, 0x1000, &error),
              ValidationResult::ImportDirectoryInvalid);
    EXPECT_EQ(ValidateDataDirectory(DataDirectory::EXPORT, 0x2000, sizeof(ExportDirectory), 0x3000, 0x1000, &error),
              ValidationResult::Valid);
    EXPECT_EQ(ValidateDataDirectory(DataDirectory::RESOURCE, 0x2F00, 0x200, 0x3000, 0x1000, &error),
              ValidationResult::DataDirectoryOutOfBounds);
}

}  // namespace ShadowStrike::PEParser::Test
