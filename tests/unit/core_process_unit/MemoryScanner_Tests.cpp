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
 * @file MemoryScanner_Tests.cpp
 * @brief Comprehensive GTest coverage for Core::Process::MemoryScanner helper surfaces.
 *
 * Coverage focus:
 * - configuration presets and atomic statistics lifecycle
 * - entropy, printable string extraction, and API-hashing heuristics
 * - PE header detection and parsing for PE32 and PE32+
 * - shellcode scoring behavior for deterministic in-memory buffers
 */

#include "../../../src/pch.h"

#include "../../../src/PhantomCore/Core/Process/MemoryScanner.hpp"

#include <array>
#include <numeric>

namespace {

using namespace ShadowStrike::Core::Process;

std::vector<uint8_t> BuildMinimalPE32() {
    std::vector<uint8_t> image(0x200, 0);
    image[0] = 'M';
    image[1] = 'Z';

    const uint32_t peOffset = 0x80;
    std::memcpy(image.data() + 0x3C, &peOffset, sizeof(peOffset));

    image[peOffset + 0] = 'P';
    image[peOffset + 1] = 'E';

    const uint16_t machine = 0x014C;
    const uint16_t characteristics = 0x210E;
    std::memcpy(image.data() + peOffset + 4, &machine, sizeof(machine));
    std::memcpy(image.data() + peOffset + 22, &characteristics, sizeof(characteristics));

    const uint16_t optionalMagic = 0x010B;
    const uint32_t entryPoint = 0x1000;
    const uint32_t imageBase = 0x00400000;
    const uint32_t imageSize = 0x5000;
    std::memcpy(image.data() + peOffset + 24, &optionalMagic, sizeof(optionalMagic));
    std::memcpy(image.data() + peOffset + 40, &entryPoint, sizeof(entryPoint));
    std::memcpy(image.data() + peOffset + 52, &imageBase, sizeof(imageBase));
    std::memcpy(image.data() + peOffset + 80, &imageSize, sizeof(imageSize));

    return image;
}

std::vector<uint8_t> BuildMinimalPE64() {
    std::vector<uint8_t> image(0x220, 0);
    image[0] = 'M';
    image[1] = 'Z';

    const uint32_t peOffset = 0x90;
    std::memcpy(image.data() + 0x3C, &peOffset, sizeof(peOffset));

    image[peOffset + 0] = 'P';
    image[peOffset + 1] = 'E';

    const uint16_t machine = 0x8664;
    const uint16_t characteristics = 0x2022;
    std::memcpy(image.data() + peOffset + 4, &machine, sizeof(machine));
    std::memcpy(image.data() + peOffset + 22, &characteristics, sizeof(characteristics));

    const uint16_t optionalMagic = 0x020B;
    const uint32_t entryPoint = 0x2000;
    const uint64_t imageBase = 0x0000000140000000ULL;
    const uint32_t imageSize = 0x9000;
    std::memcpy(image.data() + peOffset + 24, &optionalMagic, sizeof(optionalMagic));
    std::memcpy(image.data() + peOffset + 40, &entryPoint, sizeof(entryPoint));
    std::memcpy(image.data() + peOffset + 48, &imageBase, sizeof(imageBase));
    std::memcpy(image.data() + peOffset + 80, &imageSize, sizeof(imageSize));

    return image;
}

class MemoryScannerValueTest : public ::testing::Test {
protected:
    void SetUp() override {
        MemoryScanner::Instance().Shutdown();
    }

    void TearDown() override {
        MemoryScanner::Instance().Shutdown();
    }
};

TEST(MemoryScannerValueTests, ConfigPresetsReflectExpectedDepthAndPerformanceTradeoffs) {
    const auto defaults = MemoryScannerConfig::CreateDefault();
    const auto quick = MemoryScannerConfig::CreateQuick();
    const auto deep = MemoryScannerConfig::CreateDeep();
    const auto forensic = MemoryScannerConfig::CreateForensic();

    EXPECT_EQ(defaults.defaultMode, ScanMode::Normal);
    EXPECT_TRUE(defaults.scanPrivate);
    EXPECT_TRUE(defaults.extractStrings);

    EXPECT_EQ(quick.defaultMode, ScanMode::Quick);
    EXPECT_FALSE(quick.scanPrivate);
    EXPECT_FALSE(quick.scanMapped);
    EXPECT_FALSE(quick.scanImages);
    EXPECT_FALSE(quick.extractStrings);

    EXPECT_EQ(deep.defaultMode, ScanMode::Deep);
    EXPECT_TRUE(deep.scanMapped);
    EXPECT_TRUE(deep.scanImages);
    EXPECT_GT(deep.maxScanSizePerProcess, defaults.maxScanSizePerProcess);
    EXPECT_GT(deep.scanTimeoutMs, defaults.scanTimeoutMs);

    EXPECT_EQ(forensic.defaultMode, ScanMode::Forensic);
    EXPECT_TRUE(forensic.extractStrings);
    EXPECT_GT(forensic.maxStringsExtracted, deep.maxStringsExtracted);
}

TEST(MemoryScannerValueTests, StatisticsSnapshotAndResetPreserveAtomicValues) {
    MemoryScannerStats stats;
    stats.totalScans.store(5, std::memory_order_relaxed);
    stats.processesScanned.store(4, std::memory_order_relaxed);
    stats.bytesScanned.store(4096, std::memory_order_relaxed);
    stats.threatsFound.store(3, std::memory_order_relaxed);
    stats.avgScanTimeMs.store(250, std::memory_order_relaxed);

    const MemoryScannerStats snapshot = stats;
    EXPECT_EQ(snapshot.totalScans.load(std::memory_order_relaxed), 5u);
    EXPECT_EQ(snapshot.processesScanned.load(std::memory_order_relaxed), 4u);
    EXPECT_EQ(snapshot.bytesScanned.load(std::memory_order_relaxed), 4096u);
    EXPECT_EQ(snapshot.threatsFound.load(std::memory_order_relaxed), 3u);
    EXPECT_EQ(snapshot.avgScanTimeMs.load(std::memory_order_relaxed), 250u);

    stats.Reset();
    EXPECT_EQ(stats.totalScans.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.processesScanned.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.bytesScanned.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.threatsFound.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.avgScanTimeMs.load(std::memory_order_relaxed), 0u);
}

TEST_F(MemoryScannerValueTest, CalculateEntropyDistinguishesConstantAndUniformBuffers) {
    auto& scanner = MemoryScanner::Instance();

    std::vector<uint8_t> constant(512, 0x41);
    std::vector<uint8_t> uniform(256);
    std::iota(uniform.begin(), uniform.end(), static_cast<uint8_t>(0));

    EXPECT_DOUBLE_EQ(scanner.CalculateEntropy(constant), 0.0);
    EXPECT_NEAR(scanner.CalculateEntropy(uniform), 8.0, 0.001);
}

TEST_F(MemoryScannerValueTest, CalculateEntropyAndExtractStringsHandleEmptyBuffers) {
    auto& scanner = MemoryScanner::Instance();
    const std::vector<uint8_t> empty;

    EXPECT_DOUBLE_EQ(scanner.CalculateEntropy(empty), 0.0);
    EXPECT_TRUE(scanner.ExtractStrings(empty).empty());
    EXPECT_FALSE(scanner.CheckAPIHashing(empty));
}

TEST_F(MemoryScannerValueTest, ExtractStringsKeepsPrintableRunsAboveRequestedThreshold) {
    auto& scanner = MemoryScanner::Instance();
    const std::vector<uint8_t> buffer{
        'A', 'B', 'C', 0x00,
        '1', '2', '3', '4', '5', 0x00,
        'x', 'y', 0x7F,
        'S', 'h', 'a', 'd', 'o', 'w', 0x00
    };

    const auto minThree = scanner.ExtractStrings(buffer, 3);
    const auto minFive = scanner.ExtractStrings(buffer, 5);

    ASSERT_EQ(minThree.size(), 3u);
    EXPECT_EQ(minThree[0], "ABC");
    EXPECT_EQ(minThree[1], "12345");
    EXPECT_EQ(minThree[2], "Shadow");

    ASSERT_EQ(minFive.size(), 2u);
    EXPECT_EQ(minFive[0], "12345");
    EXPECT_EQ(minFive[1], "Shadow");
}

TEST_F(MemoryScannerValueTest, ContainsPEAndParsePESupportPE32AndPE32PlusBuffers) {
    auto& scanner = MemoryScanner::Instance();
    const auto pe32 = BuildMinimalPE32();
    const auto pe64 = BuildMinimalPE64();

    ASSERT_TRUE(scanner.ContainsPE(pe32));
    ASSERT_TRUE(scanner.ContainsPE(pe64));

    const auto pe32Info = scanner.ParsePE(pe32);
    ASSERT_TRUE(pe32Info.has_value());
    EXPECT_TRUE(pe32Info->valid);
    EXPECT_EQ(pe32Info->machine, 0x014Cu);
    EXPECT_EQ(pe32Info->entryPoint, 0x1000u);
    EXPECT_EQ(pe32Info->imageBase, 0x00400000u);
    EXPECT_EQ(pe32Info->imageSize, 0x5000u);

    const auto pe64Info = scanner.ParsePE(pe64);
    ASSERT_TRUE(pe64Info.has_value());
    EXPECT_TRUE(pe64Info->valid);
    EXPECT_EQ(pe64Info->machine, 0x8664u);
    EXPECT_EQ(pe64Info->entryPoint, 0x2000u);
    EXPECT_EQ(pe64Info->imageBase, 0x0000000140000000ULL);
    EXPECT_EQ(pe64Info->imageSize, 0x9000u);
}

TEST_F(MemoryScannerValueTest, ContainsPEAndParsePERejectTruncatedAndCorruptImages) {
    auto& scanner = MemoryScanner::Instance();

    const std::vector<uint8_t> truncated(63, 0x00);
    EXPECT_FALSE(scanner.ContainsPE(truncated));
    EXPECT_FALSE(scanner.ParsePE(truncated).has_value());

    auto invalidNtSignature = BuildMinimalPE32();
    invalidNtSignature[0x80 + 0] = 'P';
    invalidNtSignature[0x80 + 1] = 'X';
    EXPECT_FALSE(scanner.ContainsPE(invalidNtSignature));
    EXPECT_FALSE(scanner.ParsePE(invalidNtSignature).has_value());

    auto invalidOptionalMagic = BuildMinimalPE32();
    const uint16_t badMagic = 0x0137;
    std::memcpy(invalidOptionalMagic.data() + 0x80 + 24, &badMagic, sizeof(badMagic));
    EXPECT_TRUE(scanner.ContainsPE(invalidOptionalMagic));
    EXPECT_FALSE(scanner.ParsePE(invalidOptionalMagic).has_value());
}

TEST_F(MemoryScannerValueTest, ContainsPEAndParsePERejectInvalidOffsetsAndTruncatedPE64Headers) {
    auto& scanner = MemoryScanner::Instance();

    std::vector<uint8_t> invalidOffset(0x80, 0x00);
    invalidOffset[0] = 'M';
    invalidOffset[1] = 'Z';
    const uint32_t badOffset = 0x20;
    std::memcpy(invalidOffset.data() + 0x3C, &badOffset, sizeof(badOffset));
    invalidOffset[badOffset + 0] = 'P';
    invalidOffset[badOffset + 1] = 'E';

    EXPECT_FALSE(scanner.ContainsPE(invalidOffset));
    EXPECT_FALSE(scanner.ParsePE(invalidOffset).has_value());

    auto truncatedPe64 = BuildMinimalPE64();
    truncatedPe64.resize(0x90 + 24 + 111);

    EXPECT_TRUE(scanner.ContainsPE(truncatedPe64));
    EXPECT_FALSE(scanner.ParsePE(truncatedPe64).has_value());
}

TEST_F(MemoryScannerValueTest, AnalyzeForShellcodeFlagsCompoundIndicatorsAndConfidenceCap) {
    auto& scanner = MemoryScanner::Instance();

    std::vector<uint8_t> shellcode(16, 0x90);
    const std::array<uint8_t, 6> getPc{ 0xE8, 0x00, 0x00, 0x00, 0x00, 0x58 };
    const std::array<uint8_t, 3> apiHash{ 0xC1, 0xC8, 0x0D };
    const std::array<uint8_t, 2> syscall{ 0x0F, 0x05 };
    const std::array<uint8_t, 7> leaRip{ 0x48, 0x8D, 0x05, 0x00, 0x00, 0x00, 0x00 };

    shellcode.insert(shellcode.end(), getPc.begin(), getPc.end());
    shellcode.insert(shellcode.end(), apiHash.begin(), apiHash.end());
    shellcode.insert(shellcode.end(), syscall.begin(), syscall.end());
    shellcode.insert(shellcode.end(), leaRip.begin(), leaRip.end());

    const auto analysis = scanner.AnalyzeForShellcode(shellcode);

    EXPECT_TRUE(analysis.isShellcode);
    EXPECT_TRUE(analysis.hasNOPSled);
    EXPECT_TRUE(analysis.hasGetPC);
    EXPECT_TRUE(analysis.hasAPIHashing);
    EXPECT_TRUE(analysis.hasSyscallStubs);
    EXPECT_EQ(analysis.nopSledLength, 16u);
    EXPECT_EQ(analysis.apiHashAlgorithm, "ROL/ROR");
    EXPECT_EQ(analysis.architecture, "x64");
    EXPECT_DOUBLE_EQ(analysis.confidence, 90.0);
}

TEST_F(MemoryScannerValueTest, AnalyzeForShellcodeKeepsExactBoundarySignalsBelowShellcodeThreshold) {
    auto& scanner = MemoryScanner::Instance();
    const std::vector<uint8_t> boundaryNopSled(16, 0x90);

    const auto analysis = scanner.AnalyzeForShellcode(boundaryNopSled);

    EXPECT_FALSE(analysis.isShellcode);
    EXPECT_TRUE(analysis.hasNOPSled);
    EXPECT_FALSE(analysis.hasGetPC);
    EXPECT_FALSE(analysis.hasAPIHashing);
    EXPECT_FALSE(analysis.hasSyscallStubs);
    EXPECT_EQ(analysis.nopSledLength, 16u);
    EXPECT_EQ(analysis.architecture, "x86");
    EXPECT_DOUBLE_EQ(analysis.confidence, 0.0);
}

TEST_F(MemoryScannerValueTest, AnalyzeForShellcodeRejectsBuffersBelowMinimumSize) {
    auto& scanner = MemoryScanner::Instance();
    const std::vector<uint8_t> tiny(8, 0x90);

    const auto analysis = scanner.AnalyzeForShellcode(tiny);

    EXPECT_FALSE(analysis.isShellcode);
    EXPECT_FALSE(analysis.hasNOPSled);
    EXPECT_FALSE(analysis.hasGetPC);
    EXPECT_DOUBLE_EQ(analysis.confidence, 0.0);
    EXPECT_TRUE(analysis.architecture.empty());
}

TEST_F(MemoryScannerValueTest, CheckAPIHashingMatchesKnownRotationLoopsOnly) {
    auto& scanner = MemoryScanner::Instance();
    const std::vector<uint8_t> hashingCode{ 0x55, 0x8B, 0xEC, 0xC1, 0xC8, 0x0D, 0x5D, 0xC3 };
    const std::vector<uint8_t> ordinaryCode{ 0x55, 0x8B, 0xEC, 0x8B, 0x45, 0x08, 0x5D, 0xC3 };

    EXPECT_TRUE(scanner.CheckAPIHashing(hashingCode));
    EXPECT_FALSE(scanner.CheckAPIHashing(ordinaryCode));
}

}  // namespace
