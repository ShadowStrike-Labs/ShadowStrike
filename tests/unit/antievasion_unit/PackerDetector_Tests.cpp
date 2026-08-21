/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 */

#include "pch.h"

#include <gtest/gtest.h>

#include "../../../src/PhantomCore/AntiEvasion/PackerDetector.hpp"

namespace ShadowStrike::AntiEvasion::Tests {

TEST(PackerDetector_Helpers, CategoryAndTypeStringMappingsRemainStable) {
    EXPECT_STREQ("Compression Packer", PackerCategoryToString(PackerCategory::Compression));
    EXPECT_STREQ("VM Protection", PackerCategoryToString(PackerCategory::VMProtection));
    EXPECT_STREQ("Unknown", PackerCategoryToString(static_cast<PackerCategory>(0xFF)));

    EXPECT_STREQ(L"UPX", PackerTypeToString(PackerType::UPX));
    EXPECT_STREQ(L"Themida", PackerTypeToString(PackerType::Themida));
    EXPECT_STREQ(L"VMProtect", PackerTypeToString(PackerType::VMProtect));
    EXPECT_STREQ(L"Custom Packer", PackerTypeToString(PackerType::Custom_Packer));
    EXPECT_STREQ(L"Unknown", PackerTypeToString(static_cast<PackerType>(0xFFFF)));
}

TEST(PackerDetector_Entropy, CalculateEntropyHandlesNullUniformAndHighEntropyBuffers) {
    std::vector<uint8_t> zeros(1024, 0x00);
    std::vector<uint8_t> alternating(1024);
    for (size_t i = 0; i < alternating.size(); ++i) {
        alternating[i] = static_cast<uint8_t>(i % 2 == 0 ? 0x00 : 0xFF);
    }

    std::vector<uint8_t> fullRange(256);
    for (size_t i = 0; i < fullRange.size(); ++i) {
        fullRange[i] = static_cast<uint8_t>(i);
    }

    EXPECT_DOUBLE_EQ(0.0, PackerDetector::CalculateEntropy(nullptr, 0));
    EXPECT_NEAR(0.0, PackerDetector::CalculateEntropy(zeros.data(), zeros.size()), 1e-9);
    EXPECT_NEAR(1.0, PackerDetector::CalculateEntropy(alternating.data(), alternating.size()), 0.05);
    EXPECT_NEAR(8.0, PackerDetector::CalculateEntropy(fullRange.data(), fullRange.size()), 0.05);
}

TEST(PackerDetector_Builder, MatchBuilderPopulatesDerivedMetadata) {
    const auto match = PackerMatchBuilder{}
        .Type(PackerType::VMProtect)
        .Method(DetectionMethod::EPSignature)
        .Confidence(0.99)
        .Name(L"VMProtect")
        .Version(L"3.x")
        .Pattern(L"vmprotect ep stub")
        .Location(0x420)
        .Details(L"Commercial virtualization protector stub detected")
        .Build();

    EXPECT_EQ(PackerType::VMProtect, match.packerType);
    EXPECT_EQ(GetPackerCategory(PackerType::VMProtect), match.category);
    EXPECT_EQ(GetPackerSeverity(PackerType::VMProtect), match.severity);
    EXPECT_STREQ(PackerTypeToMitreId(PackerType::VMProtect), match.mitreId.c_str());
    EXPECT_EQ(DetectionMethod::EPSignature, match.method);
    EXPECT_DOUBLE_EQ(0.99, match.confidence);
    EXPECT_EQ(L"VMProtect", match.packerName);
    EXPECT_EQ(L"3.x", match.version);
    EXPECT_EQ(L"vmprotect ep stub", match.matchedPattern);
    EXPECT_EQ(0x420u, match.matchLocation);
    EXPECT_EQ(L"Commercial virtualization protector stub detected", match.details);
}

TEST(PackerDetector_ResultHelpers, MatchQueriesAndClearResetAllEntropyMetrics) {
    PackingInfo info;
    info.filePath = L"C:\\Temp\\packed.exe";
    info.fileSize = 8192;
    info.sha256Hash = "abc123";
    info.isPacked = true;
    info.packingConfidence = 0.97;
    info.primaryPacker = PackerType::VMProtect;
    info.packerName = L"VMProtect";
    info.packerVersion = L"3.x";
    info.packerCategory = PackerCategory::VMProtection;
    info.severity = PackerSeverity::Critical;
    info.packerMatches = {
        PackerMatchBuilder{}.Type(PackerType::UPX).Confidence(0.66).Build(),
        PackerMatchBuilder{}.Type(PackerType::VMProtect).Confidence(0.98).Build()
    };
    info.fileEntropy = 7.9;
    info.chiSquared = 3.14;
    info.monteCarloPiError = 0.42;
    info.codeSectionEntropy = 7.1;
    info.dataSectionEntropy = 7.8;
    info.maxSectionEntropy = 8.0;
    info.maxEntropySectionName = ".vmp0";
    info.averageSectionEntropy = 7.45;
    info.entropyIndicatesCompression = true;
    info.entropyIndicatesEncryption = true;
    info.analysisComplete = true;
    info.fromCache = true;

    EXPECT_TRUE(info.HasMatch(PackerType::UPX));
    // VMProtect (110) falls in 101-200 range → PackerCategory::Protector
    EXPECT_TRUE(info.HasCategory(PackerCategory::Protector));
    EXPECT_FALSE(info.HasMatch(PackerType::Themida));
    EXPECT_FALSE(info.HasCategory(PackerCategory::Crypter));
    ASSERT_NE(nullptr, info.GetBestMatch());
    EXPECT_EQ(PackerType::VMProtect, info.GetBestMatch()->packerType);

    info.Clear();

    EXPECT_TRUE(info.filePath.empty());
    EXPECT_EQ(0u, info.fileSize);
    EXPECT_TRUE(info.sha256Hash.empty());
    EXPECT_FALSE(info.isPacked);
    EXPECT_DOUBLE_EQ(0.0, info.packingConfidence);
    EXPECT_EQ(PackerType::Unknown, info.primaryPacker);
    EXPECT_TRUE(info.packerMatches.empty());
    EXPECT_DOUBLE_EQ(0.0, info.fileEntropy);
    EXPECT_DOUBLE_EQ(0.0, info.chiSquared);
    EXPECT_DOUBLE_EQ(0.0, info.monteCarloPiError);
    EXPECT_DOUBLE_EQ(0.0, info.codeSectionEntropy);
    EXPECT_DOUBLE_EQ(0.0, info.dataSectionEntropy);
    EXPECT_DOUBLE_EQ(0.0, info.maxSectionEntropy);
    EXPECT_TRUE(info.maxEntropySectionName.empty());
    EXPECT_DOUBLE_EQ(0.0, info.averageSectionEntropy);
    EXPECT_FALSE(info.entropyIndicatesCompression);
    EXPECT_FALSE(info.entropyIndicatesEncryption);
    EXPECT_FALSE(info.analysisComplete);
    EXPECT_FALSE(info.fromCache);
    EXPECT_EQ(nullptr, info.GetBestMatch());
}

TEST(PackerDetector_Statistics, ResetClearsCounters) {
    PackerDetector::Statistics stats;
    stats.totalAnalyses = 8;
    stats.packedFilesDetected = 6;
    stats.installersDetected = 1;
    stats.cryptersDetected = 2;
    stats.protectorsDetected = 3;
    stats.cacheHits = 4;
    stats.cacheMisses = 5;
    stats.analysisErrors = 1;
    stats.totalAnalysisTimeUs = 9000;
    stats.bytesAnalyzed = 4096;
    stats.categoryDetections[static_cast<size_t>(PackerCategory::Protector)] = 2;

    stats.Reset();

    EXPECT_EQ(0u, stats.totalAnalyses.load());
    EXPECT_EQ(0u, stats.packedFilesDetected.load());
    EXPECT_EQ(0u, stats.installersDetected.load());
    EXPECT_EQ(0u, stats.cryptersDetected.load());
    EXPECT_EQ(0u, stats.protectorsDetected.load());
    EXPECT_EQ(0u, stats.cacheHits.load());
    EXPECT_EQ(0u, stats.cacheMisses.load());
    EXPECT_EQ(0u, stats.analysisErrors.load());
    EXPECT_EQ(0u, stats.totalAnalysisTimeUs.load());
    EXPECT_EQ(0u, stats.bytesAnalyzed.load());

    for (const auto& categoryCounter : stats.categoryDetections) {
        EXPECT_EQ(0u, categoryCounter.load());
    }
}

// ============================================================================
// Hand-written assembly: ScanForAntiDebugOpcodes
//
// These exercise the routine in PackerDetector_x64.asm directly. It resolves to
// the assembly because the .asm is linked into PhantomCoreLib; /ALTERNATENAME
// substitutes Fallback_ScanForAntiDebugOpcodes only where the .asm is absent.
// Either implementation must satisfy every assertion below, which is the point -
// the contract is the same on both paths.
//
// The flag bits are fixed by the assembly (or r15d, <bit>) and are asserted here
// so that changing one without changing the other cannot pass silently.
// ============================================================================

namespace {

constexpr uint32_t kFlagInt2Dh = 0x01u;
constexpr uint32_t kFlagInt3   = 0x02u;
constexpr uint32_t kFlagRdtsc  = 0x04u;
constexpr uint32_t kFlagCpuid  = 0x08u;
constexpr uint32_t kFlagRdtscp = 0x10u;

} // namespace

TEST(PackerDetector_AsmAntiDebugScan, EachTechniqueSetsItsOwnFlagAndIsCounted) {
    struct Case final {
        std::vector<uint8_t> bytes;
        uint32_t             expectedFlag;
        const char*          what;
    };

    const std::vector<Case> cases = {
        { { 0xCD, 0x2D },       kFlagInt2Dh, "INT 2Dh"  },
        { { 0xCC },             kFlagInt3,   "INT3"     },
        { { 0x0F, 0x31 },       kFlagRdtsc,  "RDTSC"    },
        { { 0x0F, 0xA2 },       kFlagCpuid,  "CPUID"    },
        { { 0x0F, 0x01, 0xF9 }, kFlagRdtscp, "RDTSCP"   },
    };

    for (const Case& c : cases) {
        uint32_t flags = 0xDEADBEEFu;   // poisoned, so a routine that never writes is caught
        const uint64_t hits = ScanForAntiDebugOpcodes(c.bytes.data(), c.bytes.size(), &flags);

        EXPECT_EQ(1u, hits) << "expected exactly one match for " << c.what;
        EXPECT_EQ(c.expectedFlag, flags) << "wrong flag bit for " << c.what;
    }
}

TEST(PackerDetector_AsmAntiDebugScan, MultipleTechniquesAccumulateIntoOneMask) {
    // INT3, RDTSC, CPUID and INT 2Dh in one buffer, separated by NOPs.
    const std::vector<uint8_t> buffer = {
        0x90, 0xCC, 0x90, 0x0F, 0x31, 0x90, 0x0F, 0xA2, 0x90, 0xCD, 0x2D, 0x90
    };

    uint32_t flags = 0;
    const uint64_t hits = ScanForAntiDebugOpcodes(buffer.data(), buffer.size(), &flags);

    EXPECT_EQ(4u, hits);
    EXPECT_EQ(kFlagInt3 | kFlagRdtsc | kFlagCpuid | kFlagInt2Dh, flags);
    EXPECT_EQ(0u, flags & kFlagRdtscp) << "RDTSCP is absent from this buffer";
}

TEST(PackerDetector_AsmAntiDebugScan, BenignBufferProducesNoFindings) {
    // A run of NOPs plus printable ASCII: nothing here is an anti-analysis opcode.
    std::vector<uint8_t> buffer(512, 0x90);
    for (size_t i = 0; i < 64; ++i) {
        buffer[i] = static_cast<uint8_t>('A' + (i % 26));
    }

    uint32_t flags = 0xFFFFFFFFu;
    const uint64_t hits = ScanForAntiDebugOpcodes(buffer.data(), buffer.size(), &flags);

    EXPECT_EQ(0u, hits);
    EXPECT_EQ(0u, flags) << "the routine must zero the mask when it finds nothing, "
                            "otherwise a caller sees stale flags as real findings";
}

TEST(PackerDetector_AsmAntiDebugScan, TruncatedSequencesAtTheBufferEndAreNotReadPastTheEnd) {
    // Each of these ends with a prefix whose completing byte lies OUTSIDE the buffer.
    // The routine must decline to match rather than read the following byte. A failure
    // here is an out-of-bounds read on attacker-supplied file content, so these are
    // memory-safety assertions, not merely accuracy ones.
    const std::vector<std::vector<uint8_t>> truncated = {
        { 0x90, 0xCD },              // INT prefix, opcode byte missing
        { 0x90, 0x0F },              // two-byte escape, second byte missing
        { 0x90, 0x0F, 0x01 },        // RDTSCP prefix, final 0xF9 missing
    };

    for (const std::vector<uint8_t>& bytes : truncated) {
        uint32_t flags = 0xABCDEF01u;
        const uint64_t hits = ScanForAntiDebugOpcodes(bytes.data(), bytes.size(), &flags);

        EXPECT_EQ(0u, hits) << "a truncated sequence must not be reported as a match";
        EXPECT_EQ(0u, flags);
    }
}

TEST(PackerDetector_AsmAntiDebugScan, RejectsInvalidInputWithoutTouchingMemory) {
    uint32_t flags = 0x5A5A5A5Au;
    EXPECT_EQ(0u, ScanForAntiDebugOpcodes(nullptr, 64, &flags));
    EXPECT_EQ(0u, flags) << "the mask must be cleared on the failure path";

    const std::vector<uint8_t> buffer = { 0xCC, 0xCC, 0xCC };
    flags = 0x5A5A5A5Au;
    EXPECT_EQ(0u, ScanForAntiDebugOpcodes(buffer.data(), 0, &flags));
    EXPECT_EQ(0u, flags);

    // The flags pointer is optional and NULL-checked by the routine; passing null must
    // still return the count rather than faulting.
    EXPECT_EQ(3u, ScanForAntiDebugOpcodes(buffer.data(), buffer.size(), nullptr));
}

TEST(PackerDetector_AsmOpcodeLocators, ReturnTheOffsetOfTheFirstMatchOrMinusOne) {
    // Each locator returns the index of the FIRST byte of the sequence, or -1.
    const std::vector<uint8_t> int2d  = { 0x90, 0x90, 0xCD, 0x2D };
    const std::vector<uint8_t> rdtsc  = { 0x90, 0x0F, 0x31 };
    const std::vector<uint8_t> cpuid  = { 0x0F, 0xA2, 0x90 };
    const std::vector<uint8_t> benign = { 0x90, 0x90, 0x90, 0x90 };

    EXPECT_EQ(2, ScanForInt2DOpcode(int2d.data(), int2d.size()));
    EXPECT_EQ(1, ScanForRDTSCOpcode(rdtsc.data(), rdtsc.size()));
    EXPECT_EQ(0, ScanForCPUIDOpcode(cpuid.data(), cpuid.size()));

    EXPECT_EQ(-1, ScanForInt2DOpcode(benign.data(), benign.size()));
    EXPECT_EQ(-1, ScanForRDTSCOpcode(benign.data(), benign.size()));
    EXPECT_EQ(-1, ScanForCPUIDOpcode(benign.data(), benign.size()));
}

TEST(PackerDetector_AsmOpcodeLocators, DeclineTruncatedSequencesAndInvalidInput) {
    // A lone prefix at the final byte must not be matched, because matching would mean
    // reading the byte after the buffer. Memory safety, not merely accuracy.
    const std::vector<uint8_t> trailingCd = { 0x90, 0xCD };
    const std::vector<uint8_t> trailing0f = { 0x90, 0x0F };
    const std::vector<uint8_t> singleCd   = { 0xCD };

    EXPECT_EQ(-1, ScanForInt2DOpcode(trailingCd.data(), trailingCd.size()));
    EXPECT_EQ(-1, ScanForRDTSCOpcode(trailing0f.data(), trailing0f.size()));
    EXPECT_EQ(-1, ScanForCPUIDOpcode(trailing0f.data(), trailing0f.size()));
    EXPECT_EQ(-1, ScanForInt2DOpcode(singleCd.data(), singleCd.size()));

    EXPECT_EQ(-1, ScanForInt2DOpcode(nullptr, 16));
    EXPECT_EQ(-1, ScanForRDTSCOpcode(trailingCd.data(), 0));
    EXPECT_EQ(-1, ScanForCPUIDOpcode(nullptr, 0));
}

TEST(PackerDetector_AsmSmcScan, CountsRepPrefixedStringOperations) {
    // F3 (REP) followed by A4/A5/AA/AB - MOVSB/MOVSW/STOSB/STOSW - is how an unpacker
    // stub writes decompressed bytes over its own code.
    const std::vector<std::vector<uint8_t>> singles = {
        { 0xF3, 0xA4 },   // REP MOVSB
        { 0xF3, 0xA5 },   // REP MOVSW/D
        { 0xF3, 0xAA },   // REP STOSB
        { 0xF3, 0xAB },   // REP STOSW/D
    };
    for (const std::vector<uint8_t>& bytes : singles) {
        EXPECT_EQ(1u, ScanForSMCPatterns(bytes.data(), bytes.size()))
            << "expected one REP string operation to be counted";
    }

    const std::vector<uint8_t> two = { 0xF3, 0xA4, 0x90, 0xF3, 0xAA, 0x90 };
    EXPECT_EQ(2u, ScanForSMCPatterns(two.data(), two.size()));
}

TEST(PackerDetector_AsmSmcScan, BareStringOpcodesWithoutRepAreDeliberatelyNotCounted) {
    // STOSB/STOSW without a REP prefix are ordinary instructions and appear throughout
    // compiler output. The assembly routes them to a non-counting branch on purpose, and
    // this test pins that choice: counting them would inflate the figure on clean code.
    const std::vector<uint8_t> bareStos = { 0x90, 0xAA, 0x90, 0xAB, 0x90 };
    EXPECT_EQ(0u, ScanForSMCPatterns(bareStos.data(), bareStos.size()));
}

TEST(PackerDetector_AsmSmcScan, HandlesTruncatedPrefixAndInvalidInput) {
    const std::vector<uint8_t> trailingRep = { 0x90, 0xF3 };   // REP with no string op
    EXPECT_EQ(0u, ScanForSMCPatterns(trailingRep.data(), trailingRep.size()));

    const std::vector<uint8_t> buffer = { 0xF3, 0xA4 };
    EXPECT_EQ(0u, ScanForSMCPatterns(nullptr, 16));
    EXPECT_EQ(0u, ScanForSMCPatterns(buffer.data(), 0));

    std::vector<uint8_t> benign(256, 0x90);
    EXPECT_EQ(0u, ScanForSMCPatterns(benign.data(), benign.size()));
}

} // namespace ShadowStrike::AntiEvasion::Tests
