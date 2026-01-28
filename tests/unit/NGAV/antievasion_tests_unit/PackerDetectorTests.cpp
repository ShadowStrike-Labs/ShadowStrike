#include <gtest/gtest.h>
#include <vector>
#include <memory>
#include <random>
#include "../../src/AntiEvasion/PackerDetector.hpp"

using namespace ShadowStrike::AntiEvasion;

class PackerDetectorTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Initialize random seed
        srand(static_cast<unsigned int>(time(nullptr)));
    }

    void TearDown() override {
    }
};

// Helper to create a minimal DOS+NT header
// RVA 0x1000 maps to Raw 0x400
std::vector<uint8_t> CreateMinimalPE() {
    std::vector<uint8_t> pe(4096, 0); // 4KB buffer

    // DOS Header
    IMAGE_DOS_HEADER* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(pe.data());
    dos->e_magic = IMAGE_DOS_SIGNATURE; // MZ
    dos->e_lfanew = sizeof(IMAGE_DOS_HEADER);

    // NT Headers
    IMAGE_NT_HEADERS* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(pe.data() + dos->e_lfanew);
    nt->Signature = IMAGE_NT_SIGNATURE; // PE\0\0
    nt->FileHeader.Machine = IMAGE_FILE_MACHINE_AMD64;
    nt->FileHeader.NumberOfSections = 1;
    nt->FileHeader.SizeOfOptionalHeader = sizeof(IMAGE_OPTIONAL_HEADER64);
    nt->FileHeader.Characteristics = IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_LARGE_ADDRESS_AWARE;

    nt->OptionalHeader.Magic = IMAGE_NT_OPTIONAL_HDR64_MAGIC;
    nt->OptionalHeader.AddressOfEntryPoint = 0x1000;
    nt->OptionalHeader.ImageBase = 0x140000000;
    nt->OptionalHeader.SectionAlignment = 0x1000;
    nt->OptionalHeader.FileAlignment = 0x200;

    // Section Header
    IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(nt);
    memcpy(sec->Name, ".text", 5);
    sec->VirtualAddress = 0x1000;
    sec->Misc.VirtualSize = 0x200;
    sec->PointerToRawData = 0x400;
    sec->SizeOfRawData = 0x200;
    sec->Characteristics = IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ;

    return pe;
}

TEST_F(PackerDetectorTest, Initialization) {
    PackerDetector detector;
    PackerError err;
    EXPECT_TRUE(detector.Initialize(&err));
    EXPECT_TRUE(detector.IsInitialized());
}

TEST_F(PackerDetectorTest, CalculateEntropyLow) {
    PackerDetector detector;
    std::vector<uint8_t> zeroBuffer(1000, 0);
    double entropy = detector.CalculateEntropy(zeroBuffer.data(), zeroBuffer.size());
    EXPECT_NEAR(entropy, 0.0, 0.01);
}

TEST_F(PackerDetectorTest, CalculateEntropyHigh) {
    PackerDetector detector;
    std::vector<uint8_t> randBuffer(1000);
    // Fill with uniform distribution for max entropy
    for(size_t i=0; i<randBuffer.size(); ++i) randBuffer[i] = static_cast<uint8_t>(i % 256);

    double entropy = detector.CalculateEntropy(randBuffer.data(), randBuffer.size());
    // Max entropy for 256 symbols is 8.0
    EXPECT_GT(entropy, 7.5);
}

TEST_F(PackerDetectorTest, AnalyzeMinimalPE) {
    PackerDetector detector;
    detector.Initialize();

    auto pe = CreateMinimalPE();
    PackerAnalysisConfig config;
    config.flags = PackerAnalysisFlags::EnableSectionAnalysis | PackerAnalysisFlags::EnableEntropyAnalysis;

    auto result = detector.AnalyzeBuffer(pe.data(), pe.size(), config, nullptr);

    EXPECT_TRUE(result.analysisComplete);
    EXPECT_EQ(result.sectionCount, 1);
    EXPECT_FALSE(result.isPacked); // Should be clean
}

TEST_F(PackerDetectorTest, DetectUPXSignature) {
    PackerDetector detector;
    detector.Initialize();

    // UPX signature: 60 E8 ?? ?? ?? ?? (PUSHAD; CALL)
    // We need to place this at the EntryPoint to trigger EP signature match.
    // In our mock PE, EP is at RVA 0x1000, which maps to Offset 0x400.
    auto pe = CreateMinimalPE();

    size_t epOffset = 0x400;

    // Write UPX stub
    if (epOffset + 10 < pe.size()) {
        pe[epOffset] = 0x60;     // PUSHAD
        pe[epOffset + 1] = 0xE8; // CALL
        pe[epOffset + 2] = 0x05; // relative offset
        pe[epOffset + 3] = 0x00;
        pe[epOffset + 4] = 0x00;
        pe[epOffset + 5] = 0x00;
    }

    PackerAnalysisConfig config;
    config.flags = PackerAnalysisFlags::EnableEPSignature;

    auto result = detector.AnalyzeBuffer(pe.data(), pe.size(), config, nullptr);

    // We expect a match
    bool foundUPX = false;
    for(const auto& match : result.packerMatches) {
        if (match.packerType == PackerType::UPX) {
            foundUPX = true;
            break;
        }
    }

    EXPECT_TRUE(foundUPX) << "Failed to detect UPX signature at EntryPoint";
    EXPECT_GT(result.packingConfidence, 0.5);
}

TEST_F(PackerDetectorTest, DetectHighEntropySection) {
    PackerDetector detector;
    detector.Initialize();

    auto pe = CreateMinimalPE();

    // Fill the section data (offset 0x400) with random noise to simulate packing/encryption
    size_t dataOffset = 0x400;
    size_t dataSize = 0x200;

    // Use high quality randomness for entropy
    std::mt19937 gen(12345);
    std::uniform_int_distribution<> dis(0, 255);

    for(size_t i=0; i<dataSize; ++i) {
        pe[dataOffset + i] = static_cast<uint8_t>(dis(gen));
    }

    PackerAnalysisConfig config;
    config.flags = PackerAnalysisFlags::EnableSectionAnalysis | PackerAnalysisFlags::EnableEntropyAnalysis;

    auto result = detector.AnalyzeBuffer(pe.data(), pe.size(), config, nullptr);

    EXPECT_GT(result.highEntropySectionCount, 0);
    EXPECT_GT(result.fileEntropy, 6.0);
}

TEST_F(PackerDetectorTest, DetectSectionName) {
    PackerDetector detector;
    detector.Initialize();

    auto pe = CreateMinimalPE();

    // Rename section to "UPX1"
    IMAGE_DOS_HEADER* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(pe.data());
    IMAGE_NT_HEADERS* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(pe.data() + dos->e_lfanew);
    IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(nt);
    memset(sec->Name, 0, 8);
    memcpy(sec->Name, "UPX1", 4);

    PackerAnalysisConfig config;
    config.flags = PackerAnalysisFlags::EnableSectionAnalysis;

    auto result = detector.AnalyzeBuffer(pe.data(), pe.size(), config, nullptr);

    bool foundUPXSection = false;
    for(const auto& section : result.sections) {
        if (section.isPackerSection && section.matchedPackerName.find("upx") != std::string::npos) {
            foundUPXSection = true;
            break;
        }
    }

    EXPECT_TRUE(foundUPXSection) << "Failed to detect known packer section name UPX1";
}

TEST_F(PackerDetectorTest, DetectWritableExecutableSection) {
    PackerDetector detector;
    detector.Initialize();

    auto pe = CreateMinimalPE();

    // Make section RWE (Read-Write-Execute)
    IMAGE_DOS_HEADER* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(pe.data());
    IMAGE_NT_HEADERS* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(pe.data() + dos->e_lfanew);
    IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(nt);
    sec->Characteristics = IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;

    PackerAnalysisConfig config;
    config.flags = PackerAnalysisFlags::EnableSectionAnalysis;

    auto result = detector.AnalyzeBuffer(pe.data(), pe.size(), config, nullptr);

    EXPECT_TRUE(result.hasWritableCodeSections);
    ASSERT_FALSE(result.sections.empty());

    bool foundAnomaly = false;
    for(const auto& s : result.sections[0].anomalies) {
        if (s.find(L"Writable") != std::wstring::npos) foundAnomaly = true;
    }
    EXPECT_TRUE(foundAnomaly);
}
