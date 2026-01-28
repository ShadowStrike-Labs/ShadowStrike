/**
 * @file MetamorphicTests.cpp
 * @brief Enterprise-Grade Unit Tests for MetamorphicDetector
 *
 * COVERAGE:
 * - Lifecycle: Init, Shutdown, Idempotency
 * - Entropy Analysis: Shannon entropy verification
 * - Opcode Analysis: Histogram, NOP sleds, Junk code
 * - Polymorphic Detection: Decryption loops, GetPC patterns
 * - Control Flow: LDE-based CFG analysis, flattening detection
 * - PE Structure: Header parsing, section analysis
 * - Process Memory: RWX detection, self-modifying code
 * - Concurrency: Thread-safe stress testing
 * - Error Handling: Invalid inputs, resource limits
 *
 * Copyright (c) 2026 ShadowStrike Security Suite
 */

#include "pch.h"
#include <gtest/gtest.h>
#include "../../../../src/AntiEvasion/MetamorphicDetector.hpp"
#include <vector>
#include <random>
#include <numeric>
#include <filesystem>
#include <fstream>
#include <thread>
#include <future>

using namespace ShadowStrike::AntiEvasion;
namespace fs = std::filesystem;

class MetamorphicTestFixture : public ::testing::Test {
protected:
    std::wstring m_tempDir;
    std::wstring m_tempFile;

    void SetUp() override {
        // Create temp directory for file tests
        auto tempPath = fs::temp_directory_path() / "ShadowStrike_MetaTests";
        if (!fs::exists(tempPath)) {
            fs::create_directories(tempPath);
        }
        m_tempDir = tempPath.wstring();
        m_tempFile = (tempPath / "test_sample.bin").wstring();
    }

    void TearDown() override {
        // Cleanup
        if (fs::exists(m_tempDir)) {
            fs::remove_all(m_tempDir);
        }
    }

    // Helper: Create a dummy file with specific content
    void CreateTestFile(const std::vector<uint8_t>& content) {
        std::ofstream file(m_tempFile, std::ios::binary);
        file.write(reinterpret_cast<const char*>(content.data()), content.size());
        file.close();
    }

    // Helper: Generate random high-entropy buffer
    std::vector<uint8_t> GenerateHighEntropyData(size_t size) {
        std::vector<uint8_t> data(size);
        std::mt19937 gen(42); // Fixed seed for reproducibility
        std::uniform_int_distribution<> dis(0, 255);
        for (auto& b : data) b = static_cast<uint8_t>(dis(gen));
        return data;
    }

    // Helper: Generate low-entropy buffer (repeating)
    std::vector<uint8_t> GenerateLowEntropyData(size_t size) {
        return std::vector<uint8_t>(size, 0xAA);
    }
};

// ============================================================================
// 1. LIFECYCLE TESTS
// ============================================================================

TEST_F(MetamorphicTestFixture, Lifecycle_Initialization) {
    MetamorphicDetector detector;
    EXPECT_FALSE(detector.IsInitialized());

    MetamorphicError err;
    EXPECT_TRUE(detector.Initialize(&err));
    EXPECT_TRUE(detector.IsInitialized());
    EXPECT_FALSE(err.HasError());
}

TEST_F(MetamorphicTestFixture, Lifecycle_DoubleInit) {
    MetamorphicDetector detector;
    EXPECT_TRUE(detector.Initialize());
    EXPECT_TRUE(detector.Initialize()); // Should be idempotent
}

TEST_F(MetamorphicTestFixture, Lifecycle_Shutdown) {
    MetamorphicDetector detector;
    detector.Initialize();
    detector.Shutdown();
    EXPECT_FALSE(detector.IsInitialized());
}

// ============================================================================
// 2. ENTROPY & HISTOGRAM TESTS
// ============================================================================

TEST_F(MetamorphicTestFixture, Analysis_EntropyCalculation) {
    MetamorphicDetector detector;
    detector.Initialize();

    // High entropy
    auto highEntropy = GenerateHighEntropyData(1024);
    double e1 = detector.CalculateEntropy(highEntropy.data(), highEntropy.size());
    EXPECT_GT(e1, 7.0); // Random byte distribution should be close to 8.0

    // Low entropy
    auto lowEntropy = GenerateLowEntropyData(1024);
    double e2 = detector.CalculateEntropy(lowEntropy.data(), lowEntropy.size());
    EXPECT_LT(e2, 1.0); // Homogeneous data should be near 0.0
}

TEST_F(MetamorphicTestFixture, Analysis_OpcodeHistogram_NopSled) {
    MetamorphicDetector detector;
    detector.Initialize();

    // Create a NOP sled (0x90)
    std::vector<uint8_t> buffer(100, 0x90);
    // Add some shellcode-like bytes at the end
    buffer.push_back(0xCC);
    buffer.push_back(0xC3);

    OpcodeHistogram hist;
    EXPECT_TRUE(detector.ComputeOpcodeHistogram(buffer.data(), buffer.size(), hist));

    EXPECT_TRUE(hist.valid);
    EXPECT_GT(hist.nopPercentage, 90.0);
    EXPECT_TRUE(hist.hasExcessiveNops);
}

// ============================================================================
// 3. POLYMORPHIC PATTERN TESTS
// ============================================================================

TEST_F(MetamorphicTestFixture, Detection_DecryptionLoop_XOR) {
    MetamorphicDetector detector;
    detector.Initialize();

    // Simple XOR loop pattern:
    // XOR EAX, EAX     (31 C0)
    // INC EAX          (40)
    // LOOP -3          (E2 FD)
    std::vector<uint8_t> buffer = {
        0x90, 0x90,             // Padding
        0x31, 0xC0,             // XOR EAX, EAX
        0x40,                   // INC EAX
        0xE2, 0xFD,             // LOOP -3 (back to INC)
        0x90, 0x90
    };

    std::vector<DecryptionLoopInfo> loops;
    EXPECT_TRUE(detector.DetectDecryptionLoops(buffer.data(), buffer.size(), loops));

    ASSERT_FALSE(loops.empty());
    EXPECT_TRUE(loops[0].usesXOR);
    EXPECT_TRUE(loops[0].valid);
}

TEST_F(MetamorphicTestFixture, Detection_GetPC_CallPop) {
    MetamorphicDetector detector;
    detector.Initialize();

    // CALL $+5 (E8 00 00 00 00) followed by POP REG (58 = EAX)
    std::vector<uint8_t> buffer = {
        0x90, 0x90,
        0xE8, 0x00, 0x00, 0x00, 0x00, // CALL next instruction
        0x58,                         // POP EAX
        0x90
    };

    std::vector<DecryptionLoopInfo> loops;
    EXPECT_TRUE(detector.DetectDecryptionLoops(buffer.data(), buffer.size(), loops));

    ASSERT_FALSE(loops.empty());
    EXPECT_TRUE(loops[0].usesGetPC);
    EXPECT_EQ(loops[0].getPCMethod, L"CALL/POP");
}

// ============================================================================
// 4. CONTROL FLOW & LDE TESTS
// ============================================================================

TEST_F(MetamorphicTestFixture, Analysis_CFG_Heuristic) {
    MetamorphicDetector detector;
    detector.Initialize();

    // Construct a buffer with many relative jumps to simulate spaghetti code
    std::vector<uint8_t> buffer;
    for(int i=0; i<50; i++) {
        buffer.push_back(0xE9); // JMP rel32
        buffer.push_back(0x10); buffer.push_back(0x00); buffer.push_back(0x00); buffer.push_back(0x00);
        buffer.push_back(0x90);
    }

    CFGAnalysisInfo info;
    EXPECT_TRUE(detector.AnalyzeCFG(buffer.data(), buffer.size(), 0x1000, info));

    // High branch density expected
    EXPECT_GT(info.branchDensity, 0.5);
}

// ============================================================================
// 5. PE STRUCTURE TESTS
// ============================================================================

TEST_F(MetamorphicTestFixture, Analysis_PE_Header) {
    MetamorphicDetector detector;
    detector.Initialize();

    // Minimal valid DOS+PE Header construction
    std::vector<uint8_t> peBuffer(1024, 0);

    // DOS Header
    IMAGE_DOS_HEADER* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(peBuffer.data());
    dos->e_magic = IMAGE_DOS_SIGNATURE; // MZ
    dos->e_lfanew = sizeof(IMAGE_DOS_HEADER);

    // NT Header
    IMAGE_NT_HEADERS64* nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(peBuffer.data() + dos->e_lfanew);
    nt->Signature = IMAGE_NT_SIGNATURE; // PE\0\0
    nt->FileHeader.Machine = IMAGE_FILE_MACHINE_AMD64;
    nt->FileHeader.NumberOfSections = 1;
    nt->OptionalHeader.Magic = IMAGE_NT_OPTIONAL_HDR64_MAGIC;
    nt->OptionalHeader.AddressOfEntryPoint = 0x1000;

    // Section Header
    IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(nt);
    memcpy(sec->Name, ".text", 5);
    sec->VirtualAddress = 0x1000;
    sec->Misc.VirtualSize = 0x200;
    sec->Characteristics = IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_CNT_CODE;

    CreateTestFile(peBuffer);

    PEAnalysisInfo info;
    EXPECT_TRUE(detector.AnalyzePEStructure(m_tempFile, info));
    EXPECT_TRUE(info.valid);
    EXPECT_TRUE(info.is64Bit);
    EXPECT_EQ(info.entryPointRVA, 0x1000);
    ASSERT_EQ(info.sections.size(), 1);
    EXPECT_EQ(info.sections[0].name, ".text");
}

// ============================================================================
// 6. PROCESS MEMORY TESTS
// ============================================================================

TEST_F(MetamorphicTestFixture, Process_AnalyzeSelf) {
    MetamorphicDetector detector;
    detector.Initialize();

    // Analyze current process
    // Should pass without error, though unlikely to find malware in the test runner
    MetamorphicAnalysisConfig config;
    config.depth = MetamorphicAnalysisDepth::Quick;

    auto result = detector.AnalyzeProcess(::GetCurrentProcessId(), config);

    EXPECT_TRUE(result.analysisComplete);
    EXPECT_EQ(result.processId, ::GetCurrentProcessId());
}

TEST_F(MetamorphicTestFixture, Process_InvalidPID) {
    MetamorphicDetector detector;
    detector.Initialize();

    // PID 0 or huge PID
    MetamorphicError err;
    auto result = detector.AnalyzeProcess(999999, {}, &err); // Assuming this PID doesn't exist

    EXPECT_FALSE(result.analysisComplete);
    EXPECT_TRUE(err.HasError()); // Process open failed
}

// ============================================================================
// 7. FULL ANALYSIS INTEGRATION
// ============================================================================

TEST_F(MetamorphicTestFixture, Integration_AnalyzeBuffer_Metamorphic) {
    MetamorphicDetector detector;
    detector.Initialize();

    // Construct a "malicious" buffer combining multiple techniques
    std::vector<uint8_t> buffer;

    // 1. NOP Sled
    for(int i=0; i<20; i++) buffer.push_back(0x90);

    // 2. Decryption Loop (XOR)
    uint8_t loop[] = { 0x31, 0xC0, 0x40, 0xE2, 0xFD };
    buffer.insert(buffer.end(), std::begin(loop), std::end(loop));

    // 3. High entropy payload (fake encrypted data)
    auto junk = GenerateHighEntropyData(100);
    buffer.insert(buffer.end(), junk.begin(), junk.end());

    MetamorphicAnalysisConfig config;
    config.flags = MetamorphicAnalysisFlags::StandardScan;

    auto result = detector.AnalyzeBuffer(buffer.data(), buffer.size(), config);

    EXPECT_TRUE(result.analysisComplete);

    // Should detect NOP insertion
    bool nopDetected = false;
    for(const auto& det : result.detectedTechniques) {
        if(det.technique == MetamorphicTechnique::META_NOPInsertion) nopDetected = true;
    }
    EXPECT_TRUE(nopDetected);

    // Should detect Decryption Loop
    bool loopDetected = false;
    for(const auto& det : result.detectedTechniques) {
        if(det.technique == MetamorphicTechnique::POLY_XORDecryption) loopDetected = true;
    }
    EXPECT_TRUE(loopDetected);
}

// ============================================================================
// 8. CONCURRENCY TESTS
// ============================================================================

TEST_F(MetamorphicTestFixture, Concurrency_Stress) {
    MetamorphicDetector detector;
    detector.Initialize();

    const int numThreads = 8;
    const int iterations = 10;
    std::vector<std::future<MetamorphicResult>> futures;

    auto data = GenerateHighEntropyData(1024);

    for (int i = 0; i < numThreads; ++i) {
        futures.push_back(std::async(std::launch::async, [&]() {
            MetamorphicResult lastRes;
            for (int j = 0; j < iterations; ++j) {
                lastRes = detector.AnalyzeBuffer(data.data(), data.size(), {});
            }
            return lastRes;
        }));
    }

    for (auto& f : futures) {
        auto res = f.get();
        EXPECT_TRUE(res.analysisComplete);
    }
}

// ============================================================================
// 9. ERROR HANDLING EDGE CASES
// ============================================================================

TEST_F(MetamorphicTestFixture, Error_NullBuffer) {
    MetamorphicDetector detector;
    detector.Initialize();

    MetamorphicError err;
    auto result = detector.AnalyzeBuffer(nullptr, 100, {}, &err);

    EXPECT_TRUE(err.HasError()); // Invalid parameter
    EXPECT_FALSE(result.analysisComplete);
}

TEST_F(MetamorphicTestFixture, Error_ZeroSize) {
    MetamorphicDetector detector;
    detector.Initialize();

    uint8_t buf[10];
    MetamorphicError err;
    auto result = detector.AnalyzeBuffer(buf, 0, {}, &err);

    EXPECT_TRUE(err.HasError());
}

TEST_F(MetamorphicTestFixture, Error_Uninitialized) {
    MetamorphicDetector detector;
    // Skip Initialize()

    MetamorphicError err;
    uint8_t buf[10];
    auto result = detector.AnalyzeBuffer(buf, 10, {}, &err);

    EXPECT_TRUE(err.HasError()); // Not ready
    EXPECT_FALSE(result.analysisComplete);
}
