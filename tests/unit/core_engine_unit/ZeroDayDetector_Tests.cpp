/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * Unit coverage for ZeroDayDetector deterministic behavior.
 *
 * Scope:
 *   - validation and JSON helpers used by exploit-analysis diagnostics
 *   - pre-init safe defaults
 *   - initialized helper paths for shellcode, ROP, and heap heuristics
 */

#include "pch.h"

#include <gtest/gtest.h>

#include <array>
#include <map>
#include <string_view>
#include <vector>

#include "../../../src/Shared_modules/Core/Engine/ZeroDayDetector.hpp"

namespace Engine = ShadowStrike::Core::Engine;

namespace ShadowStrike::Core::Engine::Test {
namespace {

bool Contains(std::string_view haystack, std::string_view needle) {
    return haystack.find(needle) != std::string_view::npos;
}

std::vector<uint8_t> MakeShellcodeLikeBuffer() {
    std::vector<uint8_t> buffer(Engine::ZeroDayConstants::MIN_NOP_SLED_LENGTH, 0x90);
    const std::array<uint8_t, 6> getPc = {0xE8, 0x00, 0x00, 0x00, 0x00, 0x58};
    buffer.insert(buffer.end(), getPc.begin(), getPc.end());
    return buffer;
}

}  // namespace

class ZeroDayDetectorTest : public ::testing::Test {
protected:
    void SetUp() override {
        Engine::ZeroDayDetector::Instance().Shutdown();
    }

    void TearDown() override {
        Engine::ZeroDayDetector::Instance().Shutdown();
    }
};

TEST_F(ZeroDayDetectorTest, ValidationAndSerializationHelpersRemainStable) {
    Engine::ZeroDayAnalysisOptions options;
    EXPECT_TRUE(options.IsValid());
    options.maxAnalysisTimeMs = 0;
    EXPECT_FALSE(options.IsValid());
    options.maxAnalysisTimeMs = 120001;
    EXPECT_FALSE(options.IsValid());

    Engine::ZeroDayConfiguration config;
    EXPECT_TRUE(config.IsValid());
    config.workerThreads = 0;
    EXPECT_FALSE(config.IsValid());
    config.workerThreads = 33;
    EXPECT_FALSE(config.IsValid());

    Engine::ROPGadget gadget;
    gadget.address = 0x401000;
    gadget.type = Engine::GadgetType::PopRet;
    gadget.disassembly = "pop eax ; ret";
    gadget.module = "kernel32.dll";
    EXPECT_TRUE(Contains(gadget.ToJson(), "\"module\":\"kernel32.dll\""));

    Engine::ROPChainInfo chain;
    chain.startAddress = 0x401000;
    chain.gadgets = {gadget};
    chain.purpose = "VirtualProtect";
    chain.isComplete = true;
    chain.targetAPI = "VirtualProtect";
    EXPECT_TRUE(Contains(chain.ToJson(), "\"gadgetCount\":1"));

    Engine::ShellcodeInfo shellcode;
    shellcode.type = Engine::ShellcodeType::ConnectBack;
    shellcode.startOffset = 12;
    shellcode.size = 48;
    shellcode.entropy = 6.5f;
    shellcode.hasNopSled = true;
    shellcode.hasGetPC = true;
    shellcode.hasDecoderStub = false;
    EXPECT_TRUE(Contains(shellcode.ToJson(), "\"nopSled\":true"));

    Engine::HeapSprayInfo heapSpray;
    heapSpray.allocationCount = 12;
    heapSpray.totalSize = 16 * 1024 * 1024;
    heapSpray.sprayValue = 0x0C0C0C0C;
    EXPECT_TRUE(Contains(heapSpray.ToJson(), "\"sprayValue\":202116108"));

    Engine::MemoryCorruptionInfo corruption;
    corruption.corruptionType = "write-what-where";
    corruption.targetAddress = 0x5000;
    corruption.sourceAddress = 0x6000;
    corruption.vulnerableFunction = "memcpy";
    EXPECT_TRUE(Contains(corruption.ToJson(), "\"function\":\"memcpy\""));

    Engine::CVEMatch cve;
    cve.cveId = "CVE-2024-0001";
    cve.description = "test entry";
    cve.cvssScore = 9.8f;
    cve.confidence = 0.8f;
    EXPECT_TRUE(Contains(cve.ToJson(), "\"cveId\":\"CVE-2024-0001\""));

    Engine::ZeroDayResult result;
    result.detected = true;
    result.type = Engine::ExploitType::Shellcode;
    result.severity = Engine::ExploitSeverity::Critical;
    result.confidence = Engine::DetectionConfidence::High;
    result.analysisTimeUs = 123;
    result.shellcodeInfo = shellcode;
    const std::string resultJson = result.ToJson();
    EXPECT_TRUE(Contains(resultJson, "\"detected\":true"));
    EXPECT_TRUE(Contains(resultJson, "\"analysisTimeUs\":123"));
    EXPECT_TRUE(Contains(resultJson, "\"shellcode\":"));

    Engine::ZeroDayResult minimalResult;
    minimalResult.detected = false;
    const std::string minimalJson = minimalResult.ToJson();
    EXPECT_FALSE(Contains(minimalJson, "\"shellcode\":"));
    EXPECT_FALSE(Contains(minimalJson, "\"ropChain\":"));
    EXPECT_FALSE(Contains(minimalJson, "\"heapSpray\":"));

    Engine::ZeroDayStatistics stats;
    stats.totalAnalyses.store(8, std::memory_order_relaxed);
    stats.exploitsDetected.store(2, std::memory_order_relaxed);
    stats.shellcodeDetected.store(1, std::memory_order_relaxed);
    const std::string statsJson = stats.ToJson();
    EXPECT_TRUE(Contains(statsJson, "\"totalAnalyses\":8"));
    EXPECT_TRUE(Contains(statsJson, "\"shellcode\":1"));
    stats.Reset();
    EXPECT_EQ(stats.totalAnalyses.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.exploitsDetected.load(std::memory_order_relaxed), 0u);

    EXPECT_EQ(Engine::GetExploitTypeName(Engine::ExploitType::ROPChain), "ROPChain");
    EXPECT_EQ(Engine::GetShellcodeTypeName(Engine::ShellcodeType::ConnectBack), "ConnectBack");
    EXPECT_EQ(Engine::GetShellcodeTypeName(Engine::ShellcodeType::Egg_Hunter), "EggHunter");
    EXPECT_EQ(Engine::GetGadgetTypeName(Engine::GadgetType::PopRet), "PopRet");
    EXPECT_EQ(Engine::GetExploitSeverityName(Engine::ExploitSeverity::Critical), "Critical");
    EXPECT_EQ(Engine::GetDetectionConfidenceName(Engine::DetectionConfidence::High), "High");
    EXPECT_FLOAT_EQ(Engine::CalculateEntropy(std::span<const uint8_t>{}), 0.0f);
}

TEST_F(ZeroDayDetectorTest, GuardPathsStayBenignBeforeInitialization) {
    auto& detector = Engine::ZeroDayDetector::Instance();
    EXPECT_FALSE(detector.IsInitialized());

    const Engine::ZeroDayResult result = detector.AnalyzeBuffer(std::vector<uint8_t>{0x90, 0x90, 0xCC});
    EXPECT_FALSE(result.detected);
    EXPECT_FALSE(result.shellcodeInfo.has_value());

    EXPECT_FALSE(detector.AnalyzeFile(L"C:\\missing.bin").detected);
    EXPECT_FALSE(detector.AnalyzeStack(std::vector<uintptr_t>{0x1000, 0x2000}).detected);
    EXPECT_FALSE(detector.DetectShellcode(std::vector<uint8_t>{0x90, 0x90}).has_value());
    EXPECT_FALSE(detector.IsNopSled(std::vector<uint8_t>(32, 0x90)));
    EXPECT_FALSE(detector.HasGetPC(std::vector<uint8_t>{0xE8, 0x00, 0x00, 0x00, 0x00, 0x58}));
    EXPECT_FALSE(detector.HasDecoderStub(std::vector<uint8_t>(12, 0x40)));
    EXPECT_TRUE(detector.FindGadgets(std::vector<uint8_t>{0x58, 0xC3}, 0x1000).empty());
    EXPECT_FALSE(detector.DetectHeapSpray({{0x1000, 4096}}).has_value());
    EXPECT_FALSE(detector.IsHeapSprayPattern(std::vector<uint8_t>(128, 0x0C)));
    EXPECT_TRUE(detector.LookupCVE(Engine::ZeroDayResult{}).empty());
    EXPECT_FALSE(detector.GetCVEInfo("CVE-2024-0001").has_value());
    EXPECT_FALSE(detector.SelfTest());
}

TEST_F(ZeroDayDetectorTest, InitializedHeuristicsDetectShellcodeHeapAndRopSignals) {
    auto& detector = Engine::ZeroDayDetector::Instance();
    ASSERT_TRUE(detector.Initialize());
    EXPECT_TRUE(detector.IsInitialized());
    EXPECT_TRUE(detector.SelfTest());

    const std::vector<uint8_t> shellcodeBuffer = MakeShellcodeLikeBuffer();
    EXPECT_TRUE(detector.IsNopSled(shellcodeBuffer));
    EXPECT_TRUE(detector.HasGetPC(std::span<const uint8_t>(shellcodeBuffer).subspan(
        Engine::ZeroDayConstants::MIN_NOP_SLED_LENGTH)));
    EXPECT_TRUE(detector.IsNopSled(std::vector<uint8_t>(Engine::ZeroDayConstants::MIN_NOP_SLED_LENGTH, 0x97)));
    EXPECT_TRUE(detector.HasGetPC(std::vector<uint8_t>{0xD9, 0x74, 0x24, 0xF4}));

    const std::vector<uint8_t> decoderStub = {
        0x31, 0xC0, 0x40, 0xE2, 0xFE, 0x41,
        0x33, 0xC1, 0x42, 0xE2, 0xFC, 0x43
    };
    EXPECT_TRUE(detector.HasDecoderStub(decoderStub));

    const auto shellcode = detector.DetectShellcode(shellcodeBuffer);
    ASSERT_TRUE(shellcode.has_value());
    EXPECT_TRUE(shellcode->hasNopSled);
    EXPECT_TRUE(shellcode->hasGetPC);

    const Engine::ZeroDayResult analyzedBuffer = detector.AnalyzeBuffer(shellcodeBuffer);
    EXPECT_TRUE(analyzedBuffer.detected);
    EXPECT_EQ(analyzedBuffer.type, Engine::ExploitType::Shellcode);

    const std::vector<uint8_t> heapPattern(128, 0x0C);
    EXPECT_TRUE(detector.IsHeapSprayPattern(heapPattern));
    EXPECT_FALSE(detector.IsHeapSprayPattern(std::vector<uint8_t>(63, 0x0C)));
    std::vector<uint8_t> almostUniform(64, 0x41);
    for (size_t i = 0; i < 7; ++i) {
        almostUniform[i] = static_cast<uint8_t>(0x50 + i);
    }
    EXPECT_FALSE(detector.IsHeapSprayPattern(almostUniform));

    const std::vector<std::pair<uintptr_t, size_t>> allocations = {
        {0x0C0C0C0C, 0x100000}, {0x0C1C0C0C, 0x100000}, {0x0C2C0C0C, 0x100000},
        {0x0C3C0C0C, 0x100000}, {0x0C4C0C0C, 0x100000}, {0x0C5C0C0C, 0x100000},
        {0x0C6C0C0C, 0x100000}, {0x0C7C0C0C, 0x100000}, {0x0C8C0C0C, 0x100000},
        {0x0C9C0C0C, 0x100000}
    };
    const auto heapSpray = detector.DetectHeapSpray(allocations);
    ASSERT_TRUE(heapSpray.has_value());
    EXPECT_EQ(heapSpray->allocationCount, allocations.size());
    EXPECT_EQ(heapSpray->sprayValue, 0x0C0C0C0C);

    const std::vector<std::pair<uintptr_t, size_t>> insufficientSpray = {
        {0x0C0C0C0C, 0x20000}, {0x0C1C0C0C, 0x20000}, {0x0C2C0C0C, 0x20000},
        {0x0C3C0C0C, 0x20000}, {0x0C4C0C0C, 0x20000}, {0x0C5C0C0C, 0x20000},
        {0x0C6C0C0C, 0x20000}, {0x0C7C0C0C, 0x20000}, {0x0C8C0C0C, 0x20000},
        {0x0C9C0C0C, 0x20000}
    };
    EXPECT_FALSE(detector.DetectHeapSpray(insufficientSpray).has_value());

    const std::vector<uint8_t> gadgetBytes = {0x58, 0xC3, 0x90, 0x5A, 0xC3};
    const auto gadgets = detector.FindGadgets(gadgetBytes, 0x1000);
    EXPECT_FALSE(gadgets.empty());

    const std::map<std::string, std::pair<uintptr_t, size_t>> moduleRanges = {
        {"kernel32.dll", {0x1000, 0x100}},
        {"ntdll.dll", {0x2000, 0x100}},
        {"user32.dll", {0x3000, 0x100}}
    };
    const std::vector<uintptr_t> stackDump = {0x1001, 0x2002, 0x3003, 0x1004, 0x2005};
    const auto ropChain = detector.DetectROPChain(stackDump, moduleRanges);
    ASSERT_TRUE(ropChain.has_value());
    EXPECT_EQ(ropChain->gadgets.size(), stackDump.size());

    const Engine::ZeroDayResult stackAnalysis = detector.AnalyzeStack(stackDump, moduleRanges);
    EXPECT_TRUE(stackAnalysis.detected);
    EXPECT_EQ(stackAnalysis.type, Engine::ExploitType::ROPChain);
}

}  // namespace ShadowStrike::Core::Engine::Test
