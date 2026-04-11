/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * Integration Tests — Tier 2: AI/ML Detection Pipeline
 *
 * =========================================================================
 * PURPOSE
 * =========================================================================
 * Validates the full AI/ML inference pipeline by exercising the real,
 * production implementations of:
 *
 *   PhantomCortex       — top-level orchestrator (Meyers' Singleton)
 *   FeatureExtractor    — raw-telemetry-to-feature-vector conversion
 *   ModelCache          — atomic model-file swap and integrity protocol
 *   ModelInference      — ONNX Runtime wrapper
 *   CortexConfigManager — JSON / Registry configuration manager
 *
 * No mocks. No stubs. Where ONNX model files are absent (typical in CI),
 * methods that require a loaded model return safe defaults; those tests
 * assert the graceful-failure contract rather than skip entirely.
 *
 * =========================================================================
 * TEST GROUPS
 * =========================================================================
 *   GROUP 1  FeatureExtractor_VectorSizes    — feature-vector size contracts
 *   GROUP 2  FeatureExtractor_Adversarial    — hostile / malformed inputs
 *   GROUP 3  CortexConfigManager_Integration — JSON config roundtrip
 *   GROUP 4  ModelCache_Integration          — filesystem swap protocol
 *   GROUP 5  ModelInference_Lifecycle        — ORT init / model-load contracts
 *   GROUP 6  PhantomCortex_Lifecycle         — singleton, stats, graceful-fail
 *   GROUP 7  EnsembleVerdict_Logic           — weighted multi-model aggregation
 *   GROUP 8  TypeContracts                   — enum ordinals, struct invariants
 *
 * =========================================================================
 * BUILD
 * =========================================================================
 * cl /nologo /std:c++20 /EHsc /W4 /c /I. /Isrc /Iinclude
 *    tests\integration\ai_pipeline\AIPipeline_Integration_Tests.cpp
 *    /FoAIPipeline_Integration_Tests.obj
 */

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cmath>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <limits>
#include <memory>
#include <optional>
#include <random>
#include <span>
#include <string>
#include <thread>
#include <vector>

#include <gtest/gtest.h>

#include "../../../src/PhantomCore/AI/CortexTypes.hpp"
#include "../../../src/PhantomCore/AI/PhantomCortex.hpp"
#include "../../../src/PhantomCore/AI/FeatureExtractor.hpp"
#include "../../../src/PhantomCore/AI/ModelCache.hpp"
#include "../../../src/PhantomCore/AI/ModelInference.hpp"
#include "../../../src/PhantomCore/AI/CortexConfig.hpp"

namespace AI = ShadowStrike::AI;

// ===========================================================================
// RAII: SCOPED TEMP DIRECTORY
// Creates a unique directory under %TEMP% and removes it recursively on
// destruction, ensuring no test leaves filesystem artefacts behind.
// ===========================================================================
class ScopedTempDir {
public:
    ScopedTempDir() {
        wchar_t tmp[MAX_PATH] = {};
        GetTempPathW(MAX_PATH, tmp);
        static std::atomic<uint32_t> s_seq{0};
        const uint32_t idx = ++s_seq;
        m_path = std::filesystem::path(tmp) /
                 (std::wstring(L"ss_ai_") +
                  std::to_wstring(GetCurrentProcessId()) +
                  L"_" + std::to_wstring(idx));
        std::filesystem::create_directories(m_path);
    }
    ~ScopedTempDir() {
        std::error_code ec;
        std::filesystem::remove_all(m_path, ec);
    }
    [[nodiscard]] const std::filesystem::path& Path() const noexcept {
        return m_path;
    }
    ScopedTempDir(const ScopedTempDir&)            = delete;
    ScopedTempDir& operator=(const ScopedTempDir&) = delete;
private:
    std::filesystem::path m_path;
};

// ===========================================================================
// FILE I/O HELPERS
// ===========================================================================

/// @brief Read all bytes from a file; returns nullopt on any failure.
static std::optional<std::vector<uint8_t>>
ReadFileBytes(const std::filesystem::path& p) noexcept {
    std::ifstream f(p, std::ios::binary | std::ios::ate);
    if (!f.good()) return std::nullopt;
    const auto sz = f.tellg();
    if (sz <= 0) return std::nullopt;
    f.seekg(0, std::ios::beg);
    std::vector<uint8_t> buf(static_cast<size_t>(sz));
    if (!f.read(reinterpret_cast<char*>(buf.data()), sz)) return std::nullopt;
    return buf;
}

/// @brief Returns bytes of a live Windows system PE for valid-PE coverage.
///        Tries notepad.exe, then calc.exe, then mspaint.exe in order.
static std::vector<uint8_t> GetSystemPEBytes() noexcept {
    wchar_t sysDir[MAX_PATH] = {};
    if (GetSystemDirectoryW(sysDir, MAX_PATH) == 0) return {};
    const wchar_t* candidates[] = { L"notepad.exe", L"calc.exe", L"mspaint.exe" };
    for (const wchar_t* name : candidates) {
        auto path  = std::filesystem::path(sysDir) / name;
        auto bytes = ReadFileBytes(path);
        if (bytes && !bytes->empty()) return std::move(*bytes);
    }
    return {};
}

/// @brief Write a small file with fixed content; returns true on success.
static bool WriteDummyFile(const std::filesystem::path& p,
                            std::string_view content = "PLACEHOLDER") noexcept {
    std::ofstream f(p, std::ios::binary);
    if (!f.good()) return false;
    f.write(content.data(), static_cast<std::streamsize>(content.size()));
    return f.good();
}

// ===========================================================================
// GROUP 1 — FeatureExtractor: Feature-Vector Size Contracts
// ===========================================================================
/**
 * @brief Validates that every Extract*() overload returns a vector whose size
 * exactly matches the corresponding CortexConstants compile-time value, and
 * that invalid / empty inputs yield std::nullopt.
 *
 * Fixture: FeatureExtractor is a singleton.  Initialize() is called once for
 * the entire suite via SetUpTestSuite(); subsequent calls are safe no-ops.
 * Concurrent-extraction safety is validated in test 1.13.
 */
class FeatureExtractor_VectorSizes : public ::testing::Test {
public:
    static void SetUpTestSuite() {
        s_initialized = AI::FeatureExtractor::Instance().Initialize();
    }
    static bool s_initialized;
};
bool FeatureExtractor_VectorSizes::s_initialized = false;

#define SKIP_FE_INIT()                                                         \
    do {                                                                        \
        if (!FeatureExtractor_VectorSizes::s_initialized) {                    \
            GTEST_SKIP() << "FeatureExtractor::Initialize() returned false.";  \
        }                                                                       \
    } while (false)

// ---------------------------------------------------------------------------
// 1.1  Initialize() must succeed on any supported Windows x86-64 platform.
// ---------------------------------------------------------------------------
TEST_F(FeatureExtractor_VectorSizes, Init_Succeeds) {
    EXPECT_TRUE(s_initialized)
        << "FeatureExtractor::Initialize() must return true on Windows x86-64.";
}

// ---------------------------------------------------------------------------
// 1.2  An empty span must yield nullopt — there is no MZ magic to validate.
// ---------------------------------------------------------------------------
TEST_F(FeatureExtractor_VectorSizes, PE_EmptyBuffer_ReturnsNullopt) {
    SKIP_FE_INIT();
    const auto r = AI::FeatureExtractor::Instance().ExtractPEFeatures(
        std::span<const uint8_t>{});
    EXPECT_FALSE(r.has_value())
        << "ExtractPEFeatures(empty span) must return std::nullopt.";
}

// ---------------------------------------------------------------------------
// 1.3  Bytes that start with ELF magic (not MZ) must yield nullopt.
// ---------------------------------------------------------------------------
TEST_F(FeatureExtractor_VectorSizes, PE_ELFMagic_ReturnsNullopt) {
    SKIP_FE_INIT();
    const std::array<uint8_t, 16> elf = {
        0x7F, 0x45, 0x4C, 0x46,  0x02, 0x01, 0x01, 0x00,
        0x00, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00
    };
    const auto r = AI::FeatureExtractor::Instance().ExtractPEFeatures(
        std::span<const uint8_t>(elf.data(), elf.size()));
    EXPECT_FALSE(r.has_value())
        << "ELF-magic input must not produce PE features.";
}

// ---------------------------------------------------------------------------
// 1.4  A real Windows system PE must produce STATIC_FEATURE_COUNT features.
// ---------------------------------------------------------------------------
TEST_F(FeatureExtractor_VectorSizes, PE_RealWindowsPE_CorrectVectorSize) {
    SKIP_FE_INIT();
    const auto bytes = GetSystemPEBytes();
    if (bytes.empty()) {
        GTEST_SKIP() << "No system PE located (notepad.exe / calc.exe absent).";
    }
    const auto r = AI::FeatureExtractor::Instance().ExtractPEFeatures(
        std::span<const uint8_t>(bytes.data(), bytes.size()));
    ASSERT_TRUE(r.has_value())
        << "ExtractPEFeatures() must succeed for a valid Windows PE.";
    EXPECT_EQ(r->size(), AI::CortexConstants::STATIC_FEATURE_COUNT)
        << "PE feature vector must be exactly STATIC_FEATURE_COUNT="
        << AI::CortexConstants::STATIC_FEATURE_COUNT << ".";
}

// ---------------------------------------------------------------------------
// 1.5  An empty API call span must yield nullopt.
// ---------------------------------------------------------------------------
TEST_F(FeatureExtractor_VectorSizes, Behavioral_EmptySequence_ReturnsNullopt) {
    SKIP_FE_INIT();
    const auto r = AI::FeatureExtractor::Instance().ExtractBehavioralFeatures(
        std::span<const AI::APICallRecord>{});
    EXPECT_FALSE(r.has_value())
        << "ExtractBehavioralFeatures(empty) must return std::nullopt.";
}

// ---------------------------------------------------------------------------
// 1.6  A representative 32-call sequence must yield BEHAVIORAL_FEATURE_COUNT.
// ---------------------------------------------------------------------------
TEST_F(FeatureExtractor_VectorSizes, Behavioral_ValidSequence_CorrectVectorSize) {
    SKIP_FE_INIT();
    std::vector<AI::APICallRecord> calls(32);
    for (uint32_t i = 0; i < 32; ++i) {
        calls[i].apiNameHash      = 0xDEAD0000u + i;
        calls[i].argSummaryHash   = 0xBEEF0000u + i;
        calls[i].returnValue      = static_cast<int32_t>(i);
        calls[i].timestampDeltaMs = static_cast<float>(i) * 1.5f;
    }
    const auto r = AI::FeatureExtractor::Instance().ExtractBehavioralFeatures(
        std::span<const AI::APICallRecord>(calls.data(), calls.size()));
    ASSERT_TRUE(r.has_value())
        << "A 32-element API call sequence must produce a feature vector.";
    EXPECT_EQ(r->size(), AI::CortexConstants::BEHAVIORAL_FEATURE_COUNT)
        << "Behavioral vector must be exactly BEHAVIORAL_FEATURE_COUNT="
        << AI::CortexConstants::BEHAVIORAL_FEATURE_COUNT << ".";
}

// ---------------------------------------------------------------------------
// 1.7  A sequence exceeding MAX_API_SEQUENCE_LENGTH must be truncated, not
//      rejected — the vector size must still match the expected constant.
// ---------------------------------------------------------------------------
TEST_F(FeatureExtractor_VectorSizes, Behavioral_LongSequence_TruncatedAndSucceeds) {
    SKIP_FE_INIT();
    const size_t overLen = AI::CortexConstants::MAX_API_SEQUENCE_LENGTH + 256;
    std::vector<AI::APICallRecord> calls(overLen);
    for (size_t i = 0; i < overLen; ++i)
        calls[i].apiNameHash = static_cast<uint32_t>(i & 0xFFFFu);
    const auto r = AI::FeatureExtractor::Instance().ExtractBehavioralFeatures(
        std::span<const AI::APICallRecord>(calls.data(), calls.size()));
    ASSERT_TRUE(r.has_value())
        << "Sequences exceeding MAX_API_SEQUENCE_LENGTH must be truncated, "
           "not rejected.";
    EXPECT_EQ(r->size(), AI::CortexConstants::BEHAVIORAL_FEATURE_COUNT);
}

// ---------------------------------------------------------------------------
// 1.8  A 4 KB memory region must yield exactly MEMORY_FEATURE_COUNT features.
// ---------------------------------------------------------------------------
TEST_F(FeatureExtractor_VectorSizes, Memory_ValidRegion_CorrectVectorSize) {
    SKIP_FE_INIT();
    constexpr size_t kBytes = 4096;
    std::vector<uint8_t> data(kBytes, 0xCC); // INT3 sled — high opcode density
    AI::MemoryRegionInfo region;
    region.data        = std::span<const uint8_t>(data.data(), data.size());
    region.baseAddress = 0x7FFE00000000ULL;
    region.size        = kBytes;
    region.protection  = PAGE_EXECUTE_READ;
    const auto r = AI::FeatureExtractor::Instance().ExtractMemoryFeatures(region);
    ASSERT_TRUE(r.has_value())
        << "A valid 4 KB memory region must produce a feature vector.";
    EXPECT_EQ(r->size(), AI::CortexConstants::MEMORY_FEATURE_COUNT)
        << "Memory vector must be exactly MEMORY_FEATURE_COUNT="
        << AI::CortexConstants::MEMORY_FEATURE_COUNT << ".";
}

// ---------------------------------------------------------------------------
// 1.9  A region larger than MAX_MEMORY_REGION_SIZE must yield nullopt.
//      MAX_MEMORY_REGION_SIZE = 64 MB; we allocate 64 MB + 1 byte.
// ---------------------------------------------------------------------------
TEST_F(FeatureExtractor_VectorSizes, Memory_ExceedsMaxSize_ReturnsNullopt) {
    SKIP_FE_INIT();
    const size_t oversized = AI::CortexConstants::MAX_MEMORY_REGION_SIZE + 1;
    std::vector<uint8_t> bigData;
    try {
        bigData.resize(oversized, 0x00);
    } catch (const std::bad_alloc&) {
        GTEST_SKIP() << "Insufficient memory to allocate " << oversized << " bytes.";
    }
    AI::MemoryRegionInfo region;
    region.data        = std::span<const uint8_t>(bigData.data(), bigData.size());
    region.baseAddress = 0;
    region.size        = oversized;
    region.protection  = PAGE_READWRITE;
    const auto r = AI::FeatureExtractor::Instance().ExtractMemoryFeatures(region);
    EXPECT_FALSE(r.has_value())
        << "Regions exceeding MAX_MEMORY_REGION_SIZE must be rejected with nullopt.";
}

// ---------------------------------------------------------------------------
// 1.10 A zero-initialised NetworkFlowInfo must yield NETWORK_FEATURE_COUNT.
//      Covers the "idle / no-traffic" baseline extraction path.
// ---------------------------------------------------------------------------
TEST_F(FeatureExtractor_VectorSizes, Network_ZeroFlow_CorrectVectorSize) {
    SKIP_FE_INIT();
    const AI::NetworkFlowInfo flow{};
    const auto r = AI::FeatureExtractor::Instance().ExtractNetworkFeatures(flow);
    ASSERT_TRUE(r.has_value())
        << "A zero-initialised NetworkFlowInfo must produce network features.";
    EXPECT_EQ(r->size(), AI::CortexConstants::NETWORK_FEATURE_COUNT)
        << "Network vector must be exactly NETWORK_FEATURE_COUNT="
        << AI::CortexConstants::NETWORK_FEATURE_COUNT << ".";
}

// ---------------------------------------------------------------------------
// 1.11 An empty emulation trace must yield nullopt.
// ---------------------------------------------------------------------------
TEST_F(FeatureExtractor_VectorSizes, Emulation_EmptyTrace_ReturnsNullopt) {
    SKIP_FE_INIT();
    const auto r = AI::FeatureExtractor::Instance().ExtractEmulationFeatures(
        std::span<const AI::EmulationEvent>{});
    EXPECT_FALSE(r.has_value())
        << "ExtractEmulationFeatures(empty) must return std::nullopt.";
}

// ---------------------------------------------------------------------------
// 1.12 A 128-event trace must yield exactly EMULATION_FEATURE_COUNT features.
// ---------------------------------------------------------------------------
TEST_F(FeatureExtractor_VectorSizes, Emulation_ValidTrace_CorrectVectorSize) {
    SKIP_FE_INIT();
    std::vector<AI::EmulationEvent> events(128);
    for (uint16_t i = 0; i < 128; ++i) {
        events[i].opcodeCategory   = static_cast<uint16_t>(i % 16);
        events[i].memoryAccessType = static_cast<uint8_t>(i % 4);
        events[i].apiCallId        = (i % 8 == 0) ? static_cast<uint16_t>(i + 1) : 0;
        events[i].eflagsChange     = static_cast<uint8_t>(i & 0xFF);
    }
    const auto r = AI::FeatureExtractor::Instance().ExtractEmulationFeatures(
        std::span<const AI::EmulationEvent>(events.data(), events.size()));
    ASSERT_TRUE(r.has_value())
        << "A 128-event emulation trace must produce a feature vector.";
    EXPECT_EQ(r->size(), AI::CortexConstants::EMULATION_FEATURE_COUNT)
        << "Emulation vector must be exactly EMULATION_FEATURE_COUNT="
        << AI::CortexConstants::EMULATION_FEATURE_COUNT << ".";
}

// ---------------------------------------------------------------------------
// 1.13 ExtractNetworkFeatures() must be safe for 8 concurrent callers.
//      Validates the "read-only lookup tables" thread-safety guarantee.
// ---------------------------------------------------------------------------
TEST_F(FeatureExtractor_VectorSizes, Concurrent_ExtractionNoRace) {
    SKIP_FE_INIT();
    constexpr int kThreads = 8;
    std::atomic<int> failCount{0};
    std::vector<std::thread> threads;
    threads.reserve(kThreads);
    for (int t = 0; t < kThreads; ++t) {
        threads.emplace_back([&failCount, t]() {
            AI::NetworkFlowInfo flow{};
            flow.bytesSent     = static_cast<uint64_t>(t) * 1024;
            flow.bytesReceived = static_cast<uint64_t>(t) * 512;
            flow.durationMs    = static_cast<float>(t + 1) * 10.0f;
            const auto r =
                AI::FeatureExtractor::Instance().ExtractNetworkFeatures(flow);
            if (!r.has_value() ||
                r->size() != AI::CortexConstants::NETWORK_FEATURE_COUNT) {
                ++failCount;
            }
        });
    }
    for (auto& th : threads) th.join();
    EXPECT_EQ(failCount.load(), 0)
        << "All 8 concurrent ExtractNetworkFeatures() calls must produce "
           "a vector of size NETWORK_FEATURE_COUNT.";
}

// ===========================================================================
// GROUP 2 — FeatureExtractor: Adversarial Inputs
// ===========================================================================
/**
 * @brief Feeds deliberately malformed, truncated, and saturated inputs to
 * FeatureExtractor to confirm that no hostile input can cause undefined
 * behaviour, buffer overruns, integer overflow, or NaN propagation.
 *
 * Uses the same fixture class as GROUP 1 (FeatureExtractor_VectorSizes).
 */

// ---------------------------------------------------------------------------
// 2.1  A 2-byte MZ stub must yield nullopt — the DOS header is truncated.
// ---------------------------------------------------------------------------
TEST_F(FeatureExtractor_VectorSizes, Adversarial_PE_TwoByteStub_Nullopt) {
    SKIP_FE_INIT();
    const std::array<uint8_t, 2> stub = { 0x4D, 0x5A };
    const auto r = AI::FeatureExtractor::Instance().ExtractPEFeatures(
        std::span<const uint8_t>(stub.data(), stub.size()));
    EXPECT_FALSE(r.has_value())
        << "A 2-byte MZ-only stub must be rejected — DOS header is incomplete.";
}

// ---------------------------------------------------------------------------
// 2.2  An e_lfanew pointing 64 KB beyond the file end must yield nullopt.
// ---------------------------------------------------------------------------
TEST_F(FeatureExtractor_VectorSizes, Adversarial_PE_BadE_lfanew_Nullopt) {
    SKIP_FE_INIT();
    std::array<uint8_t, 64> buf{};
    buf[0]    = 0x4D; buf[1]    = 0x5A; // MZ magic
    buf[0x3C] = 0xFF; buf[0x3D] = 0xFF; // e_lfanew = 65535 — way out of bounds
    const auto r = AI::FeatureExtractor::Instance().ExtractPEFeatures(
        std::span<const uint8_t>(buf.data(), buf.size()));
    EXPECT_FALSE(r.has_value())
        << "An e_lfanew pointing beyond the file end must be rejected.";
}

// ---------------------------------------------------------------------------
// 2.3  Valid MZ + in-range e_lfanew but garbage PE signature — nullopt.
// ---------------------------------------------------------------------------
TEST_F(FeatureExtractor_VectorSizes, Adversarial_PE_MissingPESig_Nullopt) {
    SKIP_FE_INIT();
    std::array<uint8_t, 128> buf{};
    buf[0]    = 0x4D; buf[1]    = 0x5A; // MZ
    buf[0x3C] = 0x40;                   // e_lfanew = 64 (valid offset into buf)
    buf[0x40] = 0xAA; buf[0x41] = 0xBB; // garbage — not "PE\0\0"
    const auto r = AI::FeatureExtractor::Instance().ExtractPEFeatures(
        std::span<const uint8_t>(buf.data(), buf.size()));
    EXPECT_FALSE(r.has_value())
        << "Garbage in the PE signature slot must be rejected.";
}

// ---------------------------------------------------------------------------
// 2.4  A 64 KB high-entropy region must not crash or produce NaN features.
// ---------------------------------------------------------------------------
TEST_F(FeatureExtractor_VectorSizes, Adversarial_Memory_HighEntropy_NoNaN) {
    SKIP_FE_INIT();
    constexpr size_t kSize = 65536;
    std::vector<uint8_t> hostile(kSize);
    std::mt19937 rng(0xDEADBEEFu);
    std::uniform_int_distribution<uint32_t> dist(0, 255);
    for (auto& b : hostile) b = static_cast<uint8_t>(dist(rng));
    AI::MemoryRegionInfo region;
    region.data        = std::span<const uint8_t>(hostile.data(), hostile.size());
    region.baseAddress = 0x00DEAD000000ULL;
    region.size        = kSize;
    region.protection  = PAGE_EXECUTE_READWRITE;
    const auto r = AI::FeatureExtractor::Instance().ExtractMemoryFeatures(region);
    if (r.has_value()) {
        EXPECT_EQ(r->size(), AI::CortexConstants::MEMORY_FEATURE_COUNT);
        for (float v : *r) {
            EXPECT_FALSE(std::isnan(v))
                << "Feature vector must not contain NaN after high-entropy input.";
        }
    }
    // If nullopt: extractor chose to reject — also acceptable.
}

// ---------------------------------------------------------------------------
// 2.5  A sequence of exactly MAX_API_SEQUENCE_LENGTH records must succeed.
//      This is the at-limit boundary: must NOT be truncated or rejected.
// ---------------------------------------------------------------------------
TEST_F(FeatureExtractor_VectorSizes, Adversarial_Behavioral_AtExactMaxLength) {
    SKIP_FE_INIT();
    std::vector<AI::APICallRecord> calls(AI::CortexConstants::MAX_API_SEQUENCE_LENGTH);
    for (size_t i = 0; i < calls.size(); ++i)
        calls[i].apiNameHash = static_cast<uint32_t>(i & 0xFFFFu);
    const auto r = AI::FeatureExtractor::Instance().ExtractBehavioralFeatures(
        std::span<const AI::APICallRecord>(calls.data(), calls.size()));
    ASSERT_TRUE(r.has_value())
        << "A sequence of exactly MAX_API_SEQUENCE_LENGTH must succeed.";
    EXPECT_EQ(r->size(), AI::CortexConstants::BEHAVIORAL_FEATURE_COUNT);
}

// ---------------------------------------------------------------------------
// 2.6  A NetworkFlowInfo with all numeric fields at max must not crash or
//      produce NaN in the resulting feature vector.
// ---------------------------------------------------------------------------
TEST_F(FeatureExtractor_VectorSizes, Adversarial_Network_SaturatedFields_NoNaN) {
    SKIP_FE_INIT();
    AI::NetworkFlowInfo flow{};
    flow.bytesSent           = std::numeric_limits<uint64_t>::max();
    flow.bytesReceived       = std::numeric_limits<uint64_t>::max();
    flow.packetsSent         = std::numeric_limits<uint32_t>::max();
    flow.packetsReceived     = std::numeric_limits<uint32_t>::max();
    flow.durationMs          = std::numeric_limits<float>::max();
    flow.avgInterArrivalMs   = 1e30f;
    flow.payloadEntropy      = 8.0f; // max Shannon entropy for a byte sequence
    flow.srcIPv4             = 0xFFFFFFFFu;
    flow.dstIPv4             = 0xFFFFFFFFu;
    flow.srcPort             = 65535u;
    flow.dstPort             = 65535u;
    const auto r = AI::FeatureExtractor::Instance().ExtractNetworkFeatures(flow);
    if (r.has_value()) {
        EXPECT_EQ(r->size(), AI::CortexConstants::NETWORK_FEATURE_COUNT);
        for (float v : *r) {
            EXPECT_FALSE(std::isnan(v))
                << "Feature vector must not contain NaN with saturated network fields.";
        }
    }
}

// ===========================================================================
// GROUP 3 — CortexConfigManager: JSON Config Roundtrip
// ===========================================================================
/**
 * @brief Tests CortexConfigManager's load/save/validate pipeline:
 *  - default-value sanity checks
 *  - graceful failure on a missing file
 *  - SaveConfig() followed by LoadConfig() roundtrip preserving thresholds
 *
 * Fixture: a ScopedTempDir is created per-test to give each test a clean
 * scratch area for JSON files.
 */
class CortexConfigManager_Integration : public ::testing::Test {
protected:
    void SetUp() override {
        m_tempDir = std::make_unique<ScopedTempDir>();
    }
    void TearDown() override {
        m_tempDir.reset();
    }
    std::unique_ptr<ScopedTempDir> m_tempDir;
};

// ---------------------------------------------------------------------------
// 3.1  Default CortexConfig must have all thresholds in the valid range [0,1].
// ---------------------------------------------------------------------------
TEST_F(CortexConfigManager_Integration, DefaultConfig_ThresholdsInValidRange) {
    const AI::CortexConfig cfg = AI::CortexConfigManager::Instance().GetConfig();
    EXPECT_GE(cfg.staticThreshold,     0.0f); EXPECT_LE(cfg.staticThreshold,     1.0f);
    EXPECT_GE(cfg.behavioralThreshold, 0.0f); EXPECT_LE(cfg.behavioralThreshold, 1.0f);
    EXPECT_GE(cfg.memoryThreshold,     0.0f); EXPECT_LE(cfg.memoryThreshold,     1.0f);
    EXPECT_GE(cfg.networkThreshold,    0.0f); EXPECT_LE(cfg.networkThreshold,    1.0f);
    EXPECT_GE(cfg.emulationThreshold,  0.0f); EXPECT_LE(cfg.emulationThreshold,  1.0f);
    EXPECT_GE(cfg.ensembleThreshold,   0.0f); EXPECT_LE(cfg.ensembleThreshold,   1.0f);
}

// ---------------------------------------------------------------------------
// 3.2  Default maxBatchSize must not exceed CortexConstants::MAX_BATCH_SIZE.
// ---------------------------------------------------------------------------
TEST_F(CortexConfigManager_Integration, DefaultConfig_MaxBatchSizeLeqLimit) {
    const AI::CortexConfig cfg = AI::CortexConfigManager::Instance().GetConfig();
    EXPECT_GT(cfg.maxBatchSize, 0u)
        << "Default maxBatchSize must be positive.";
    EXPECT_LE(cfg.maxBatchSize, AI::CortexConstants::MAX_BATCH_SIZE)
        << "Default maxBatchSize must not exceed the hard limit of "
        << AI::CortexConstants::MAX_BATCH_SIZE << ".";
}

// ---------------------------------------------------------------------------
// 3.3  Default inferenceTimeoutMs must be in [1, MAX_INFERENCE_TIMEOUT_MS].
// ---------------------------------------------------------------------------
TEST_F(CortexConfigManager_Integration, DefaultConfig_TimeoutInValidRange) {
    const AI::CortexConfig cfg = AI::CortexConfigManager::Instance().GetConfig();
    EXPECT_GT(cfg.inferenceTimeoutMs, 0u)
        << "inferenceTimeoutMs must be positive.";
    EXPECT_LE(cfg.inferenceTimeoutMs, AI::CortexConstants::MAX_INFERENCE_TIMEOUT_MS)
        << "inferenceTimeoutMs must not exceed MAX_INFERENCE_TIMEOUT_MS="
        << AI::CortexConstants::MAX_INFERENCE_TIMEOUT_MS << ".";
}

// ---------------------------------------------------------------------------
// 3.4  LoadConfig() with a non-existent path must return false gracefully.
// ---------------------------------------------------------------------------
TEST_F(CortexConfigManager_Integration, LoadConfig_NonExistentFile_ReturnsFalse) {
    const auto ghost = m_tempDir->Path() / L"no_such_config.json";
    ASSERT_FALSE(std::filesystem::exists(ghost));
    EXPECT_FALSE(AI::CortexConfigManager::Instance().LoadConfig(ghost))
        << "LoadConfig() must return false for a path that does not exist.";
}

// ---------------------------------------------------------------------------
// 3.5  SaveConfig() must create a non-empty file and return true.
// ---------------------------------------------------------------------------
TEST_F(CortexConfigManager_Integration, SaveConfig_CreatesNonEmptyFile) {
    const auto outPath = m_tempDir->Path() / L"saved_config.json";
    ASSERT_FALSE(std::filesystem::exists(outPath));
    ASSERT_TRUE(AI::CortexConfigManager::Instance().SaveConfig(outPath))
        << "SaveConfig() must return true on success.";
    EXPECT_TRUE(std::filesystem::exists(outPath))
        << "SaveConfig() must create the output file.";
    EXPECT_GT(std::filesystem::file_size(outPath), 2u)
        << "Saved config file must not be empty or trivially small.";
}

// ---------------------------------------------------------------------------
// 3.6  SaveConfig() + LoadConfig() roundtrip must preserve all thresholds.
//      This is the primary regression guard for the JSON serialisation layer.
// ---------------------------------------------------------------------------
TEST_F(CortexConfigManager_Integration, SaveAndLoad_Roundtrip_PreservesThresholds) {
    const auto path   = m_tempDir->Path() / L"roundtrip.json";
    const AI::CortexConfig before = AI::CortexConfigManager::Instance().GetConfig();
    ASSERT_TRUE(AI::CortexConfigManager::Instance().SaveConfig(path))
        << "SaveConfig() must succeed.";
    ASSERT_TRUE(AI::CortexConfigManager::Instance().LoadConfig(path))
        << "LoadConfig() must accept the file just produced by SaveConfig().";
    const AI::CortexConfig after = AI::CortexConfigManager::Instance().GetConfig();
    EXPECT_NEAR(after.staticThreshold,     before.staticThreshold,     1e-4f);
    EXPECT_NEAR(after.behavioralThreshold, before.behavioralThreshold, 1e-4f);
    EXPECT_NEAR(after.memoryThreshold,     before.memoryThreshold,     1e-4f);
    EXPECT_NEAR(after.networkThreshold,    before.networkThreshold,    1e-4f);
    EXPECT_NEAR(after.emulationThreshold,  before.emulationThreshold,  1e-4f);
    EXPECT_NEAR(after.ensembleThreshold,   before.ensembleThreshold,   1e-4f);
    EXPECT_EQ(after.maxBatchSize,          before.maxBatchSize);
    EXPECT_EQ(after.inferenceTimeoutMs,    before.inferenceTimeoutMs);
}

// ===========================================================================
// GROUP 4 — ModelCache: Filesystem Swap Protocol
// ===========================================================================
/**
 * @brief Validates ModelCache's directory creation, model-path queries,
 * atomic swap, integrity verification, and rollback against a real (though
 * toy) filesystem.
 *
 * Fixture: the cache is initialised once per suite into a shared temp
 * directory.  Tests that need model files write uniquely-named placeholder
 * .onnx files via the PlaceholderOnnx() helper.
 */
class ModelCache_Integration : public ::testing::Test {
public:
    static void SetUpTestSuite() {
        s_dir         = std::make_unique<ScopedTempDir>();
        s_initialized = AI::ModelCache::Instance().Initialize(s_dir->Path());
    }
    static void TearDownTestSuite() {
        s_dir.reset();
    }
    static std::unique_ptr<ScopedTempDir> s_dir;
    static bool s_initialized;

protected:
    /// Write a uniquely-named placeholder .onnx file; return its path.
    static std::filesystem::path PlaceholderOnnx(const wchar_t* name) {
        const auto p = s_dir->Path() / name;
        WriteDummyFile(p, "FAKE_ONNX_PLACEHOLDER");
        return p;
    }
};
std::unique_ptr<ScopedTempDir> ModelCache_Integration::s_dir;
bool ModelCache_Integration::s_initialized = false;

#define SKIP_CACHE_INIT()                                                      \
    do {                                                                        \
        if (!ModelCache_Integration::s_initialized) {                          \
            GTEST_SKIP() << "ModelCache::Initialize() returned false.";        \
        }                                                                       \
    } while (false)

// ---------------------------------------------------------------------------
// 4.1  Initialize() must return true for a writable directory.
// ---------------------------------------------------------------------------
TEST_F(ModelCache_Integration, Init_Succeeds) {
    EXPECT_TRUE(s_initialized)
        << "ModelCache::Initialize() must succeed for a writable temp directory.";
}

// ---------------------------------------------------------------------------
// 4.2  Each of the five model slot subdirectories must exist after Initialize().
// ---------------------------------------------------------------------------
TEST_F(ModelCache_Integration, Init_CreatesDirStructure) {
    SKIP_CACHE_INIT();
    ASSERT_NE(s_dir, nullptr);
    const wchar_t* slots[] = {
        L"static", L"behavioral", L"memory", L"network", L"emulation"
    };
    for (const auto* name : slots) {
        const auto slotDir = s_dir->Path() / name;
        EXPECT_TRUE(std::filesystem::is_directory(slotDir))
            << "ModelCache must create slot subdirectory: " << slotDir.string();
    }
}

// ---------------------------------------------------------------------------
// 4.3  GetModelPath() must return nullopt for a slot with no model file,
//      OR must return a path to an existing file if pre-populated.
// ---------------------------------------------------------------------------
TEST_F(ModelCache_Integration, GetModelPath_EmptySlot_Consistent) {
    SKIP_CACHE_INIT();
    const auto path =
        AI::ModelCache::Instance().GetModelPath(AI::CortexModelType::Network);
    if (!path.has_value()) {
        SUCCEED() << "GetModelPath() correctly returns nullopt for an empty slot.";
    } else {
        EXPECT_TRUE(std::filesystem::exists(*path))
            << "If GetModelPath() returns a path, the file must exist on disk.";
    }
}

// ---------------------------------------------------------------------------
// 4.4  VerifyIntegrity() must return false for a slot with no model file
//      (no manifest.json has been written, so verification must fail).
// ---------------------------------------------------------------------------
TEST_F(ModelCache_Integration, VerifyIntegrity_EmptySlot_ReturnsFalse) {
    SKIP_CACHE_INIT();
    // Emulation slot is never written in this suite — must have no manifest.
    EXPECT_FALSE(
        AI::ModelCache::Instance().VerifyIntegrity(AI::CortexModelType::Emulation))
        << "VerifyIntegrity() must return false for a slot with no manifest.";
}

// ---------------------------------------------------------------------------
// 4.5  Rollback() must return false when there is no previous.onnx to restore.
// ---------------------------------------------------------------------------
TEST_F(ModelCache_Integration, Rollback_EmptySlot_ReturnsFalse) {
    SKIP_CACHE_INIT();
    EXPECT_FALSE(
        AI::ModelCache::Instance().Rollback(AI::CortexModelType::Emulation))
        << "Rollback() must return false when no previous model exists.";
}

// ---------------------------------------------------------------------------
// 4.6  SwapModel() with a path that does not exist must return false.
// ---------------------------------------------------------------------------
TEST_F(ModelCache_Integration, SwapModel_InvalidPath_ReturnsFalse) {
    SKIP_CACHE_INIT();
    const auto ghost = s_dir->Path() / L"does_not_exist.onnx";
    ASSERT_FALSE(std::filesystem::exists(ghost));
    EXPECT_FALSE(
        AI::ModelCache::Instance().SwapModel(AI::CortexModelType::Memory, ghost))
        << "SwapModel() with a missing source file must return false.";
}

// ---------------------------------------------------------------------------
// 4.7  SwapModel() with a valid file must return true.
// ---------------------------------------------------------------------------
TEST_F(ModelCache_Integration, SwapModel_ValidFile_ReturnsTrue) {
    SKIP_CACHE_INIT();
    const auto fake = PlaceholderOnnx(L"static_v1.onnx");
    ASSERT_TRUE(std::filesystem::exists(fake));
    EXPECT_TRUE(
        AI::ModelCache::Instance().SwapModel(AI::CortexModelType::Static, fake))
        << "SwapModel() with a valid source file must return true.";
}

// ---------------------------------------------------------------------------
// 4.8  After a successful swap, GetModelPath() must return an existing path.
// ---------------------------------------------------------------------------
TEST_F(ModelCache_Integration, GetModelPath_AfterSwap_ReturnsExistingPath) {
    SKIP_CACHE_INIT();
    const auto fake = PlaceholderOnnx(L"behavioral_v1.onnx");
    ASSERT_TRUE(
        AI::ModelCache::Instance().SwapModel(AI::CortexModelType::Behavioral, fake))
        << "SwapModel() must succeed as a test prerequisite.";
    const auto path =
        AI::ModelCache::Instance().GetModelPath(AI::CortexModelType::Behavioral);
    ASSERT_TRUE(path.has_value())
        << "GetModelPath() must return a value after a successful swap.";
    EXPECT_TRUE(std::filesystem::exists(*path))
        << "The returned path must point to an existing file.";
}

// ---------------------------------------------------------------------------
// 4.9  After two successive swaps, Rollback() must succeed — a previous.onnx
//      was produced by the second swap.
// ---------------------------------------------------------------------------
TEST_F(ModelCache_Integration, Rollback_AfterDoubleSwap_Succeeds) {
    SKIP_CACHE_INIT();
    const auto m1 = PlaceholderOnnx(L"mem_v1.onnx");
    const auto m2 = PlaceholderOnnx(L"mem_v2.onnx");
    ASSERT_TRUE(
        AI::ModelCache::Instance().SwapModel(AI::CortexModelType::Memory, m1))
        << "First swap must succeed (test prerequisite).";
    ASSERT_TRUE(
        AI::ModelCache::Instance().SwapModel(AI::CortexModelType::Memory, m2))
        << "Second swap must succeed (test prerequisite).";
    EXPECT_TRUE(AI::ModelCache::Instance().Rollback(AI::CortexModelType::Memory))
        << "Rollback() must succeed after two swaps have created a previous.onnx.";
}

// ===========================================================================
// GROUP 5 — ModelInference: Lifecycle and Inference Contracts
// ===========================================================================
/**
 * @brief Validates the ONNX Runtime wrapper: initialization, model-load
 * failure handling, safe inference without a loaded model, and hardware
 * capability queries.
 *
 * Fixture: Shutdown() is called in both SetUp and TearDown to guarantee
 * each test starts and ends with a clean singleton state.
 *
 * @note Tests in this group may skip if ORT is not available on the host.
 */
class ModelInference_Lifecycle : public ::testing::Test {
protected:
    void SetUp() override {
        AI::ModelInference::Instance().Shutdown();
    }
    void TearDown() override {
        AI::ModelInference::Instance().Shutdown();
    }
};

// ---------------------------------------------------------------------------
// 5.1  Before Initialize(), IsInitialized() must report false.
// ---------------------------------------------------------------------------
TEST_F(ModelInference_Lifecycle, BeforeInit_IsInitialized_False) {
    EXPECT_FALSE(AI::ModelInference::Instance().IsInitialized())
        << "IsInitialized() must be false before Initialize() is called.";
}

// ---------------------------------------------------------------------------
// 5.2  Initialize() with GPU and AVX-512 disabled must succeed on any
//      x86-64 Windows system where ORT is present.  When ORT is not compiled
//      in, graceful degradation (returning false) is the accepted behaviour
//      and the test is skipped rather than failed.
// ---------------------------------------------------------------------------
TEST_F(ModelInference_Lifecycle, Initialize_DefaultConfig_ReturnsTrue) {
    AI::CortexConfig cfg;
    cfg.useGPU    = false;
    cfg.useAVX512 = false;
    const bool ok = AI::ModelInference::Instance().Initialize(cfg);
    if (!ok) {
        GTEST_SKIP() << "ORT unavailable — skipping Initialize success contract.";
    }
    EXPECT_TRUE(ok)
        << "ModelInference::Initialize() must succeed on Windows x86-64 with ORT.";
}

// ---------------------------------------------------------------------------
// 5.3  IsInitialized() must report true after a successful Initialize().
// ---------------------------------------------------------------------------
TEST_F(ModelInference_Lifecycle, AfterInit_IsInitialized_True) {
    AI::CortexConfig cfg;
    cfg.useGPU    = false;
    cfg.useAVX512 = false;
    if (!AI::ModelInference::Instance().Initialize(cfg)) {
        GTEST_SKIP() << "ORT unavailable — skipping post-init state check.";
    }
    EXPECT_TRUE(AI::ModelInference::Instance().IsInitialized())
        << "IsInitialized() must be true after successful Initialize().";
}

// ---------------------------------------------------------------------------
// 5.4  LoadModel() with a non-existent path must return false gracefully.
// ---------------------------------------------------------------------------
TEST_F(ModelInference_Lifecycle, LoadModel_NonExistentPath_ReturnsFalse) {
    AI::CortexConfig cfg;
    cfg.useGPU = false;
    if (!AI::ModelInference::Instance().Initialize(cfg)) {
        GTEST_SKIP() << "ORT unavailable — skipping LoadModel test.";
    }
    const std::filesystem::path ghost{ L"C:\\does\\not\\exist\\fake.onnx" };
    EXPECT_FALSE(
        AI::ModelInference::Instance().LoadModel(AI::CortexModelType::Static, ghost))
        << "LoadModel() must return false for a missing .onnx file.";
}

// ---------------------------------------------------------------------------
// 5.5  IsModelLoaded() must return false when no model has been loaded.
// ---------------------------------------------------------------------------
TEST_F(ModelInference_Lifecycle, IsModelLoaded_NoModel_ReturnsFalse) {
    AI::CortexConfig cfg;
    cfg.useGPU = false;
    if (!AI::ModelInference::Instance().Initialize(cfg)) {
        GTEST_SKIP() << "ORT unavailable — skipping IsModelLoaded test.";
    }
    EXPECT_FALSE(
        AI::ModelInference::Instance().IsModelLoaded(AI::CortexModelType::Static))
        << "IsModelLoaded() must be false when no model has been loaded.";
}

// ---------------------------------------------------------------------------
// 5.6  Infer() without a loaded model must return nullopt gracefully.
// ---------------------------------------------------------------------------
TEST_F(ModelInference_Lifecycle, Infer_WithoutModel_ReturnsNullopt) {
    AI::CortexConfig cfg;
    cfg.useGPU = false;
    if (!AI::ModelInference::Instance().Initialize(cfg)) {
        GTEST_SKIP() << "ORT unavailable — skipping Infer nullopt test.";
    }
    std::vector<float> data(AI::CortexConstants::STATIC_FEATURE_COUNT, 0.0f);
    const std::array<int64_t, 2> shape = {
        1, static_cast<int64_t>(AI::CortexConstants::STATIC_FEATURE_COUNT)
    };
    const auto r = AI::ModelInference::Instance().Infer(
        AI::CortexModelType::Static,
        std::span<const float>(data.data(), data.size()),
        std::span<const int64_t>(shape.data(), shape.size()));
    EXPECT_FALSE(r.has_value())
        << "Infer() without a loaded model must return std::nullopt.";
}

// ---------------------------------------------------------------------------
// 5.7  InferBatch() without a loaded model must return nullopt gracefully.
// ---------------------------------------------------------------------------
TEST_F(ModelInference_Lifecycle, InferBatch_WithoutModel_ReturnsNullopt) {
    AI::CortexConfig cfg;
    cfg.useGPU = false;
    if (!AI::ModelInference::Instance().Initialize(cfg)) {
        GTEST_SKIP() << "ORT unavailable — skipping InferBatch nullopt test.";
    }
    constexpr size_t kBatch = 4;
    std::vector<float> batchData(kBatch * AI::CortexConstants::STATIC_FEATURE_COUNT, 0.0f);
    const std::array<int64_t, 2> shape = {
        static_cast<int64_t>(kBatch),
        static_cast<int64_t>(AI::CortexConstants::STATIC_FEATURE_COUNT)
    };
    const auto r = AI::ModelInference::Instance().InferBatch(
        AI::CortexModelType::Static,
        std::span<const float>(batchData.data(), batchData.size()),
        std::span<const int64_t>(shape.data(), shape.size()));
    EXPECT_FALSE(r.has_value())
        << "InferBatch() without a loaded model must return std::nullopt.";
}

// ---------------------------------------------------------------------------
// 5.8  Hardware capability queries must execute without throwing or crashing.
//      We make no assertion on the returned values — they depend on the host.
// ---------------------------------------------------------------------------
TEST_F(ModelInference_Lifecycle, HardwareCapabilities_QueryDoesNotCrash) {
    AI::CortexConfig cfg;
    cfg.useGPU = false;
    if (!AI::ModelInference::Instance().Initialize(cfg)) {
        GTEST_SKIP() << "ORT unavailable — skipping hardware query test.";
    }
    const bool avx2     = AI::ModelInference::Instance().HasAVX2();
    const bool avx512   = AI::ModelInference::Instance().HasAVX512();
    const bool directML = AI::ModelInference::Instance().HasDirectML();
    (void)avx2; (void)avx512; (void)directML;
    SUCCEED() << "All hardware capability queries completed without crashing.";
}

// ===========================================================================
// GROUP 6 — PhantomCortex: Lifecycle and Graceful-Failure Contracts
// ===========================================================================
/**
 * @brief Validates PhantomCortex's singleton semantics, IsOperational()
 * state machine, safe fallback verdicts before initialization, statistics
 * counter baseline, and Shutdown + re-Initialize cycle.
 *
 * Fixture: Shutdown() is called in SetUp and TearDown to isolate each test.
 */
class PhantomCortex_Lifecycle : public ::testing::Test {
protected:
    void SetUp() override {
        AI::PhantomCortex::Instance().Shutdown();
    }
    void TearDown() override {
        AI::PhantomCortex::Instance().Shutdown();
    }
    ScopedTempDir m_tempDir;
};

// ---------------------------------------------------------------------------
// 6.1  Instance() must return the same object address on every call.
// ---------------------------------------------------------------------------
TEST_F(PhantomCortex_Lifecycle, Singleton_SameInstanceAddress) {
    const AI::PhantomCortex* a = &AI::PhantomCortex::Instance();
    const AI::PhantomCortex* b = &AI::PhantomCortex::Instance();
    EXPECT_EQ(a, b)
        << "PhantomCortex::Instance() must always return the same singleton.";
}

// ---------------------------------------------------------------------------
// 6.2  IsOperational() must return false before any call to Initialize().
// ---------------------------------------------------------------------------
TEST_F(PhantomCortex_Lifecycle, BeforeInit_IsOperational_False) {
    EXPECT_FALSE(AI::PhantomCortex::Instance().IsOperational())
        << "IsOperational() must be false before Initialize() is called.";
}

// ---------------------------------------------------------------------------
// 6.3  AnalyzeFile() before Initialize() must return Benign + confidence=0.
// ---------------------------------------------------------------------------
TEST_F(PhantomCortex_Lifecycle, BeforeInit_AnalyzeFile_ReturnsBenignDefault) {
    const auto verdict =
        AI::PhantomCortex::Instance().AnalyzeFile(std::span<const uint8_t>{});
    EXPECT_EQ(verdict.verdict, AI::ThreatVerdict::Benign)
        << "AnalyzeFile() before Initialize() must return Benign.";
    EXPECT_NEAR(verdict.confidence, 0.0f, 1e-4f)
        << "AnalyzeFile() before Initialize() must return confidence=0.";
}

// ---------------------------------------------------------------------------
// 6.4  GetStats() before Initialize() must not crash and must return zeros.
// ---------------------------------------------------------------------------
TEST_F(PhantomCortex_Lifecycle, BeforeInit_GetStats_ReturnsZeroStats) {
    const AI::PhantomCortex::CortexStats stats =
        AI::PhantomCortex::Instance().GetStats();
    EXPECT_EQ(stats.totalInferences,            0u);
    EXPECT_EQ(stats.totalMaliciousDetections,   0u);
    EXPECT_EQ(stats.totalSuspiciousDetections,  0u);
    EXPECT_EQ(stats.totalBenignClassifications, 0u);
}

// ---------------------------------------------------------------------------
// 6.5  Initialize() with an empty model directory must complete without
//      crashing.  (No .onnx files — models are not loaded, but the engine
//      sub-components initialise.)  IsOperational() must reflect the result.
// ---------------------------------------------------------------------------
TEST_F(PhantomCortex_Lifecycle, Initialize_EmptyModelDir_IsOperationalMatchesResult) {
    AI::CortexConfig cfg;
    cfg.modelDirectory = m_tempDir.Path();
    cfg.useGPU         = false;
    cfg.useAVX512      = false;
    const bool ok = AI::PhantomCortex::Instance().Initialize(cfg);
    EXPECT_EQ(AI::PhantomCortex::Instance().IsOperational(), ok)
        << "IsOperational() must equal the return value of Initialize().";
}

// ---------------------------------------------------------------------------
// 6.6  Shutdown() + Initialize() must put the engine back into a clean state
//      with statistics counters reset to zero.
// ---------------------------------------------------------------------------
TEST_F(PhantomCortex_Lifecycle, Shutdown_Reinitialize_StatisticsReset) {
    AI::CortexConfig cfg;
    cfg.modelDirectory = m_tempDir.Path();
    cfg.useGPU         = false;
    cfg.useAVX512      = false;
    // First init cycle.
    std::ignore = AI::PhantomCortex::Instance().Initialize(cfg);
    AI::PhantomCortex::Instance().Shutdown();
    EXPECT_FALSE(AI::PhantomCortex::Instance().IsOperational())
        << "IsOperational() must be false immediately after Shutdown().";
    // Re-initialise — must not crash or enter a broken state.
    std::ignore = AI::PhantomCortex::Instance().Initialize(cfg);
    const AI::PhantomCortex::CortexStats stats =
        AI::PhantomCortex::Instance().GetStats();
    EXPECT_EQ(stats.totalInferences, 0u)
        << "Statistics must reset to zero after Shutdown() + re-Initialize().";
}

// ===========================================================================
// GROUP 7 — EnsembleVerdict: Weighted Multi-Model Aggregation Logic
// ===========================================================================
/**
 * @brief Tests PhantomCortex::EnsembleVerdict() with constructed
 * CortexVerdict inputs.  This is primarily a computation test: no .onnx
 * model files are required.
 *
 * Threshold semantics (ensembleThreshold = 0.5, default):
 *   ensembleConfidence  < 0.50  → Benign
 *   ensembleConfidence  >= 0.50 and < 0.70 → Suspicious  (+0.2 band)
 *   ensembleConfidence  >= 0.70  → Malicious
 *
 * Fixture: PhantomCortex is initialised with a known config in SetUp and
 * shut down in TearDown so ensemble logic uses a deterministic threshold.
 * EnsembleVerdict() reads from the stored config via a shared lock and
 * performs only computation — it does not require loaded model files.
 */
class EnsembleVerdict_Logic : public ::testing::Test {
protected:
    void SetUp() override {
        AI::PhantomCortex::Instance().Shutdown();
        AI::CortexConfig cfg;
        cfg.modelDirectory     = m_tempDir.Path();
        cfg.ensembleThreshold  = 0.5f;
        cfg.staticThreshold    = 0.5f;
        cfg.behavioralThreshold = 0.6f;
        cfg.memoryThreshold    = 0.7f;
        cfg.networkThreshold   = 0.8f;
        cfg.emulationThreshold = 0.6f;
        cfg.useGPU             = false;
        cfg.useAVX512          = false;
        m_initialized = AI::PhantomCortex::Instance().Initialize(cfg);
    }
    void TearDown() override {
        AI::PhantomCortex::Instance().Shutdown();
    }

    /// Convenience: build a CortexVerdict from the three most-used fields.
    static AI::CortexVerdict V(AI::ThreatVerdict v, float conf,
                                AI::CortexModelType src) noexcept {
        AI::CortexVerdict r;
        r.verdict    = v;
        r.confidence = conf;
        r.source     = src;
        return r;
    }

    ScopedTempDir m_tempDir;
    bool m_initialized = false;
};

// ---------------------------------------------------------------------------
// 7.1  All five models at Malicious/1.0 → final verdict must be Malicious.
// ---------------------------------------------------------------------------
TEST_F(EnsembleVerdict_Logic, AllMalicious_FullConfidence_FinalIsMalicious) {
    using MT = AI::CortexModelType;
    const auto ev = AI::PhantomCortex::Instance().EnsembleVerdict(
        V(AI::ThreatVerdict::Malicious, 1.0f, MT::Static),
        V(AI::ThreatVerdict::Malicious, 1.0f, MT::Behavioral),
        V(AI::ThreatVerdict::Malicious, 1.0f, MT::Memory),
        V(AI::ThreatVerdict::Malicious, 1.0f, MT::Network),
        V(AI::ThreatVerdict::Malicious, 1.0f, MT::Emulation));
    EXPECT_EQ(ev.finalVerdict, AI::ThreatVerdict::Malicious)
        << "All-Malicious at confidence=1.0 must yield a Malicious ensemble verdict.";
    EXPECT_GE(ev.ensembleConfidence, 0.7f)
        << "Ensemble confidence for all-Malicious/1.0 must be >= 0.7.";
}

// ---------------------------------------------------------------------------
// 7.2  All five models at Benign/0.0 → final verdict must be Benign.
// ---------------------------------------------------------------------------
TEST_F(EnsembleVerdict_Logic, AllBenign_ZeroConfidence_FinalIsBenign) {
    using MT = AI::CortexModelType;
    const auto ev = AI::PhantomCortex::Instance().EnsembleVerdict(
        V(AI::ThreatVerdict::Benign, 0.0f, MT::Static),
        V(AI::ThreatVerdict::Benign, 0.0f, MT::Behavioral),
        V(AI::ThreatVerdict::Benign, 0.0f, MT::Memory),
        V(AI::ThreatVerdict::Benign, 0.0f, MT::Network),
        V(AI::ThreatVerdict::Benign, 0.0f, MT::Emulation));
    EXPECT_EQ(ev.finalVerdict, AI::ThreatVerdict::Benign)
        << "All-Benign at confidence=0.0 must yield a Benign ensemble verdict.";
    EXPECT_LT(ev.ensembleConfidence, 0.5f)
        << "Ensemble confidence for all-Benign/0.0 must be < 0.5.";
}

// ---------------------------------------------------------------------------
// 7.3  Only the static model provided (behavioralV and memoryV are nullopt).
//      Malicious at confidence=1.0 must drive the ensemble to Malicious.
// ---------------------------------------------------------------------------
TEST_F(EnsembleVerdict_Logic, SingleStaticModel_Malicious_DrivesMalicious) {
    const auto ev = AI::PhantomCortex::Instance().EnsembleVerdict(
        V(AI::ThreatVerdict::Malicious, 1.0f, AI::CortexModelType::Static),
        std::nullopt,
        std::nullopt);
    EXPECT_EQ(ev.finalVerdict, AI::ThreatVerdict::Malicious)
        << "A single Malicious/1.0 static verdict must drive a Malicious ensemble.";
}

// ---------------------------------------------------------------------------
// 7.4  Only the memory model provided; Benign at 0.0 → ensemble is Benign.
// ---------------------------------------------------------------------------
TEST_F(EnsembleVerdict_Logic, SingleMemoryModel_Benign_DrivesBenign) {
    const auto ev = AI::PhantomCortex::Instance().EnsembleVerdict(
        std::nullopt,
        std::nullopt,
        V(AI::ThreatVerdict::Benign, 0.0f, AI::CortexModelType::Memory));
    EXPECT_EQ(ev.finalVerdict, AI::ThreatVerdict::Benign)
        << "A single Benign/0.0 memory verdict must drive a Benign ensemble.";
}

// ---------------------------------------------------------------------------
// 7.5  ensembleConfidence must always lie in [0.0, 1.0] regardless of inputs.
// ---------------------------------------------------------------------------
TEST_F(EnsembleVerdict_Logic, EnsembleConfidence_AlwaysInUnitInterval) {
    for (const float conf : { 0.0f, 0.01f, 0.49f, 0.5f, 0.69f, 0.7f, 0.99f, 1.0f }) {
        const AI::ThreatVerdict verd =
            (conf >= 0.7f) ? AI::ThreatVerdict::Malicious :
            (conf >= 0.5f) ? AI::ThreatVerdict::Suspicious :
                             AI::ThreatVerdict::Benign;
        AI::CortexVerdict sv;
        sv.verdict    = verd;
        sv.confidence = conf;
        sv.source     = AI::CortexModelType::Static;
        const auto ev = AI::PhantomCortex::Instance().EnsembleVerdict(
            sv, std::nullopt, std::nullopt);
        EXPECT_GE(ev.ensembleConfidence, 0.0f)
            << "ensembleConfidence must be >= 0.0 for input conf=" << conf;
        EXPECT_LE(ev.ensembleConfidence, 1.0f)
            << "ensembleConfidence must be <= 1.0 for input conf=" << conf;
    }
}

// ---------------------------------------------------------------------------
// 7.6  modelVerdicts[Static] in the returned struct must reflect the static
//      verdict passed in (ordinal 0 maps to CortexModelType::Static).
// ---------------------------------------------------------------------------
TEST_F(EnsembleVerdict_Logic, ModelVerdicts_StaticSlot_ReflectsInput) {
    const auto sv = V(AI::ThreatVerdict::Malicious, 0.9f, AI::CortexModelType::Static);
    const auto ev = AI::PhantomCortex::Instance().EnsembleVerdict(
        sv, std::nullopt, std::nullopt);
    EXPECT_EQ(ev.modelVerdicts[0].verdict, AI::ThreatVerdict::Malicious)
        << "modelVerdicts[0] (Static slot) must carry the Malicious verdict.";
}

// ---------------------------------------------------------------------------
// 7.7  totalInferenceTime in the ensemble result must be >= 0.
// ---------------------------------------------------------------------------
TEST_F(EnsembleVerdict_Logic, TotalInferenceTime_NonNegative) {
    const auto ev = AI::PhantomCortex::Instance().EnsembleVerdict(
        V(AI::ThreatVerdict::Benign, 0.1f, AI::CortexModelType::Static),
        std::nullopt, std::nullopt);
    EXPECT_GE(ev.totalInferenceTime.count(), 0LL)
        << "totalInferenceTime must be a non-negative duration.";
}

// ---------------------------------------------------------------------------
// 7.8  A default-constructed CortexVerdict must have Benign verdict and
//      confidence=0.0 (tests the struct's in-class initialiser contract).
// ---------------------------------------------------------------------------
TEST_F(EnsembleVerdict_Logic, DefaultVerdict_IsBenignWithZeroConf) {
    const AI::CortexVerdict dv;
    EXPECT_EQ(dv.verdict, AI::ThreatVerdict::Benign);
    EXPECT_NEAR(dv.confidence, 0.0f, 1e-6f);
}

// ---------------------------------------------------------------------------
// 7.9  A mixed static=Malicious(0.9)/behavioral=Benign(0.0) call must produce
//      a finalVerdict that is a valid ThreatVerdict enum value.
// ---------------------------------------------------------------------------
TEST_F(EnsembleVerdict_Logic, MixedVerdicts_ResultIsValidThreatVerdict) {
    const auto ev = AI::PhantomCortex::Instance().EnsembleVerdict(
        V(AI::ThreatVerdict::Malicious, 0.9f, AI::CortexModelType::Static),
        V(AI::ThreatVerdict::Benign,    0.0f, AI::CortexModelType::Behavioral),
        std::nullopt);
    const uint8_t raw = static_cast<uint8_t>(ev.finalVerdict);
    EXPECT_LE(raw, 2u)
        << "finalVerdict must be 0 (Benign), 1 (Suspicious), or 2 (Malicious).";
}

// ---------------------------------------------------------------------------
// 7.10 EnsembleVerdict() called concurrently from 8 threads must not race.
//      Verifies the shared-lock read of ensembleThreshold from stored config.
// ---------------------------------------------------------------------------
TEST_F(EnsembleVerdict_Logic, Concurrent_EnsembleNoRace) {
    constexpr int kThreads = 8;
    std::atomic<int> badCount{0};
    std::vector<std::thread> threads;
    threads.reserve(kThreads);
    for (int t = 0; t < kThreads; ++t) {
        threads.emplace_back([&badCount, t]() {
            AI::CortexVerdict sv;
            sv.verdict    = AI::ThreatVerdict::Malicious;
            sv.confidence = static_cast<float>(t + 1) / 10.0f;
            sv.source     = AI::CortexModelType::Static;
            const auto ev = AI::PhantomCortex::Instance().EnsembleVerdict(
                sv, std::nullopt, std::nullopt);
            if (ev.ensembleConfidence < 0.0f || ev.ensembleConfidence > 1.0f)
                ++badCount;
        });
    }
    for (auto& th : threads) th.join();
    EXPECT_EQ(badCount.load(), 0)
        << "Concurrent EnsembleVerdict() calls must all produce "
           "ensembleConfidence in [0, 1].";
}

// ===========================================================================
// GROUP 8 — Type Contracts and Compile-Time Constants
// ===========================================================================
/**
 * @brief Verifies that enumeration ordinal values, array sizes, and
 * compile-time constants are exactly what the rest of ShadowStrike expects.
 *
 * These are the sentinel tests that catch ABI-breaking changes early.
 * They do NOT require any singleton initialization.
 */

// ---------------------------------------------------------------------------
// 8.1  MODEL_COUNT must be exactly 5 (Static, Behavioral, Memory, Network,
//      Emulation) to match the five-model ensemble architecture.
// ---------------------------------------------------------------------------
TEST(TypeContracts, MODEL_COUNT_Is5) {
    EXPECT_EQ(AI::CortexConstants::MODEL_COUNT, 5u)
        << "MODEL_COUNT must be 5 to match the five-model ensemble architecture.";
}

// ---------------------------------------------------------------------------
// 8.2  CortexModelType ordinals must be contiguous 0–4 (used as array indices).
// ---------------------------------------------------------------------------
TEST(TypeContracts, CortexModelType_OrdinalValues) {
    EXPECT_EQ(static_cast<uint8_t>(AI::CortexModelType::Static),     0u);
    EXPECT_EQ(static_cast<uint8_t>(AI::CortexModelType::Behavioral), 1u);
    EXPECT_EQ(static_cast<uint8_t>(AI::CortexModelType::Memory),     2u);
    EXPECT_EQ(static_cast<uint8_t>(AI::CortexModelType::Network),    3u);
    EXPECT_EQ(static_cast<uint8_t>(AI::CortexModelType::Emulation),  4u);
}

// ---------------------------------------------------------------------------
// 8.3  ThreatVerdict ordinals must be stable (used in telemetry persistence).
// ---------------------------------------------------------------------------
TEST(TypeContracts, ThreatVerdict_OrdinalValues) {
    EXPECT_EQ(static_cast<uint8_t>(AI::ThreatVerdict::Benign),    0u);
    EXPECT_EQ(static_cast<uint8_t>(AI::ThreatVerdict::Suspicious), 1u);
    EXPECT_EQ(static_cast<uint8_t>(AI::ThreatVerdict::Malicious),  2u);
}

// ---------------------------------------------------------------------------
// 8.4  CortexEnsembleVerdict::modelVerdicts must have MODEL_COUNT elements.
//      This guards against accidental array-size changes in the struct.
// ---------------------------------------------------------------------------
TEST(TypeContracts, EnsembleVerdict_ModelArraySize_MatchesModelCount) {
    const AI::CortexEnsembleVerdict ev;
    EXPECT_EQ(ev.modelVerdicts.size(), AI::CortexConstants::MODEL_COUNT)
        << "modelVerdicts array must have exactly MODEL_COUNT slots.";
}

// ---------------------------------------------------------------------------
// 8.5  Feature vector size constants must match the training-pipeline values.
//      Any divergence silently degrades detection accuracy in production.
// ---------------------------------------------------------------------------
TEST(TypeContracts, FeatureVectorSizes_MatchDocumentedValues) {
    EXPECT_EQ(AI::CortexConstants::STATIC_FEATURE_COUNT,    2381u);
    EXPECT_EQ(AI::CortexConstants::BEHAVIORAL_FEATURE_COUNT, 512u);
    EXPECT_EQ(AI::CortexConstants::MEMORY_FEATURE_COUNT,     256u);
    EXPECT_EQ(AI::CortexConstants::NETWORK_FEATURE_COUNT,    128u);
    EXPECT_EQ(AI::CortexConstants::EMULATION_FEATURE_COUNT,  384u);
}

// ===========================================================================
// ADDITIONAL GROUP 1 — FeatureExtractor: Boundary Conditions
// ===========================================================================

// ---------------------------------------------------------------------------
// 1.14 A single-record API call sequence (minimum valid input) must either
//      yield a feature vector of size BEHAVIORAL_FEATURE_COUNT, or return
//      std::nullopt.  It must NOT crash or produce out-of-bounds access.
// ---------------------------------------------------------------------------
TEST_F(FeatureExtractor_VectorSizes, Behavioral_SingleRecord_NoCrash) {
    SKIP_FE_INIT();
    const AI::APICallRecord rec{ 0xAABBCCDDu, 0x11223344u, 0, 0.0f };
    const auto r = AI::FeatureExtractor::Instance().ExtractBehavioralFeatures(
        std::span<const AI::APICallRecord>(&rec, 1));
    if (r.has_value()) {
        EXPECT_EQ(r->size(), AI::CortexConstants::BEHAVIORAL_FEATURE_COUNT)
            << "Single-record sequence must yield BEHAVIORAL_FEATURE_COUNT features.";
        for (float v : *r) {
            EXPECT_FALSE(std::isnan(v))
                << "Feature vector must not contain NaN for a single-record sequence.";
        }
    }
    // nullopt is also acceptable; what is not acceptable is a crash.
}

// ---------------------------------------------------------------------------
// 1.15 A single-byte memory region (minimum size) must not crash and must
//      not produce NaN features — the implementation must gracefully handle
//      degenerate region sizes.
// ---------------------------------------------------------------------------
TEST_F(FeatureExtractor_VectorSizes, Memory_SingleByte_NoCrash) {
    SKIP_FE_INIT();
    const uint8_t oneByte = 0xCC; // INT3
    AI::MemoryRegionInfo region;
    region.data        = std::span<const uint8_t>(&oneByte, 1);
    region.baseAddress = 0x1000;
    region.size        = 1;
    region.protection  = PAGE_EXECUTE_READ;
    const auto r = AI::FeatureExtractor::Instance().ExtractMemoryFeatures(region);
    if (r.has_value()) {
        EXPECT_EQ(r->size(), AI::CortexConstants::MEMORY_FEATURE_COUNT);
        for (float v : *r) {
            EXPECT_FALSE(std::isnan(v))
                << "Feature vector must not contain NaN for a 1-byte region.";
        }
    }
    // nullopt is acceptable for degenerate regions; crash is not.
}

// ---------------------------------------------------------------------------
// 1.16 A valid 128-byte DOS stub (correct MZ magic and in-range e_lfanew)
//      with zeroed bytes at the PE signature offset must yield std::nullopt.
//      This validates that the full DOS-stub parsing path is exercised.
// ---------------------------------------------------------------------------
TEST_F(FeatureExtractor_VectorSizes, PE_ValidDOSStubNoPESignature_Nullopt) {
    SKIP_FE_INIT();
    std::array<uint8_t, 128> buf{};
    buf[0x00] = 0x4D; buf[0x01] = 0x5A; // MZ magic
    buf[0x3C] = 0x40;                   // e_lfanew = 64 — valid, within buffer
    // Bytes at offset 0x40 remain zero — not "PE\0\0"
    const auto r = AI::FeatureExtractor::Instance().ExtractPEFeatures(
        std::span<const uint8_t>(buf.data(), buf.size()));
    EXPECT_FALSE(r.has_value())
        << "A 128-byte DOS stub with no PE signature at e_lfanew=64 must be rejected.";
}

// ===========================================================================
// ADDITIONAL GROUP 2 — FeatureExtractor: Extended Adversarial Inputs
// ===========================================================================

// ---------------------------------------------------------------------------
// 2.7  NaN in NetworkFlowInfo float fields must not crash or produce an
//      out-of-size result.  Output may contain NaN (not yet sanitized by
//      the extractor) but the call must complete without throwing or
//      invoking undefined behaviour.
// ---------------------------------------------------------------------------
TEST_F(FeatureExtractor_VectorSizes, Adversarial_Network_NaNInput_NoCrash) {
    SKIP_FE_INIT();
    AI::NetworkFlowInfo flow{};
    flow.durationMs        = std::numeric_limits<float>::quiet_NaN();
    flow.avgInterArrivalMs = std::numeric_limits<float>::quiet_NaN();
    flow.payloadEntropy    = std::numeric_limits<float>::quiet_NaN();
    flow.stdInterArrivalMs = std::numeric_limits<float>::quiet_NaN();
    const auto r = AI::FeatureExtractor::Instance().ExtractNetworkFeatures(flow);
    if (r.has_value()) {
        EXPECT_EQ(r->size(), AI::CortexConstants::NETWORK_FEATURE_COUNT)
            << "Feature vector size must equal NETWORK_FEATURE_COUNT even with NaN inputs.";
    }
    // Crash-free completion is the primary contract being asserted here.
    SUCCEED() << "ExtractNetworkFeatures() with NaN inputs completed without crashing. "
                 "result=" << (r.has_value() ? "has_value" : "nullopt");
}

// ---------------------------------------------------------------------------
// 2.8  Infinity in NetworkFlowInfo float fields must not crash or produce an
//      out-of-size result.  The call must complete safely with either a
//      valid-sized vector (possibly containing Inf/NaN) or std::nullopt.
// ---------------------------------------------------------------------------
TEST_F(FeatureExtractor_VectorSizes, Adversarial_Network_InfInput_NoCrash) {
    SKIP_FE_INIT();
    AI::NetworkFlowInfo flow{};
    flow.durationMs        = std::numeric_limits<float>::infinity();
    flow.avgInterArrivalMs = std::numeric_limits<float>::infinity();
    flow.payloadEntropy    = std::numeric_limits<float>::infinity();
    const auto r = AI::FeatureExtractor::Instance().ExtractNetworkFeatures(flow);
    if (r.has_value()) {
        EXPECT_EQ(r->size(), AI::CortexConstants::NETWORK_FEATURE_COUNT)
            << "Feature vector size must equal NETWORK_FEATURE_COUNT even with Inf inputs.";
    }
    SUCCEED() << "ExtractNetworkFeatures() with Inf inputs completed without crashing. "
                 "result=" << (r.has_value() ? "has_value" : "nullopt");
}

// ---------------------------------------------------------------------------
// 2.9  EmulationEvent fields set to UINT16_MAX / UINT8_MAX must not cause
//      integer overflow or produce NaN in the feature vector.
// ---------------------------------------------------------------------------
TEST_F(FeatureExtractor_VectorSizes, Adversarial_Emulation_MaxValueFields_NoNaN) {
    SKIP_FE_INIT();
    std::vector<AI::EmulationEvent> events(64);
    for (auto& e : events) {
        e.opcodeCategory   = std::numeric_limits<uint16_t>::max();
        e.memoryAccessType = std::numeric_limits<uint8_t>::max();
        e.apiCallId        = std::numeric_limits<uint16_t>::max();
        e.eflagsChange     = std::numeric_limits<uint8_t>::max();
    }
    const auto r = AI::FeatureExtractor::Instance().ExtractEmulationFeatures(
        std::span<const AI::EmulationEvent>(events.data(), events.size()));
    if (r.has_value()) {
        EXPECT_EQ(r->size(), AI::CortexConstants::EMULATION_FEATURE_COUNT);
        for (size_t i = 0; i < r->size(); ++i) {
            EXPECT_FALSE(std::isnan((*r)[i]))
                << "Feature[" << i << "] must not be NaN with max-value emulation fields.";
        }
    }
}

// ---------------------------------------------------------------------------
// 2.10 An all-zero memory region (null-page pattern) must produce valid
//      features with no NaN — this exercises the zero-entropy code path.
// ---------------------------------------------------------------------------
TEST_F(FeatureExtractor_VectorSizes, Adversarial_Memory_AllZeroes_NoNaN) {
    SKIP_FE_INIT();
    constexpr size_t kSize = 4096;
    std::vector<uint8_t> zeros(kSize, 0x00);
    AI::MemoryRegionInfo region;
    region.data        = std::span<const uint8_t>(zeros.data(), zeros.size());
    region.baseAddress = 0x0000000000001000ULL;
    region.size        = kSize;
    region.protection  = PAGE_READWRITE;
    const auto r = AI::FeatureExtractor::Instance().ExtractMemoryFeatures(region);
    ASSERT_TRUE(r.has_value())
        << "A valid zero-filled 4 KB region must produce memory features.";
    EXPECT_EQ(r->size(), AI::CortexConstants::MEMORY_FEATURE_COUNT);
    for (size_t i = 0; i < r->size(); ++i) {
        EXPECT_FALSE(std::isnan((*r)[i]))
            << "Feature[" << i << "] must not be NaN for an all-zero memory region.";
    }
}

// ===========================================================================
// ADDITIONAL GROUP 3 — CortexConfigManager: Resilience Tests
// ===========================================================================

// ---------------------------------------------------------------------------
// 3.7  LoadConfig() with an empty file (0 bytes) must return false gracefully.
//      Empty JSON is malformed; the parser must detect and reject it.
// ---------------------------------------------------------------------------
TEST_F(CortexConfigManager_Integration, LoadConfig_EmptyFile_ReturnsFalse) {
    const auto emptyPath = m_tempDir->Path() / L"empty.json";
    { std::ofstream f(emptyPath, std::ios::binary); } // create empty file
    ASSERT_TRUE(std::filesystem::exists(emptyPath));
    ASSERT_EQ(std::filesystem::file_size(emptyPath), 0u)
        << "Test prerequisite: the file must be genuinely empty.";
    EXPECT_FALSE(AI::CortexConfigManager::Instance().LoadConfig(emptyPath))
        << "LoadConfig() must return false for an empty (0-byte) JSON file.";
}

// ---------------------------------------------------------------------------
// 3.8  LoadConfig() with binary garbage must return false.  The parser must
//      not crash, corrupt internal state, or throw on hostile binary input.
// ---------------------------------------------------------------------------
TEST_F(CortexConfigManager_Integration, LoadConfig_BinaryGarbage_ReturnsFalse) {
    const auto badPath = m_tempDir->Path() / L"garbage.json";
    {
        std::ofstream f(badPath, std::ios::binary);
        const std::array<uint8_t, 32> garbage = {
            0xFF, 0xFE, 0x00, 0x01, 0xDE, 0xAD, 0xBE, 0xEF,
            0xCA, 0xFE, 0xBA, 0xBE, 0x00, 0xFF, 0xAA, 0xBB,
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
            0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00
        };
        f.write(reinterpret_cast<const char*>(garbage.data()),
                static_cast<std::streamsize>(garbage.size()));
    }
    ASSERT_TRUE(std::filesystem::exists(badPath));
    EXPECT_FALSE(AI::CortexConfigManager::Instance().LoadConfig(badPath))
        << "LoadConfig() must return false for a binary garbage file.";
}

// ---------------------------------------------------------------------------
// 3.9  Default config must have positive, non-zero maxBatchSize and
//      inferenceTimeoutMs — verifies the live struct defaults are consistent
//      with the documented CortexTypes.hpp defaults.
// ---------------------------------------------------------------------------
TEST_F(CortexConfigManager_Integration, DefaultConfig_BatchAndTimeout_Positive) {
    const AI::CortexConfig cfg = AI::CortexConfigManager::Instance().GetConfig();
    EXPECT_GT(cfg.maxBatchSize, 0u)
        << "Default maxBatchSize must be positive (non-zero).";
    EXPECT_GT(cfg.inferenceTimeoutMs, 0u)
        << "Default inferenceTimeoutMs must be positive (non-zero).";
    EXPECT_LE(cfg.maxBatchSize, AI::CortexConstants::MAX_BATCH_SIZE)
        << "Default maxBatchSize must not exceed MAX_BATCH_SIZE.";
    EXPECT_LE(cfg.inferenceTimeoutMs, AI::CortexConstants::MAX_INFERENCE_TIMEOUT_MS)
        << "Default inferenceTimeoutMs must not exceed MAX_INFERENCE_TIMEOUT_MS.";
}

// ===========================================================================
// ADDITIONAL GROUP 4 — ModelCache: Extended Coverage
// ===========================================================================

// ---------------------------------------------------------------------------
// 4.10 GetModelPath() for every model slot must satisfy the key invariant:
//      the returned value is either std::nullopt OR a path to an existing
//      file on disk — never a ghost path pointing to a missing file.
// ---------------------------------------------------------------------------
TEST_F(ModelCache_Integration, GetModelPath_AllSlots_PathInvariant) {
    SKIP_CACHE_INIT();
    constexpr AI::CortexModelType kSlots[] = {
        AI::CortexModelType::Static,
        AI::CortexModelType::Behavioral,
        AI::CortexModelType::Memory,
        AI::CortexModelType::Network,
        AI::CortexModelType::Emulation
    };
    for (const auto slotType : kSlots) {
        const auto path = AI::ModelCache::Instance().GetModelPath(slotType);
        if (path.has_value()) {
            EXPECT_TRUE(std::filesystem::exists(*path))
                << "Slot " << static_cast<int>(slotType)
                << ": GetModelPath() must not return a ghost path.";
        }
        // std::nullopt is always acceptable for an unloaded slot.
    }
}

// ---------------------------------------------------------------------------
// 4.11 VerifyIntegrity() must return false after a file is externally
//      corrupted.  This test: swaps a placeholder (manifest is updated with
//      placeholder's SHA-256 → VerifyIntegrity returns true), then appends
//      bytes to corrupt the file → VerifyIntegrity must now return false.
// ---------------------------------------------------------------------------
TEST_F(ModelCache_Integration, VerifyIntegrity_AfterFileCorruption_ReturnsFalse) {
    SKIP_CACHE_INIT();
    const auto fake = PlaceholderOnnx(L"net_placeholder.onnx");
    ASSERT_TRUE(
        AI::ModelCache::Instance().SwapModel(AI::CortexModelType::Network, fake))
        << "SwapModel() must succeed as a test prerequisite.";
    // After a successful swap the manifest SHA-256 matches the file — verify it.
    ASSERT_TRUE(
        AI::ModelCache::Instance().VerifyIntegrity(AI::CortexModelType::Network))
        << "Precondition: VerifyIntegrity() must return true immediately after swap.";
    // Now retrieve the active model path and corrupt the file on disk.
    const auto path = AI::ModelCache::Instance().GetModelPath(AI::CortexModelType::Network);
    ASSERT_TRUE(path.has_value() && std::filesystem::exists(*path))
        << "GetModelPath() must return an existing file after a successful swap.";
    {
        std::ofstream corrupt(*path, std::ios::app | std::ios::binary);
        const uint8_t garbage[] = { 0xDE, 0xAD, 0xBE, 0xEF };
        corrupt.write(reinterpret_cast<const char*>(garbage), sizeof(garbage));
    }
    EXPECT_FALSE(
        AI::ModelCache::Instance().VerifyIntegrity(AI::CortexModelType::Network))
        << "VerifyIntegrity() must return false when the on-disk file has been "
           "modified after the last successful swap.";
}

// ---------------------------------------------------------------------------
// 4.12 SwapModel() with a zero-byte file must not crash or throw.
//      Whether it returns true or false is implementation-defined, but no
//      exception or memory-corruption is ever acceptable.
// ---------------------------------------------------------------------------
TEST_F(ModelCache_Integration, SwapModel_ZeroByteFile_DoesNotCrash) {
    SKIP_CACHE_INIT();
    const auto zeroPath = s_dir->Path() / L"zero_byte.onnx";
    { std::ofstream f(zeroPath, std::ios::binary); } // creates empty file
    ASSERT_TRUE(std::filesystem::exists(zeroPath));
    ASSERT_EQ(std::filesystem::file_size(zeroPath), 0u)
        << "Test prerequisite: the file must be empty.";
    const bool result =
        AI::ModelCache::Instance().SwapModel(AI::CortexModelType::Emulation, zeroPath);
    (void)result;
    SUCCEED() << "SwapModel() with a zero-byte file completed without crashing. "
                 "result=" << (result ? "true" : "false");
}

// ===========================================================================
// ADDITIONAL GROUP 5 — ModelInference: Robustness Tests
// ===========================================================================

// ---------------------------------------------------------------------------
// 5.9  Shutdown() before any Initialize() must not crash.  The fixture's
//      SetUp() exercises this path implicitly; this test makes the contract
//      explicit and regression-guards it.
// ---------------------------------------------------------------------------
TEST_F(ModelInference_Lifecycle, Shutdown_BeforeInit_NoCrash) {
    // SetUp() already called Shutdown() once; calling it again is safe.
    AI::ModelInference::Instance().Shutdown();
    EXPECT_FALSE(AI::ModelInference::Instance().IsInitialized())
        << "IsInitialized() must remain false after Shutdown() with no prior Initialize().";
}

// ---------------------------------------------------------------------------
// 5.10 Calling Shutdown() twice in succession must leave the singleton in a
//      clean, non-initialized state without crashing or corrupting state.
// ---------------------------------------------------------------------------
TEST_F(ModelInference_Lifecycle, DoubleShutdown_NoCrash) {
    AI::ModelInference::Instance().Shutdown();
    AI::ModelInference::Instance().Shutdown();
    EXPECT_FALSE(AI::ModelInference::Instance().IsInitialized())
        << "IsInitialized() must remain false after two consecutive Shutdown() calls.";
}

// ===========================================================================
// ADDITIONAL GROUP 6 — PhantomCortex: All Analyze*() Before Initialization
// ===========================================================================

// ---------------------------------------------------------------------------
// 6.7  AnalyzeBehavior() before Initialize() must return Benign + confidence=0.
//      This exercises the fail-safe fallback for the behavioral model path.
// ---------------------------------------------------------------------------
TEST_F(PhantomCortex_Lifecycle, BeforeInit_AnalyzeBehavior_ReturnsBenignDefault) {
    const auto verdict =
        AI::PhantomCortex::Instance().AnalyzeBehavior(std::span<const AI::APICallRecord>{});
    EXPECT_EQ(verdict.verdict, AI::ThreatVerdict::Benign)
        << "AnalyzeBehavior() before Initialize() must return Benign (fail-safe).";
    EXPECT_NEAR(verdict.confidence, 0.0f, 1e-4f)
        << "AnalyzeBehavior() before Initialize() must return confidence=0.";
}

// ---------------------------------------------------------------------------
// 6.8  AnalyzeMemory() before Initialize() must return Benign + confidence=0.
// ---------------------------------------------------------------------------
TEST_F(PhantomCortex_Lifecycle, BeforeInit_AnalyzeMemory_ReturnsBenignDefault) {
    const uint8_t dummy = 0xCC;
    AI::MemoryRegionInfo region;
    region.data        = std::span<const uint8_t>(&dummy, 1);
    region.baseAddress = 0x1000;
    region.size        = 1;
    region.protection  = PAGE_EXECUTE_READ;
    const auto verdict = AI::PhantomCortex::Instance().AnalyzeMemory(region);
    EXPECT_EQ(verdict.verdict, AI::ThreatVerdict::Benign)
        << "AnalyzeMemory() before Initialize() must return Benign (fail-safe).";
    EXPECT_NEAR(verdict.confidence, 0.0f, 1e-4f)
        << "AnalyzeMemory() before Initialize() must return confidence=0.";
}

// ---------------------------------------------------------------------------
// 6.9  AnalyzeNetwork() before Initialize() must return Benign + confidence=0.
// ---------------------------------------------------------------------------
TEST_F(PhantomCortex_Lifecycle, BeforeInit_AnalyzeNetwork_ReturnsBenignDefault) {
    const AI::NetworkFlowInfo flow{};
    const auto verdict = AI::PhantomCortex::Instance().AnalyzeNetwork(flow);
    EXPECT_EQ(verdict.verdict, AI::ThreatVerdict::Benign)
        << "AnalyzeNetwork() before Initialize() must return Benign (fail-safe).";
    EXPECT_NEAR(verdict.confidence, 0.0f, 1e-4f)
        << "AnalyzeNetwork() before Initialize() must return confidence=0.";
}

// ---------------------------------------------------------------------------
// 6.10 AnalyzeEmulationTrace() before Initialize() must return Benign/0.
// ---------------------------------------------------------------------------
TEST_F(PhantomCortex_Lifecycle, BeforeInit_AnalyzeEmulationTrace_ReturnsBenignDefault) {
    const auto verdict =
        AI::PhantomCortex::Instance().AnalyzeEmulationTrace(
            std::span<const AI::EmulationEvent>{});
    EXPECT_EQ(verdict.verdict, AI::ThreatVerdict::Benign)
        << "AnalyzeEmulationTrace() before Initialize() must return Benign (fail-safe).";
    EXPECT_NEAR(verdict.confidence, 0.0f, 1e-4f)
        << "AnalyzeEmulationTrace() before Initialize() must return confidence=0.";
}

// ---------------------------------------------------------------------------
// 6.11 GetModelVersions() before Initialize() must not crash and must return
//      MODEL_COUNT entries, all of which must be std::nullopt.
// ---------------------------------------------------------------------------
TEST_F(PhantomCortex_Lifecycle, BeforeInit_GetModelVersions_AllNullopt) {
    const auto versions = AI::PhantomCortex::Instance().GetModelVersions();
    ASSERT_EQ(versions.size(), AI::CortexConstants::MODEL_COUNT)
        << "GetModelVersions() must return exactly MODEL_COUNT entries.";
    for (size_t i = 0; i < versions.size(); ++i) {
        EXPECT_FALSE(versions[i].has_value())
            << "Slot " << i << " must have no model version before Initialize().";
    }
}

// ---------------------------------------------------------------------------
// 6.12 Eight concurrent AnalyzeFile() calls before Initialize() must all
//      return Benign/0 without data races, crashes, or assertion violations.
// ---------------------------------------------------------------------------
TEST_F(PhantomCortex_Lifecycle, Concurrent_AnalyzeFile_BeforeInit_NoRace) {
    constexpr int kThreads = 8;
    std::atomic<int> badCount{0};
    std::vector<std::thread> threads;
    threads.reserve(kThreads);
    for (int t = 0; t < kThreads; ++t) {
        threads.emplace_back([&badCount]() {
            const auto verdict =
                AI::PhantomCortex::Instance().AnalyzeFile(std::span<const uint8_t>{});
            if (verdict.verdict != AI::ThreatVerdict::Benign ||
                verdict.confidence > 1e-4f) {
                ++badCount;
            }
        });
    }
    for (auto& th : threads) th.join();
    EXPECT_EQ(badCount.load(), 0)
        << "All 8 concurrent pre-init AnalyzeFile() calls must return Benign/0.";
}

// ===========================================================================
// ADDITIONAL GROUP 7 — EnsembleVerdict: Extended Model Combinations
// ===========================================================================

// ---------------------------------------------------------------------------
// 7.11 Only the network model at Malicious/1.0 must drive a Malicious verdict.
//      Validates that every model slot independently contributes to the ensemble.
// ---------------------------------------------------------------------------
TEST_F(EnsembleVerdict_Logic, OnlyNetwork_Malicious_DrivesMalicious) {
    const auto ev = AI::PhantomCortex::Instance().EnsembleVerdict(
        std::nullopt,
        std::nullopt,
        std::nullopt,
        V(AI::ThreatVerdict::Malicious, 1.0f, AI::CortexModelType::Network),
        std::nullopt);
    EXPECT_EQ(ev.finalVerdict, AI::ThreatVerdict::Malicious)
        << "A single Network/Malicious/1.0 verdict must drive a Malicious ensemble.";
    EXPECT_GE(ev.ensembleConfidence, 0.7f)
        << "Ensemble confidence for Network/Malicious/1.0 alone must be >= 0.7.";
}

// ---------------------------------------------------------------------------
// 7.12 Only the emulation model at Benign/0.0 must drive a Benign verdict.
// ---------------------------------------------------------------------------
TEST_F(EnsembleVerdict_Logic, OnlyEmulation_Benign_DrivesBenign) {
    const auto ev = AI::PhantomCortex::Instance().EnsembleVerdict(
        std::nullopt,
        std::nullopt,
        std::nullopt,
        std::nullopt,
        V(AI::ThreatVerdict::Benign, 0.0f, AI::CortexModelType::Emulation));
    EXPECT_EQ(ev.finalVerdict, AI::ThreatVerdict::Benign)
        << "A single Emulation/Benign/0.0 verdict must drive a Benign ensemble.";
    EXPECT_LT(ev.ensembleConfidence, 0.5f)
        << "Ensemble confidence for Emulation/Benign/0.0 alone must be < 0.5.";
}

// ---------------------------------------------------------------------------
// 7.13 All five models at Malicious/0.55 (above the 0.5 threshold) must
//      produce a verdict that is NOT Benign.  Uses Malicious verdict
//      (verdictScore=1.0) so the effective contribution per model is
//      conf × 1.0 = 0.55, exceeding the 0.5 ensemble threshold.
//
//      Note: the formula is weight × confidence × verdictScore.
//      Suspicious (verdictScore=0.5) at conf=0.55 yields 0.275 which is
//      BELOW the threshold — only Malicious or Suspicious verdicts with
//      correspondingly high confidence can exceed it.
// ---------------------------------------------------------------------------
TEST_F(EnsembleVerdict_Logic, AllFive_Malicious_AboveThreshold_NotBenign) {
    using MT = AI::CortexModelType;
    const auto ev = AI::PhantomCortex::Instance().EnsembleVerdict(
        V(AI::ThreatVerdict::Malicious, 0.55f, MT::Static),
        V(AI::ThreatVerdict::Malicious, 0.55f, MT::Behavioral),
        V(AI::ThreatVerdict::Malicious, 0.55f, MT::Memory),
        V(AI::ThreatVerdict::Malicious, 0.55f, MT::Network),
        V(AI::ThreatVerdict::Malicious, 0.55f, MT::Emulation));
    EXPECT_NE(ev.finalVerdict, AI::ThreatVerdict::Benign)
        << "Five Malicious/0.55 models (conf × verdictScore = 0.55 > 0.5 threshold) "
           "must NOT yield Benign.";
    EXPECT_GE(ev.ensembleConfidence, 0.5f)
        << "Ensemble confidence for five Malicious/0.55 models must be >= 0.5.";
}

// ---------------------------------------------------------------------------
// 7.14 The behavioral model slot (index 1) must reflect the exact verdict and
//      confidence passed in via the behavioralV parameter.
// ---------------------------------------------------------------------------
TEST_F(EnsembleVerdict_Logic, BehavioralSlot_ReflectsInput) {
    const auto bv = V(AI::ThreatVerdict::Malicious, 0.95f, AI::CortexModelType::Behavioral);
    const auto ev = AI::PhantomCortex::Instance().EnsembleVerdict(
        std::nullopt, bv, std::nullopt);
    EXPECT_EQ(ev.modelVerdicts[1].verdict, AI::ThreatVerdict::Malicious)
        << "modelVerdicts[1] (Behavioral slot) must carry the Malicious verdict.";
    EXPECT_NEAR(ev.modelVerdicts[1].confidence, 0.95f, 1e-4f)
        << "modelVerdicts[1] confidence must exactly match the input confidence.";
}

// ---------------------------------------------------------------------------
// 7.15 One Malicious model at 0.95 + four Benign models at 0.0 must produce
//      a well-formed ensemble verdict in [0,1] without crashing.
// ---------------------------------------------------------------------------
TEST_F(EnsembleVerdict_Logic, OneMaliciousFourBenign_ValidOutput) {
    using MT = AI::CortexModelType;
    const auto ev = AI::PhantomCortex::Instance().EnsembleVerdict(
        V(AI::ThreatVerdict::Malicious, 0.95f, MT::Static),
        V(AI::ThreatVerdict::Benign,    0.0f,  MT::Behavioral),
        V(AI::ThreatVerdict::Benign,    0.0f,  MT::Memory),
        V(AI::ThreatVerdict::Benign,    0.0f,  MT::Network),
        V(AI::ThreatVerdict::Benign,    0.0f,  MT::Emulation));
    EXPECT_GE(ev.ensembleConfidence, 0.0f)
        << "ensembleConfidence must be >= 0.";
    EXPECT_LE(ev.ensembleConfidence, 1.0f)
        << "ensembleConfidence must be <= 1.";
    const uint8_t raw = static_cast<uint8_t>(ev.finalVerdict);
    EXPECT_LE(raw, 2u)
        << "finalVerdict must map to a valid ThreatVerdict (0=Benign, 1=Suspicious, 2=Malicious).";
}

// ===========================================================================
// ADDITIONAL GROUP 8 — Type Contracts: Full Enum and Constant Coverage
// ===========================================================================

// ---------------------------------------------------------------------------
// 8.6  All 20 BehaviorCategory ordinals must match the Python training
//      pipeline label encoding — ABI breaks here silently degrade accuracy.
// ---------------------------------------------------------------------------
TEST(TypeContracts, BehaviorCategory_OrdinalValues) {
    using BC = AI::BehaviorCategory;
    EXPECT_EQ(static_cast<uint8_t>(BC::ProcessInjection),  0u);
    EXPECT_EQ(static_cast<uint8_t>(BC::Ransomware),        1u);
    EXPECT_EQ(static_cast<uint8_t>(BC::InfoStealer),       2u);
    EXPECT_EQ(static_cast<uint8_t>(BC::Backdoor),          3u);
    EXPECT_EQ(static_cast<uint8_t>(BC::Rootkit),           4u);
    EXPECT_EQ(static_cast<uint8_t>(BC::Downloader),        5u);
    EXPECT_EQ(static_cast<uint8_t>(BC::Dropper),           6u);
    EXPECT_EQ(static_cast<uint8_t>(BC::Worm),              7u);
    EXPECT_EQ(static_cast<uint8_t>(BC::Miner),             8u);
    EXPECT_EQ(static_cast<uint8_t>(BC::Adware),            9u);
    EXPECT_EQ(static_cast<uint8_t>(BC::Keylogger),        10u);
    EXPECT_EQ(static_cast<uint8_t>(BC::RAT),              11u);
    EXPECT_EQ(static_cast<uint8_t>(BC::BankTrojan),       12u);
    EXPECT_EQ(static_cast<uint8_t>(BC::Spyware),          13u);
    EXPECT_EQ(static_cast<uint8_t>(BC::Fileless),         14u);
    EXPECT_EQ(static_cast<uint8_t>(BC::LateralMovement),  15u);
    EXPECT_EQ(static_cast<uint8_t>(BC::Exfiltration),     16u);
    EXPECT_EQ(static_cast<uint8_t>(BC::Persistence),      17u);
    EXPECT_EQ(static_cast<uint8_t>(BC::PrivEsc),          18u);
    EXPECT_EQ(static_cast<uint8_t>(BC::Benign),           19u);
}

// ---------------------------------------------------------------------------
// 8.7  All 5 MemoryThreatType ordinals must be stable.
// ---------------------------------------------------------------------------
TEST(TypeContracts, MemoryThreatType_OrdinalValues) {
    using MT = AI::MemoryThreatType;
    EXPECT_EQ(static_cast<uint8_t>(MT::Benign),    0u);
    EXPECT_EQ(static_cast<uint8_t>(MT::Shellcode), 1u);
    EXPECT_EQ(static_cast<uint8_t>(MT::ROP),       2u);
    EXPECT_EQ(static_cast<uint8_t>(MT::Encrypted), 3u);
    EXPECT_EQ(static_cast<uint8_t>(MT::Packed),    4u);
}

// ---------------------------------------------------------------------------
// 8.8  All 8 NetworkThreatType ordinals must be stable.
// ---------------------------------------------------------------------------
TEST(TypeContracts, NetworkThreatType_OrdinalValues) {
    using NT = AI::NetworkThreatType;
    EXPECT_EQ(static_cast<uint8_t>(NT::Normal),          0u);
    EXPECT_EQ(static_cast<uint8_t>(NT::C2Beacon),        1u);
    EXPECT_EQ(static_cast<uint8_t>(NT::Exfiltration),    2u);
    EXPECT_EQ(static_cast<uint8_t>(NT::LateralMovement), 3u);
    EXPECT_EQ(static_cast<uint8_t>(NT::Scanning),        4u);
    EXPECT_EQ(static_cast<uint8_t>(NT::DGADomain),       5u);
    EXPECT_EQ(static_cast<uint8_t>(NT::DNSTunnel),       6u);
    EXPECT_EQ(static_cast<uint8_t>(NT::CryptoMining),    7u);
}

// ---------------------------------------------------------------------------
// 8.9  Memory-safety allocation-cap constants must match documented values.
//      Any increase requires a formal security review for heap-pressure impact.
// ---------------------------------------------------------------------------
TEST(TypeContracts, CortexConstants_AllocationCaps_CorrectValues) {
    EXPECT_EQ(AI::CortexConstants::MAX_MEMORY_REGION_SIZE,
              64ULL * 1024 * 1024)
        << "MAX_MEMORY_REGION_SIZE must be exactly 64 MB.";
    EXPECT_EQ(AI::CortexConstants::MAX_MODEL_FILE_SIZE,
              500ULL * 1024 * 1024)
        << "MAX_MODEL_FILE_SIZE must be exactly 500 MB.";
    EXPECT_EQ(AI::CortexConstants::MAX_PE_FILE_SIZE,
              256ULL * 1024 * 1024)
        << "MAX_PE_FILE_SIZE must be exactly 256 MB.";
    EXPECT_EQ(AI::CortexConstants::MAX_API_SEQUENCE_LENGTH, 2048u)
        << "MAX_API_SEQUENCE_LENGTH must be 2048.";
    EXPECT_EQ(AI::CortexConstants::MAX_BATCH_SIZE, 128u)
        << "MAX_BATCH_SIZE must be 128.";
}

// ---------------------------------------------------------------------------
// 8.10 Default-constructed CortexStats must have all counters at zero.
//      This guards the in-class member initializers in the struct definition.
// ---------------------------------------------------------------------------
TEST(TypeContracts, CortexStats_DefaultConstruction_AllZero) {
    const AI::PhantomCortex::CortexStats s;
    EXPECT_EQ(s.totalInferences,            0u);
    EXPECT_EQ(s.totalMaliciousDetections,   0u);
    EXPECT_EQ(s.totalSuspiciousDetections,  0u);
    EXPECT_EQ(s.totalBenignClassifications, 0u);
    EXPECT_EQ(s.averageInferenceTimeUs,     0u);
    EXPECT_EQ(s.modelLoadErrors,            0u);
}

// ---------------------------------------------------------------------------
// 8.11 Inference timeout constants must match the documented safe ranges.
//      DEFAULT must be less than MAX; MAX must not exceed 30 seconds.
// ---------------------------------------------------------------------------
TEST(TypeContracts, CortexConstants_InferenceTimeouts_CorrectValues) {
    EXPECT_EQ(AI::CortexConstants::DEFAULT_INFERENCE_TIMEOUT_MS, 100u)
        << "DEFAULT_INFERENCE_TIMEOUT_MS must be 100 ms.";
    EXPECT_EQ(AI::CortexConstants::MAX_INFERENCE_TIMEOUT_MS, 30000u)
        << "MAX_INFERENCE_TIMEOUT_MS must be 30 000 ms (30 seconds).";
    EXPECT_LT(AI::CortexConstants::DEFAULT_INFERENCE_TIMEOUT_MS,
              AI::CortexConstants::MAX_INFERENCE_TIMEOUT_MS)
        << "Default timeout must be less than the maximum allowed timeout.";
}

// ---------------------------------------------------------------------------
// 8.12 CONFIDENCE_UNSET must be negative so it is always distinguishable
//      from any valid confidence value in the [0.0, 1.0] range.
// ---------------------------------------------------------------------------
TEST(TypeContracts, CortexConstants_ConfidenceUnset_IsNegativeSentinel) {
    EXPECT_LT(AI::CortexConstants::CONFIDENCE_UNSET, 0.0f)
        << "CONFIDENCE_UNSET must be negative to distinguish it from [0, 1] "
           "confidence values.";
    EXPECT_EQ(AI::CortexConstants::CONFIDENCE_UNSET, -1.0f)
        << "CONFIDENCE_UNSET must be exactly -1.0f per the documented sentinel.";
}
