/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * Unit coverage for PhantomCortex's ONNX runtime wrapper.
 *
 * These tests stay deterministic across environments by focusing on public
 * guard contracts that must hold with or without the ONNX Runtime SDK present.
 */

#include "pch.h"

#include <gtest/gtest.h>

#include <array>
#include <filesystem>
#include <vector>

#include "../../../src/PhantomCore/AI/ModelInference.hpp"
#include "AI_TestUtils.hpp"

namespace fs = std::filesystem;

namespace ShadowStrike::AI::Test {

class ModelInferenceTest : public ::testing::Test {
protected:
    ScopedTempDir tempDir{L"ShadowStrike_AIModelInference_"};

    void SetUp() override {
        ModelInference::Instance().Shutdown();
    }

    void TearDown() override {
        ModelInference::Instance().Shutdown();
    }
};

TEST_F(ModelInferenceTest, InstanceReturnsStableSingletonReference) {
    auto& first = ModelInference::Instance();
    auto& second = ModelInference::Instance();

    EXPECT_EQ(&first, &second);
}

TEST_F(ModelInferenceTest, ShutdownLeavesEngineUninitialized) {
    auto& inference = ModelInference::Instance();

    inference.Shutdown();
    EXPECT_FALSE(inference.IsInitialized());
}

TEST_F(ModelInferenceTest, LoadModelRejectsMissingFilesAndInvalidModelSlots) {
    auto& inference = ModelInference::Instance();
    const fs::path missingModel = tempDir.File(L"missing.onnx");

    EXPECT_FALSE(inference.LoadModel(CortexModelType::Static, missingModel));
    EXPECT_FALSE(inference.LoadModel(static_cast<CortexModelType>(255), missingModel));
}

TEST_F(ModelInferenceTest, InferWithoutLoadedModelReturnsNullopt) {
    auto& inference = ModelInference::Instance();
    const std::array<float, 4> input = {0.1f, 0.2f, 0.3f, 0.4f};
    const std::array<int64_t, 2> shape = {1, 4};

    EXPECT_FALSE(inference.Infer(CortexModelType::Static, input, shape).has_value());
    EXPECT_FALSE(inference.Infer(static_cast<CortexModelType>(255), input, shape).has_value());
}

TEST_F(ModelInferenceTest, InferBatchWithoutLoadedModelReturnsNullopt) {
    auto& inference = ModelInference::Instance();
    const std::array<float, 8> input = {0.0f, 1.0f, 2.0f, 3.0f, 4.0f, 5.0f, 6.0f, 7.0f};
    const std::array<int64_t, 2> shape = {2, 4};

    EXPECT_FALSE(inference.InferBatch(CortexModelType::Behavioral, input, shape).has_value());
    EXPECT_FALSE(inference.InferBatch(static_cast<CortexModelType>(255), input, shape).has_value());
}

TEST_F(ModelInferenceTest, InferRejectsEmptyInputAndInvalidShapeMetadata) {
    auto& inference = ModelInference::Instance();

    EXPECT_FALSE(inference.Infer(CortexModelType::Static,
                                 std::span<const float>{},
                                 std::span<const int64_t>{}).has_value());

    const std::array<float, 5> mismatchedInput = {1.f, 2.f, 3.f, 4.f, 5.f};
    const std::array<int64_t, 2> mismatchedShape = {2, 3};
    EXPECT_FALSE(inference.Infer(CortexModelType::Static, mismatchedInput, mismatchedShape).has_value());

    const std::array<float, 1> oneValue = {1.0f};
    const std::array<int64_t, 1> zeroDimShape = {0};
    EXPECT_FALSE(inference.Infer(CortexModelType::Static, oneValue, zeroDimShape).has_value());

    const std::array<int64_t, 1> negativeDimShape = {-1};
    EXPECT_FALSE(inference.Infer(CortexModelType::Static, oneValue, negativeDimShape).has_value());
}

TEST_F(ModelInferenceTest, InferBatchRejectsInvalidRankDimensionsAndBatchLimits) {
    auto& inference = ModelInference::Instance();

    const std::array<float, 4> flatInput = {1.f, 2.f, 3.f, 4.f};
    const std::array<int64_t, 1> rankOneShape = {4};
    EXPECT_FALSE(inference.InferBatch(CortexModelType::Behavioral, flatInput, rankOneShape).has_value());

    const std::array<int64_t, 2> zeroBatchShape = {0, 4};
    EXPECT_FALSE(inference.InferBatch(CortexModelType::Behavioral, flatInput, zeroBatchShape).has_value());

    std::vector<float> oversizedBatch(static_cast<size_t>(CortexConstants::MAX_BATCH_SIZE) + 1u, 1.0f);
    const std::array<int64_t, 2> oversizedShape = {
        static_cast<int64_t>(CortexConstants::MAX_BATCH_SIZE) + 1,
        1
    };
    EXPECT_FALSE(inference.InferBatch(CortexModelType::Behavioral, oversizedBatch, oversizedShape).has_value());

    const std::array<float, 3> mismatchedBatch = {1.f, 2.f, 3.f};
    const std::array<int64_t, 2> mismatchedBatchShape = {1, 4};
    EXPECT_FALSE(inference.InferBatch(CortexModelType::Behavioral,
                                      mismatchedBatch,
                                      mismatchedBatchShape).has_value());
}

TEST_F(ModelInferenceTest, MetadataQueriesReportEmptyForUnloadedModels) {
    auto& inference = ModelInference::Instance();

    EXPECT_FALSE(inference.GetModelVersion(CortexModelType::Memory).has_value());
    EXPECT_FALSE(inference.IsModelLoaded(CortexModelType::Memory));
    EXPECT_FALSE(inference.GetModelVersion(static_cast<CortexModelType>(255)).has_value());
    EXPECT_FALSE(inference.IsModelLoaded(static_cast<CortexModelType>(255)));
}

TEST_F(ModelInferenceTest, InitializeAttemptCanAlwaysBeCleanlyShutDown) {
    auto& inference = ModelInference::Instance();
    CortexConfig config{};

    const bool initialized = inference.Initialize(config);
    EXPECT_EQ(inference.IsInitialized(), initialized);

    inference.Shutdown();
    EXPECT_FALSE(inference.IsInitialized());
}

TEST_F(ModelInferenceTest, ShutdownIsIdempotent) {
    auto& inference = ModelInference::Instance();

    inference.Shutdown();
    inference.Shutdown();
    EXPECT_FALSE(inference.IsInitialized());
}

// WAS: a test guarded by #if !__has_include(<onnxruntime_c_api.h>) named
// WithoutOnnxRuntimeSdkInitializeFailsAndCapabilitiesStayDisabled, asserting
// EXPECT_FALSE(Initialize(...)), EXPECT_FALSE(HasAVX2()), EXPECT_FALSE(HasAVX512())
// and EXPECT_FALSE(HasDirectML()).
//
// The guard was the defect, not the assertions. __has_include is evaluated in THIS
// translation unit, whose include path (PhantomTests.vcxproj) does not carry
// vendor\onnxruntime\include - so it reported "no ONNX Runtime" and compiled the
// test in. But ModelInference.cpp is compiled into PhantomCoreLib, which DOES carry
// that include directory, so the linked implementation is the real ORT one and
// Initialize() succeeds. A test cannot infer the capabilities of a library it links
// against from its own include path; the two are configured separately, and here
// they disagree.
//
// The two assertions on CPU features were wrong for a second, independent reason:
// HasAVX2()/HasAVX512() report what DetectCpuFeatures() found via CPUID plus XGETBV
// on the machine running the test. Those vary per host, so no fixed expectation of
// either polarity is correct.
//
// What is left below are the contracts that hold on every build and every CPU.
// If someone restores the __has_include version: it fails on this build (Initialize
// succeeds), and on a build without the SDK it would still assert host CPU features
// it cannot know.
TEST_F(ModelInferenceTest, CapabilityQueriesFollowConfigAndStayStableAcrossReads) {
    auto& inference = ModelInference::Instance();

    CortexConfig config{};
    config.useGPU = false;

    const bool initialized = inference.Initialize(config);

    // Whether the engine can initialize is a property of the linked build and of the
    // ORT runtime being loadable - not something this test may assume in either
    // direction. What must always hold is that the reported state matches the answer.
    EXPECT_EQ(inference.IsInitialized(), initialized);

    // Config-driven and therefore machine-independent: with useGPU = false,
    // Initialize() takes the "GPU disabled by config" branch and clears the DirectML
    // capability instead of probing for it.
    EXPECT_FALSE(inference.HasDirectML());

    // CPU features are read from CPUID on the host, so assert only that the accessors
    // are stable and side-effect free - never a specific value.
    EXPECT_EQ(inference.HasAVX2(), inference.HasAVX2());
    EXPECT_EQ(inference.HasAVX512(), inference.HasAVX512());

    // AVX-512F implies AVX2 on every CPU that reports both through leaf 7, so this
    // holds regardless of which features the host actually has.
    if (inference.HasAVX512()) {
        EXPECT_TRUE(inference.HasAVX2());
    }

    // Guard contracts must hold in both states: a model file that does not exist is
    // never loaded, and an unloaded slot never yields a score.
    EXPECT_FALSE(inference.LoadModel(CortexModelType::Static, tempDir.File(L"absent.onnx")));
    EXPECT_FALSE(inference.IsModelLoaded(CortexModelType::Static));

    inference.Shutdown();
    EXPECT_FALSE(inference.IsInitialized());
}

}  // namespace ShadowStrike::AI::Test
