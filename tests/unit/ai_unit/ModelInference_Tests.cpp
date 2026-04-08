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

#include "../../../src/Shared_modules/AI/ModelInference.hpp"
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

#if !__has_include(<onnxruntime_c_api.h>)
TEST_F(ModelInferenceTest, WithoutOnnxRuntimeSdkInitializeFailsAndCapabilitiesStayDisabled) {
    auto& inference = ModelInference::Instance();

    EXPECT_FALSE(inference.Initialize(CortexConfig{}));
    EXPECT_FALSE(inference.IsInitialized());
    EXPECT_FALSE(inference.HasAVX2());
    EXPECT_FALSE(inference.HasAVX512());
    EXPECT_FALSE(inference.HasDirectML());
}
#endif

}  // namespace ShadowStrike::AI::Test
