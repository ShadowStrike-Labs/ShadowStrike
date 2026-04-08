/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * Unit coverage for MachineLearningDetector deterministic behavior.
 *
 * Scope:
 *   - configuration validation and diagnostic JSON helpers
 *   - statistics reset/snapshot behavior used by telemetry surfaces
 *   - safe pre-initialization guard behavior on the singleton detector
 */

#include "pch.h"

#include <gtest/gtest.h>

#include <filesystem>
#include <string_view>
#include <vector>

#include "../../../src/Shared_modules/Core/Engine/MachineLearningDetector.hpp"

namespace fs = std::filesystem;
namespace Engine = ShadowStrike::Core::Engine;

namespace ShadowStrike::Core::Engine::Test {
namespace {

bool Contains(std::string_view haystack, std::string_view needle) {
    return haystack.find(needle) != std::string_view::npos;
}

Engine::ModelConfig MakeValidModelConfig() {
    Engine::ModelConfig config;
    config.modelPath = fs::path(L"models\\primary.onnx");
    config.modelName = "primary";
    config.architecture = Engine::ModelArchitecture::ONNX;
    config.version = "3.0.0";
    config.threshold = 0.91f;
    config.ensembleWeight = 0.55f;
    config.device = Engine::InferenceDevice::CPU;
    config.inputSize = 512;
    config.numClasses = 4;
    return config;
}

}  // namespace

class MachineLearningDetectorTest : public ::testing::Test {
protected:
    void SetUp() override {
        Engine::MachineLearningDetector::Instance().Shutdown();
    }

    void TearDown() override {
        Engine::MachineLearningDetector::Instance().Shutdown();
    }
};

TEST_F(MachineLearningDetectorTest, ModelConfigEnforcesProductionValidationBounds) {
    Engine::ModelConfig config = MakeValidModelConfig();
    EXPECT_TRUE(config.IsValid());

    config.threshold = 0.0f;
    EXPECT_TRUE(config.IsValid());
    config.threshold = 1.0f;
    EXPECT_TRUE(config.IsValid());
    config.ensembleWeight = 0.0f;
    EXPECT_TRUE(config.IsValid());
    config.ensembleWeight = 1.0f;
    EXPECT_TRUE(config.IsValid());

    config.modelPath.clear();
    EXPECT_FALSE(config.IsValid());

    config = MakeValidModelConfig();
    config.modelName.clear();
    EXPECT_FALSE(config.IsValid());

    config = MakeValidModelConfig();
    config.architecture = Engine::ModelArchitecture::Unknown;
    EXPECT_FALSE(config.IsValid());

    config = MakeValidModelConfig();
    config.threshold = 1.01f;
    EXPECT_FALSE(config.IsValid());

    config = MakeValidModelConfig();
    config.ensembleWeight = -0.01f;
    EXPECT_FALSE(config.IsValid());

    config = MakeValidModelConfig();
    config.inputSize = 0;
    EXPECT_FALSE(config.IsValid());

    config = MakeValidModelConfig();
    config.numClasses = 1;
    EXPECT_FALSE(config.IsValid());
}

TEST_F(MachineLearningDetectorTest, SerializationHelpersExposeStableDiagnosticFields) {
    const Engine::ModelConfig modelConfig = MakeValidModelConfig();
    const std::string modelConfigJson = modelConfig.ToJson();
    EXPECT_TRUE(Contains(modelConfigJson, "\"modelName\":\"primary\""));
    EXPECT_TRUE(Contains(modelConfigJson, "\"inputSize\":512"));

    Engine::ModelInfo info;
    info.name = "primary";
    info.version = "3.0.0";
    info.architecture = Engine::ModelArchitecture::ONNX;
    info.status = Engine::ModelStatus::Ready;
    info.fileSize = 4096;
    info.memoryUsage = 8192;
    info.accuracy = 0.99f;
    info.precision = 0.95f;
    info.recall = 0.94f;
    info.f1Score = 0.945f;
    info.avgInferenceTimeMs = 1.75f;
    const std::string infoJson = info.ToJson();
    EXPECT_TRUE(Contains(infoJson, "\"status\":2"));
    EXPECT_TRUE(Contains(infoJson, "\"avgInferenceTimeMs\":1.75"));

    Engine::ExtractedFeatures features;
    features.features = {0.1f, 0.2f, 0.3f};
    features.fileHash = "abc123";
    features.extractionTimeMs = 7;
    const std::string featuresJson = features.ToJson();
    EXPECT_TRUE(Contains(featuresJson, "\"featureCount\":3"));
    EXPECT_TRUE(Contains(featuresJson, "\"fileHash\":\"abc123\""));

    Engine::FeatureImportance importance;
    importance.featureName = "entropy";
    importance.featureIndex = 9;
    importance.category = Engine::FeatureCategory::Entropy;
    importance.importance = 0.87f;
    importance.contributesToMalicious = true;
    const std::string importanceJson = importance.ToJson();
    EXPECT_TRUE(Contains(importanceJson, "\"featureName\":\"entropy\""));
    EXPECT_TRUE(Contains(importanceJson, "\"contributesToMalicious\":true"));

    Engine::PredictionResult prediction;
    prediction.isMalicious = true;
    prediction.classification = Engine::Classification::Ransomware;
    prediction.probability = 0.98f;
    prediction.confidence = 0.93f;
    prediction.modelName = "primary";
    prediction.inferenceTimeMs = 12;
    prediction.thresholdUsed = 0.9f;
    prediction.fromCache = false;
    const std::string predictionJson = prediction.ToJson();
    EXPECT_TRUE(Contains(predictionJson, "\"isMalicious\":true"));
    EXPECT_TRUE(Contains(predictionJson, "\"classification\":4"));
    EXPECT_TRUE(Contains(predictionJson, "\"modelName\":\"primary\""));
    EXPECT_TRUE(Contains(predictionJson, "\"threshold\":0.9"));
    EXPECT_FALSE(Contains(predictionJson, "thresholdUsed"));

    Engine::EnsemblePrediction ensemble;
    ensemble.finalResult = prediction;
    ensemble.modelResults = {prediction, prediction};
    ensemble.votingMethod = "weighted";
    ensemble.modelAgreement = 0.5f;
    ensemble.totalInferenceTimeMs = 21;
    const std::string ensembleJson = ensemble.ToJson();
    EXPECT_TRUE(Contains(ensembleJson, "\"modelCount\":2"));
    EXPECT_TRUE(Contains(ensembleJson, "\"votingMethod\":\"weighted\""));
}

TEST_F(MachineLearningDetectorTest, StatisticsResetAndAverageInferenceStayDeterministic) {
    Engine::MLStatistics stats;
    stats.totalPredictions.store(10, std::memory_order_relaxed);
    stats.modelInferences.store(4, std::memory_order_relaxed);
    stats.totalInferenceTimeUs.store(6000, std::memory_order_relaxed);
    stats.errors.store(2, std::memory_order_relaxed);
    stats.byClassification[static_cast<size_t>(Engine::Classification::Malicious)]
        .store(3, std::memory_order_relaxed);

    EXPECT_DOUBLE_EQ(stats.GetAverageInferenceTimeMs(), 1.5);
    const std::string beforeResetJson = stats.ToJson();
    EXPECT_TRUE(Contains(beforeResetJson, "\"avgInferenceTimeMs\":1.5"));
    EXPECT_TRUE(Contains(beforeResetJson, "\"errors\":2"));

    stats.Reset();
    EXPECT_EQ(stats.totalPredictions.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.modelInferences.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.errors.load(std::memory_order_relaxed), 0u);
    EXPECT_DOUBLE_EQ(stats.GetAverageInferenceTimeMs(), 0.0);
}

TEST_F(MachineLearningDetectorTest, ConfigurationValidationTracksPrimaryAndEnsembleModes) {
    Engine::MachineLearningConfiguration config;
    config.primaryModel = MakeValidModelConfig();
    EXPECT_TRUE(config.IsValid());

    config.primaryModel = {};
    EXPECT_FALSE(config.IsValid());

    config = {};
    config.useEnsemble = true;
    EXPECT_FALSE(config.IsValid());

    config = {};
    config.primaryModel = MakeValidModelConfig();
    config.useEnsemble = true;
    config.ensembleModels = {MakeValidModelConfig()};
    EXPECT_TRUE(config.IsValid());

    config.ensembleModels = {Engine::ModelConfig{}};
    EXPECT_TRUE(config.IsValid());

    config = {};
    config.enabled = false;
    EXPECT_TRUE(config.IsValid());

    config.batchSize = 0;
    EXPECT_FALSE(config.IsValid());

    config = {};
    config.primaryModel = MakeValidModelConfig();
    config.workerThreads = 0;
    EXPECT_FALSE(config.IsValid());
}

TEST_F(MachineLearningDetectorTest, GuardPathsRemainBenignBeforeInitialization) {
    auto& detector = Engine::MachineLearningDetector::Instance();
    EXPECT_FALSE(detector.IsInitialized());
    EXPECT_EQ(detector.GetStatus(), Engine::MLDetectorStatus::Uninitialized);

    EXPECT_FALSE(detector.Initialize(Engine::MachineLearningConfiguration{}));
    EXPECT_FALSE(detector.GetModelInfo("primary").has_value());
    EXPECT_TRUE(detector.GetLoadedModels().empty());

    Engine::ExtractedFeatures features;
    features.features = {0.25f, 0.75f};
    const Engine::PredictionResult prediction = detector.Analyze(features);
    EXPECT_FALSE(prediction.isMalicious);
    EXPECT_EQ(prediction.classification, Engine::Classification::PotentiallyUnwanted);
    EXPECT_EQ(prediction.modelName, "PhantomCortex-Fallback");
    EXPECT_FLOAT_EQ(prediction.probability, 0.5f);
    EXPECT_FLOAT_EQ(prediction.thresholdUsed, 0.85f);

    const auto stats = detector.GetStatistics();
    EXPECT_EQ(stats.totalPredictions, 0u);
    EXPECT_EQ(stats.modelInferences, 1u);

    const auto devices = Engine::GetAvailableDevices();
    EXPECT_FALSE(devices.empty());
    EXPECT_EQ(devices.front(), Engine::InferenceDevice::CPU);
    EXPECT_TRUE(Contains(Engine::MachineLearningDetector::GetVersionString(), "3.0."));
}

TEST_F(MachineLearningDetectorTest, EnumNameHelpersStayStableForOperationalTelemetry) {
    EXPECT_EQ(Engine::GetModelArchitectureName(Engine::ModelArchitecture::ONNX), "ONNX");
    EXPECT_EQ(Engine::GetInferenceDeviceName(Engine::InferenceDevice::CPU), "CPU");
    EXPECT_EQ(Engine::GetFeatureCategoryName(Engine::FeatureCategory::Entropy), "Entropy");
    EXPECT_EQ(Engine::GetClassificationName(Engine::Classification::Ransomware), "Ransomware");
    EXPECT_EQ(Engine::GetModelStatusName(Engine::ModelStatus::Disabled), "Disabled");
}

}  // namespace ShadowStrike::Core::Engine::Test
