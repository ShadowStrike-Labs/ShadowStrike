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
 * ============================================================================
 * ShadowStrike NGAV - MACHINE LEARNING DETECTOR MODULE
 * ============================================================================
 *
 * @file MachineLearningDetector.hpp
 * @brief Enterprise-grade AI/ML-based malware detection engine with multi-model
 *        ensemble, real-time inference, and adaptive learning capabilities.
 *
 * Provides signature-less malware detection using trained machine learning models
 * to classify executables based on static and behavioral features.
 *
 * MACHINE LEARNING CAPABILITIES:
 * ==============================
 *
 * 1. MODEL ARCHITECTURES
 *    - Random Forest classifier
 *    - Gradient Boosting (XGBoost/LightGBM)
 *    - Deep Neural Networks (CNN/LSTM)
 *    - ONNX runtime support
 *    - Ensemble voting
 *
 * 2. FEATURE EXTRACTION
 *    - PE header features
 *    - Import/Export analysis
 *    - Section characteristics
 *    - Entropy profiling
 *    - Byte n-grams
 *    - Opcode sequences
 *
 * 3. INFERENCE MODES
 *    - CPU inference (AVX2/AVX-512)
 *    - GPU inference (DirectML/CUDA)
 *    - Quantized models (INT8)
 *    - Batched inference
 *
 * 4. MODEL MANAGEMENT
 *    - Hot model updates
 *    - Version control
 *    - A/B testing
 *    - Rollback support
 *
 * 5. EXPLAINABILITY
 *    - Feature importance
 *    - SHAP values
 *    - Decision paths
 *    - Confidence scoring
 *
 * @note Thread-safe singleton design.
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @date 2026
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 *
 * LICENSE: Proprietary - ShadowStrike Enterprise License
 * ============================================================================
 */

#pragma once

// ============================================================================
// STANDARD LIBRARY INCLUDES
// ============================================================================

#include <cstdint>
#include <cstddef>
#include <string>
#include <string_view>
#include <vector>
#include <array>
#include <map>
#include <set>
#include <unordered_map>
#include <optional>
#include <variant>
#include <memory>
#include <functional>
#include <chrono>
#include <atomic>
#include <mutex>
#include <shared_mutex>
#include <filesystem>
#include <span>

// ============================================================================
// WINDOWS SDK INCLUDES
// ============================================================================

#ifdef _WIN32
#  ifndef NOMINMAX
#    define NOMINMAX
#  endif
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include <Windows.h>
#endif

// ============================================================================
// SHADOWSTRIKE INFRASTRUCTURE INCLUDES
// ============================================================================

#include "../FileSystem/ExecutableAnalyzer.hpp"
#include "../../Utils/Logger.hpp"
#include "../../Utils/FileUtils.hpp"
#include "../../Utils/HashUtils.hpp"
#include "../../Whitelist/WhiteListStore.hpp"

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

namespace ShadowStrike::Core::Engine {
    class MachineLearningDetectorImpl;
}

namespace ShadowStrike {
namespace Core {
namespace Engine {

// ============================================================================
// COMPILE-TIME CONSTANTS
// ============================================================================

namespace MLConstants {

    inline constexpr uint32_t VERSION_MAJOR = 3;
    inline constexpr uint32_t VERSION_MINOR = 0;
    inline constexpr uint32_t VERSION_PATCH = 0;

    /// @brief Default detection threshold
    inline constexpr float DEFAULT_THRESHOLD = 0.85f;
    
    /// @brief Maximum feature vector size
    inline constexpr size_t MAX_FEATURE_VECTOR_SIZE = 4096;
    
    /// @brief Maximum models in ensemble
    inline constexpr size_t MAX_ENSEMBLE_MODELS = 16;
    
    /// @brief Batch inference size
    inline constexpr size_t DEFAULT_BATCH_SIZE = 32;
    
    /// @brief Feature cache size
    inline constexpr size_t FEATURE_CACHE_SIZE = 10000;
    
    /// @brief Model timeout (milliseconds)
    inline constexpr uint32_t MODEL_TIMEOUT_MS = 5000;

}  // namespace MLConstants

// ============================================================================
// TYPE ALIASES
// ============================================================================

using Clock = std::chrono::steady_clock;
using TimePoint = std::chrono::steady_clock::time_point;
using SystemTimePoint = std::chrono::system_clock::time_point;
namespace fs = std::filesystem;

/// @brief Feature vector type
using FeatureVector = std::vector<float>;

// ============================================================================
// ENUMERATIONS
// ============================================================================

/**
 * @brief Model architecture type
 */
enum class ModelArchitecture : uint8_t {
    RandomForest        = 0,
    GradientBoosting    = 1,    ///< XGBoost/LightGBM
    DeepNeuralNetwork   = 2,    ///< Fully connected DNN
    ConvolutionalNN     = 3,    ///< CNN for byte sequences
    RecurrentNN         = 4,    ///< LSTM/GRU
    Transformer         = 5,    ///< Attention-based
    Ensemble            = 6,    ///< Multiple models combined
    ONNX                = 7,    ///< Generic ONNX model
    Unknown             = 8
};

/**
 * @brief Inference device
 */
enum class InferenceDevice : uint8_t {
    CPU             = 0,
    GPU_DirectML    = 1,
    GPU_CUDA        = 2,
    NPU             = 3,    ///< Neural processing unit
    Auto            = 4     ///< Best available
};

/**
 * @brief Feature category
 */
enum class FeatureCategory : uint8_t {
    PEHeader            = 0,
    ImportTable         = 1,
    ExportTable         = 2,
    Sections            = 3,
    Resources           = 4,
    Strings             = 5,
    ByteNGrams          = 6,
    OpcodeSequences     = 7,
    Entropy             = 8,
    ControlFlow         = 9,
    APISequences        = 10,
    Metadata            = 11,
    Behavioral          = 12,
    Unknown             = 13
};

/**
 * @brief Classification result
 */
enum class Classification : uint8_t {
    Benign          = 0,
    Suspicious      = 1,
    Malicious       = 2,
    PotentiallyUnwanted = 3,
    Ransomware      = 4,
    Trojan          = 5,
    Worm            = 6,
    Backdoor        = 7,
    Spyware         = 8,
    Miner           = 9,
    Unknown         = 10
};

/**
 * @brief Model status
 */
enum class ModelStatus : uint8_t {
    NotLoaded       = 0,
    Loading         = 1,
    Ready           = 2,
    Inferring       = 3,
    Updating        = 4,
    Error           = 5,
    Disabled        = 6
};

/**
 * @brief Detector status
 */
enum class MLDetectorStatus : uint8_t {
    Uninitialized   = 0,
    Initializing    = 1,
    Running         = 2,
    Processing      = 3,
    Error           = 4,
    Stopping        = 5,
    Stopped         = 6
};

// ============================================================================
// STRUCTURES
// ============================================================================

/**
 * @brief Model configuration
 */
struct ModelConfig {
    /// @brief Model file path
    fs::path modelPath;
    
    /// @brief Model name
    std::string modelName;
    
    /// @brief Architecture type
    ModelArchitecture architecture = ModelArchitecture::Unknown;
    
    /// @brief Version string
    std::string version;
    
    /// @brief Detection threshold
    float threshold = MLConstants::DEFAULT_THRESHOLD;
    
    /// @brief Weight in ensemble (0.0 - 1.0)
    float ensembleWeight = 1.0f;
    
    /// @brief Inference device
    InferenceDevice device = InferenceDevice::Auto;
    
    /// @brief Enable GPU acceleration
    bool useGPU = false;
    
    /// @brief Use quantized model
    bool useQuantized = false;
    
    /// @brief Input feature size
    size_t inputSize = 0;
    
    /// @brief Number of classes
    size_t numClasses = 2;
    
    /// @brief Timeout (milliseconds)
    uint32_t timeoutMs = MLConstants::MODEL_TIMEOUT_MS;
    
    [[nodiscard]] bool IsValid() const noexcept;
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Model information
 */
struct ModelInfo {
    /// @brief Model name
    std::string name;
    
    /// @brief Version
    std::string version;
    
    /// @brief Architecture
    ModelArchitecture architecture = ModelArchitecture::Unknown;
    
    /// @brief Status
    ModelStatus status = ModelStatus::NotLoaded;
    
    /// @brief Model file size
    uint64_t fileSize = 0;
    
    /// @brief Memory usage
    uint64_t memoryUsage = 0;
    
    /// @brief Input feature count
    size_t inputFeatures = 0;
    
    /// @brief Output classes
    size_t outputClasses = 0;
    
    /// @brief Training date
    SystemTimePoint trainedDate;
    
    /// @brief Accuracy metrics
    float accuracy = 0.0f;
    float precision = 0.0f;
    float recall = 0.0f;
    float f1Score = 0.0f;
    
    /// @brief Average inference time (milliseconds)
    float avgInferenceTimeMs = 0.0f;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Extracted features
 */
struct ExtractedFeatures {
    /// @brief Feature vector
    FeatureVector features;
    
    /// @brief Feature names (for explainability)
    std::vector<std::string> featureNames;
    
    /// @brief Feature categories
    std::map<FeatureCategory, std::pair<size_t, size_t>> categoryRanges;
    
    /// @brief File hash
    std::string fileHash;
    
    /// @brief Extraction time (milliseconds)
    uint32_t extractionTimeMs = 0;
    
    [[nodiscard]] size_t GetFeatureCount() const noexcept { return features.size(); }
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Feature importance (for explainability)
 */
struct FeatureImportance {
    /// @brief Feature name
    std::string featureName;
    
    /// @brief Feature index
    size_t featureIndex = 0;
    
    /// @brief Category
    FeatureCategory category = FeatureCategory::Unknown;
    
    /// @brief Importance score
    float importance = 0.0f;
    
    /// @brief SHAP value (if computed)
    std::optional<float> shapValue;
    
    /// @brief Contribution direction (positive = towards malicious)
    bool contributesToMalicious = true;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Prediction result
 */
struct PredictionResult {
    /// @brief Is malicious
    bool isMalicious = false;
    
    /// @brief Classification
    Classification classification = Classification::Unknown;
    
    /// @brief Malicious probability (0.0 - 1.0)
    float probability = 0.0f;
    
    /// @brief Confidence score
    float confidence = 0.0f;
    
    /// @brief Per-class probabilities
    std::map<Classification, float> classProbabilities;
    
    /// @brief Contributing features (top N)
    std::vector<FeatureImportance> contributingFeatures;
    
    /// @brief Model that made prediction
    std::string modelName;
    
    /// @brief Inference time (milliseconds)
    uint32_t inferenceTimeMs = 0;
    
    /// @brief Threshold used
    float thresholdUsed = 0.0f;
    
    /// @brief Cached result
    bool fromCache = false;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Ensemble prediction
 */
struct EnsemblePrediction {
    /// @brief Final result
    PredictionResult finalResult;
    
    /// @brief Individual model results
    std::vector<PredictionResult> modelResults;
    
    /// @brief Voting method used
    std::string votingMethod;
    
    /// @brief Agreement score (0.0 - 1.0)
    float modelAgreement = 0.0f;
    
    /// @brief Total inference time
    uint32_t totalInferenceTimeMs = 0;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Batch prediction request
 */
struct BatchPredictionRequest {
    /// @brief File paths to analyze
    std::vector<fs::path> filePaths;
    
    /// @brief Pre-extracted features (optional)
    std::vector<ExtractedFeatures> preExtractedFeatures;
    
    /// @brief Custom threshold (optional)
    std::optional<float> customThreshold;
    
    /// @brief Request full explanation
    bool requestExplanation = false;
    
    /// @brief Priority (higher = more urgent)
    uint32_t priority = 0;
};

/**
 * @brief Statistics
 */
struct MLStatistics {
    std::atomic<uint64_t> totalPredictions{0};
    std::atomic<uint64_t> maliciousDetections{0};
    std::atomic<uint64_t> benignClassifications{0};
    std::atomic<uint64_t> featureExtractions{0};
    std::atomic<uint64_t> cacheHits{0};
    std::atomic<uint64_t> cacheMisses{0};
    std::atomic<uint64_t> modelInferences{0};
    std::atomic<uint64_t> gpuInferences{0};
    std::atomic<uint64_t> cpuInferences{0};
    std::atomic<uint64_t> timeouts{0};
    std::atomic<uint64_t> errors{0};
    std::array<std::atomic<uint64_t>, 16> byClassification{};
    std::atomic<uint64_t> totalInferenceTimeUs{0};
    std::atomic<uint64_t> totalFeatureExtractionTimeUs{0};
    TimePoint startTime = Clock::now();
    
    void Reset() noexcept;
    [[nodiscard]] double GetAverageInferenceTimeMs() const noexcept;
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Configuration
 */
struct MachineLearningConfiguration {
    /// @brief Enable ML detection
    bool enabled = true;
    
    /// @brief Primary model configuration
    ModelConfig primaryModel;
    
    /// @brief Ensemble model configurations
    std::vector<ModelConfig> ensembleModels;
    
    /// @brief Use ensemble voting
    bool useEnsemble = false;
    
    /// @brief Ensemble voting method ("majority", "weighted", "soft")
    std::string ensembleVotingMethod = "weighted";
    
    /// @brief Enable result caching
    bool enableCaching = true;
    
    /// @brief Cache TTL (seconds)
    uint32_t cacheTtlSeconds = 3600;
    
    /// @brief Maximum cache entries
    size_t maxCacheEntries = MLConstants::FEATURE_CACHE_SIZE;
    
    /// @brief Enable batch processing
    bool enableBatchProcessing = true;
    
    /// @brief Batch size
    size_t batchSize = MLConstants::DEFAULT_BATCH_SIZE;
    
    /// @brief Worker threads
    uint32_t workerThreads = 2;
    
    /// @brief Skip whitelisted files
    bool skipWhitelisted = true;
    
    /// @brief Enable explainability
    bool enableExplainability = false;
    
    /// @brief Top N features to explain
    size_t topFeaturesForExplanation = 10;
    
    [[nodiscard]] bool IsValid() const noexcept;
};

// ============================================================================
// CALLBACK TYPES
// ============================================================================

using PredictionCallback = std::function<void(const fs::path& filePath, const PredictionResult& result)>;
using BatchPredictionCallback = std::function<void(const std::vector<std::pair<fs::path, PredictionResult>>& results)>;
using ModelUpdateCallback = std::function<void(const ModelInfo& newModel)>;
using ErrorCallback = std::function<void(const std::string& message, int code)>;

// ============================================================================
// MACHINE LEARNING DETECTOR CLASS
// ============================================================================

/**
 * @class MachineLearningDetector
 * @brief Enterprise ML malware detection
 */
class MachineLearningDetector final {
public:
    [[nodiscard]] static MachineLearningDetector& Instance() noexcept;
    [[nodiscard]] static bool HasInstance() noexcept;
    
    MachineLearningDetector(const MachineLearningDetector&) = delete;
    MachineLearningDetector& operator=(const MachineLearningDetector&) = delete;
    MachineLearningDetector(MachineLearningDetector&&) = delete;
    MachineLearningDetector& operator=(MachineLearningDetector&&) = delete;

    // ========================================================================
    // LIFECYCLE
    // ========================================================================
    
    [[nodiscard]] bool Initialize(const MachineLearningConfiguration& config = {});
    [[nodiscard]] bool Initialize(const ModelConfig& config);  // Legacy
    void Shutdown();
    [[nodiscard]] bool IsInitialized() const noexcept;
    [[nodiscard]] MLDetectorStatus GetStatus() const noexcept;

    // ========================================================================
    // SINGLE FILE ANALYSIS
    // ========================================================================
    
    /// @brief Analyze PE file
    [[nodiscard]] PredictionResult Analyze(const fs::path& filePath);
    
    /// @brief Analyze with pre-extracted executable info
    [[nodiscard]] PredictionResult Analyze(const FileSystem::ExecutableInfo& info);
    
    /// @brief Analyze with pre-extracted features
    [[nodiscard]] PredictionResult Analyze(const ExtractedFeatures& features);
    
    /// @brief Analyze with custom threshold
    [[nodiscard]] PredictionResult AnalyzeWithThreshold(
        const fs::path& filePath,
        float threshold);

    // ========================================================================
    // BATCH ANALYSIS
    // ========================================================================
    
    /// @brief Batch analyze files
    [[nodiscard]] std::vector<std::pair<fs::path, PredictionResult>> AnalyzeBatch(
        const std::vector<fs::path>& filePaths);
    
    /// @brief Async batch analyze
    void AnalyzeBatchAsync(
        const BatchPredictionRequest& request,
        BatchPredictionCallback callback);

    // ========================================================================
    // ENSEMBLE ANALYSIS
    // ========================================================================
    
    /// @brief Get ensemble prediction
    [[nodiscard]] EnsemblePrediction AnalyzeWithEnsemble(const fs::path& filePath);
    
    /// @brief Get ensemble prediction with features
    [[nodiscard]] EnsemblePrediction AnalyzeWithEnsemble(const ExtractedFeatures& features);

    // ========================================================================
    // FEATURE EXTRACTION
    // ========================================================================
    
    /// @brief Extract features from file
    [[nodiscard]] ExtractedFeatures ExtractFeatures(const fs::path& filePath);
    
    /// @brief Extract features from executable info
    [[nodiscard]] ExtractedFeatures ExtractFeatures(const FileSystem::ExecutableInfo& info);
    
    /// @brief Get feature names
    [[nodiscard]] std::vector<std::string> GetFeatureNames() const;
    
    /// @brief Get feature count
    [[nodiscard]] size_t GetFeatureCount() const;

    // ========================================================================
    // MODEL MANAGEMENT
    // ========================================================================
    
    /// @brief Load model
    [[nodiscard]] bool LoadModel(const ModelConfig& config);
    
    /// @brief Unload model
    [[nodiscard]] bool UnloadModel(const std::string& modelName);
    
    /// @brief Get model info
    [[nodiscard]] std::optional<ModelInfo> GetModelInfo(const std::string& modelName) const;
    
    /// @brief Get all loaded models
    [[nodiscard]] std::vector<ModelInfo> GetLoadedModels() const;
    
    /// @brief Update model (hot swap)
    [[nodiscard]] bool UpdateModel(const ModelConfig& newConfig);
    
    /// @brief Set default threshold
    void SetDefaultThreshold(float threshold);
    
    /// @brief Get default threshold
    [[nodiscard]] float GetDefaultThreshold() const noexcept;

    // ========================================================================
    // EXPLAINABILITY
    // ========================================================================
    
    /// @brief Get feature importance for prediction
    [[nodiscard]] std::vector<FeatureImportance> ExplainPrediction(
        const PredictionResult& prediction,
        const ExtractedFeatures& features,
        size_t topN = 10);
    
    /// @brief Get global feature importance
    [[nodiscard]] std::vector<FeatureImportance> GetGlobalFeatureImportance() const;

    // ========================================================================
    // CACHE MANAGEMENT
    // ========================================================================
    
    /// @brief Get cached prediction
    [[nodiscard]] std::optional<PredictionResult> GetCachedPrediction(const std::string& fileHash) const;
    
    /// @brief Clear prediction cache
    void ClearCache();
    
    /// @brief Get cache statistics
    [[nodiscard]] std::pair<size_t, size_t> GetCacheStats() const;  // (hits, total)

    // ========================================================================
    // CALLBACKS
    // ========================================================================
    
    void RegisterPredictionCallback(PredictionCallback callback);
    void RegisterModelUpdateCallback(ModelUpdateCallback callback);
    void RegisterErrorCallback(ErrorCallback callback);
    void UnregisterCallbacks();

    // ========================================================================
    // CONFIGURATION
    // ========================================================================

    /// @brief Get current configuration
    [[nodiscard]] MachineLearningConfiguration GetConfiguration() const;

    /// @brief Set configuration (invalidates cache)
    void SetConfiguration(const MachineLearningConfiguration& config);

    // ========================================================================
    // STATISTICS
    // ========================================================================

    [[nodiscard]] MLStatistics GetStatistics() const;
    void ResetStatistics();

    [[nodiscard]] bool SelfTest();
    [[nodiscard]] static std::string GetVersionString() noexcept;

private:
    MachineLearningDetector();
    ~MachineLearningDetector();

    // PIMPL - ALL implementation details in Impl class for ABI stability
    struct Impl;
    std::unique_ptr<Impl> m_impl;
    static std::atomic<bool> s_instanceCreated;
};

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

[[nodiscard]] std::string_view GetModelArchitectureName(ModelArchitecture arch) noexcept;
[[nodiscard]] std::string_view GetInferenceDeviceName(InferenceDevice device) noexcept;
[[nodiscard]] std::string_view GetFeatureCategoryName(FeatureCategory category) noexcept;
[[nodiscard]] std::string_view GetClassificationName(Classification classification) noexcept;
[[nodiscard]] std::string_view GetModelStatusName(ModelStatus status) noexcept;

/// @brief Check if GPU is available
[[nodiscard]] bool IsGPUAvailable();

/// @brief Get available inference devices
[[nodiscard]] std::vector<InferenceDevice> GetAvailableDevices();

}  // namespace Engine
}  // namespace Core
}  // namespace ShadowStrike

// ============================================================================
// MACROS
// ============================================================================

#define SS_ML_ANALYZE(path) \
    ::ShadowStrike::Core::Engine::MachineLearningDetector::Instance().Analyze(path)

#define SS_ML_IS_MALICIOUS(path) \
    ::ShadowStrike::Core::Engine::MachineLearningDetector::Instance().Analyze(path).isMalicious
