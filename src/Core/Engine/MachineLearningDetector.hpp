/**
 * ============================================================================
 * ShadowStrike Core Engine - MACHINE LEARNING DETECTOR (The AI)
 * ============================================================================
 *
 * @file MachineLearningDetector.hpp
 * @brief Static AI engine for pre-execution malware classification.
 *
 * This module enables "Signature-less" detection by using a trained ML model
 * (Random Forest, Gradient Boosting, or Deep Learning) to classify PE files
 * based on extracted features.
 *
 * Integrations:
 * - **Core::FileSystem::ExecutableAnalyzer**: Extracts features (Import count, Section entropy, etc.).
 * - **Utils::MathUtils**: (Assumed) Vector/Matrix operations.
 *
 * Features:
 * 1. Feature Extraction: Turns a PE file into a feature vector (float[]).
 * 2. Inference: Runs the model (e.g. XGBoost/LightGBM) locally.
 * 3. Anomaly Scoring: Returns a probability score (0.0 - 1.0).
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @copyright 2026 ShadowStrike Security Suite
 */

#pragma once

#include "../FileSystem/ExecutableAnalyzer.hpp"
#include <vector>
#include <string>
#include <memory>

namespace ShadowStrike {
    namespace Core {
        namespace Engine {

            struct ModelConfig {
                std::wstring modelPath;
                float threshold; // e.g. 0.85
                bool useGPU;
            };

            struct PredictionResult {
                bool isMalicious;
                float probability;
                std::vector<std::string> contributingFeatures; // e.g. "HighEntropy + LowImports"
            };

            class MachineLearningDetector {
            public:
                static MachineLearningDetector& Instance();

                /**
                 * @brief Load the trained model into memory.
                 */
                bool Initialize(const ModelConfig& config);

                /**
                 * @brief Predict maliciousness of a PE file.
                 * @param info Extracted PE metadata from ExecutableAnalyzer.
                 */
                PredictionResult Analyze(const FileSystem::ExecutableInfo& info);

            private:
                MachineLearningDetector() = default;
                ~MachineLearningDetector() = default;

                // Feature Engineering
                std::vector<float> ExtractFeatures(const FileSystem::ExecutableInfo& info);
                
                // Model Inference (Placeholder for XGBoost/ONNX wrapper)
                float RunInference(const std::vector<float>& features);

                ModelConfig m_config;
                bool m_modelLoaded = false;
            };

        } // namespace Engine
    } // namespace Core
} // namespace ShadowStrike
