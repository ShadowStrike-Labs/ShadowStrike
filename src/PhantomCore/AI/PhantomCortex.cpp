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
#include "pch.h"

/**
 * ============================================================================
 * ShadowStrike PhantomCortex - AI/ML DETECTION ORCHESTRATOR IMPLEMENTATION
 * ============================================================================
 *
 * @file PhantomCortex.cpp
 * @brief Top-level orchestrator for the PhantomCortex AI/ML detection pipeline.
 *
 * Coordinates FeatureExtractor, ModelInference, and ModelCache to provide
 * a unified detection API across five model types (Static, Behavioral,
 * Memory, Network, Emulation) with weighted ensemble aggregation.
 *
 * DETECTION PIPELINE PER CALL:
 * ============================
 *   1. Validate operational state and input bounds
 *   2. Extract feature vector via FeatureExtractor
 *   3. Run inference via ModelInference
 *   4. Interpret raw output against per-model thresholds
 *   5. Update atomic statistics counters
 *   6. Return CortexVerdict
 *
 * ENSEMBLE AGGREGATION:
 * =====================
 *   - Weighted sum: Σ(weight_i × confidence_i × verdict_score_i)
 *   - Verdict scores: Benign=0.0, Suspicious=0.5, Malicious=1.0
 *   - Normalize by sum of participating weights
 *   - Final verdict via ensemble threshold comparison
 *
 * THREAD SAFETY:
 * ==============
 *   - Analyze*() methods acquire shared lock on operationalMutex
 *   - Initialize/Shutdown/UpdateModels acquire exclusive lock
 *   - Statistics use lock-free std::atomic counters
 *   - EnsembleVerdict acquires a shared lock to read config thresholds
 *
 * @author ShadowStrike Security Team
 * @version 1.0.0
 * @date 2026
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 *
 * ============================================================================
 */

#include "PhantomCortex.hpp"
#include "FeatureExtractor.hpp"
#include "ModelInference.hpp"
#include "ModelCache.hpp"
#include "../Utils/Logger.hpp"

#include <algorithm>
#include <numeric>
#include <cmath>
#include <filesystem>

namespace ShadowStrike {
namespace AI {

// ============================================================================
// CONSTANTS & INTERNAL HELPERS
// ============================================================================

namespace {

    constexpr const wchar_t* LOG_CATEGORY = L"PhantomCortex";

    /// @brief Mapping from CortexModelType ordinal to model subdirectory name
    constexpr const wchar_t* kModelSubdirs[CortexConstants::MODEL_COUNT] = {
        L"static",
        L"behavioral",
        L"memory",
        L"network",
        L"emulation"
    };

    /// @brief Mapping from CortexModelType ordinal to human-readable label
    constexpr const wchar_t* kModelLabels[CortexConstants::MODEL_COUNT] = {
        L"Static",
        L"Behavioral",
        L"Memory",
        L"Network",
        L"Emulation"
    };

    /// @brief Number of output classes per model type
    constexpr size_t kModelOutputClasses[CortexConstants::MODEL_COUNT] = {
        1,      // Static — single probability (malicious)
        20,     // Behavioral — 20-class softmax (BehaviorCategory)
        5,      // Memory — 5-class (MemoryThreatType)
        8,      // Network — 8-class (NetworkThreatType)
        3       // Emulation — 3-class (Benign, Suspicious, Malicious)
    };

    /// @brief Convert ThreatVerdict to its numeric score for ensemble weighting
    [[nodiscard]] constexpr float VerdictToScore(ThreatVerdict v) noexcept {
        switch (v) {
            case ThreatVerdict::Malicious:  return 1.0f;
            case ThreatVerdict::Suspicious: return 0.5f;
            case ThreatVerdict::Benign:
            default:                        return 0.0f;
        }
    }

    /// @brief Retrieve the per-model threshold from config by model type ordinal
    [[nodiscard]] float GetThresholdForModel(
        const CortexConfig& config,
        CortexModelType type) noexcept
    {
        switch (type) {
            case CortexModelType::Static:      return config.staticThreshold;
            case CortexModelType::Behavioral:  return config.behavioralThreshold;
            case CortexModelType::Memory:      return config.memoryThreshold;
            case CortexModelType::Network:     return config.networkThreshold;
            case CortexModelType::Emulation:   return config.emulationThreshold;
            default:                           return 0.5f;
        }
    }

    /// @brief Build an error verdict for early-exit conditions
    [[nodiscard]] CortexVerdict MakeErrorVerdict(
        CortexModelType source,
        const std::wstring& details) noexcept
    {
        CortexVerdict v{};
        v.verdict    = ThreatVerdict::Benign;
        v.confidence = 0.0f;
        v.source     = source;
        v.details    = details;
        return v;
    }

    /// @brief Clamp a float to [0.0, 1.0], treating NaN as 0.0
    [[nodiscard]] float ClampProbability(float p) noexcept {
        if (std::isnan(p) || p < 0.0f) return 0.0f;
        if (p > 1.0f) return 1.0f;
        return p;
    }

    /// @brief Find argmax index and value in a span of floats
    struct ArgMaxResult {
        size_t index = 0;
        float  value = 0.0f;
    };

    [[nodiscard]] ArgMaxResult FindArgMax(std::span<const float> values) noexcept {
        ArgMaxResult result{};
        if (values.empty()) return result;

        result.index = 0;
        result.value = values[0];
        for (size_t i = 1; i < values.size(); ++i) {
            if (values[i] > result.value) {
                result.index = i;
                result.value = values[i];
            }
        }
        return result;
    }

}  // anonymous namespace

// ============================================================================
// Impl STRUCTURE
// ============================================================================

struct PhantomCortex::Impl {
    mutable std::shared_mutex operationalMutex;
    bool operational = false;
    CortexConfig config;

    // Lock-free statistics counters
    std::atomic<uint64_t> totalInferences{0};
    std::atomic<uint64_t> totalMalicious{0};
    std::atomic<uint64_t> totalSuspicious{0};
    std::atomic<uint64_t> totalBenign{0};
    std::atomic<uint64_t> totalInferenceTimeUs{0};
    std::atomic<uint64_t> modelLoadErrors{0};

    // Ensemble weights indexed by CortexModelType ordinal.
    // Tuned empirically: Static is strongest baseline, Behavioral high signal
    // at runtime, Memory/Network/Emulation are supplementary high-precision.
    static constexpr std::array<float, CortexConstants::MODEL_COUNT> kEnsembleWeights = {
        0.30f,  // Static   — strong baseline, fast
        0.25f,  // Behavioral — high signal during execution
        0.15f,  // Memory   — targeted, high precision
        0.15f,  // Network  — C2/exfil detection
        0.15f   // Emulation — deep analysis
    };

    /// @brief Update atomic statistics after an inference completes
    void RecordInference(
        ThreatVerdict verdict,
        std::chrono::microseconds elapsed) noexcept
    {
        totalInferences.fetch_add(1, std::memory_order_relaxed);
        totalInferenceTimeUs.fetch_add(
            static_cast<uint64_t>(elapsed.count()),
            std::memory_order_relaxed);

        switch (verdict) {
            case ThreatVerdict::Malicious:
                totalMalicious.fetch_add(1, std::memory_order_relaxed);
                break;
            case ThreatVerdict::Suspicious:
                totalSuspicious.fetch_add(1, std::memory_order_relaxed);
                break;
            case ThreatVerdict::Benign:
            default:
                totalBenign.fetch_add(1, std::memory_order_relaxed);
                break;
        }
    }
};

// ============================================================================
// SINGLETON & LIFECYCLE
// ============================================================================

PhantomCortex::PhantomCortex()
    : m_impl(std::make_unique<Impl>())
{
}

PhantomCortex& PhantomCortex::Instance() noexcept {
    static PhantomCortex instance;
    return instance;
}

PhantomCortex::~PhantomCortex() {
    Shutdown();
}

bool PhantomCortex::Initialize(const CortexConfig& config) noexcept {
    try {
        std::unique_lock lock(m_impl->operationalMutex);

        if (m_impl->operational) {
            SS_LOG_WARN(LOG_CATEGORY, L"PhantomCortex already operational — re-initializing");
            m_impl->operational = false;
        }

        m_impl->config = config;

        SS_LOG_INFO(LOG_CATEGORY, L"Initializing PhantomCortex AI/ML detection engine");
        SS_LOG_INFO(LOG_CATEGORY, L"Model directory: %ls", config.modelDirectory.c_str());

        // ---- Step 1: Initialize FeatureExtractor ----
        auto& extractor = FeatureExtractor::Instance();
        if (!extractor.Initialize()) {
            SS_LOG_ERROR(LOG_CATEGORY,
                L"FeatureExtractor initialization failed — PhantomCortex cannot operate");
            m_impl->modelLoadErrors.fetch_add(1, std::memory_order_relaxed);
            return false;
        }
        SS_LOG_INFO(LOG_CATEGORY, L"FeatureExtractor initialized successfully");

        // ---- Step 2: Initialize ModelInference (ORT environment) ----
        auto& inference = ModelInference::Instance();
        if (!inference.Initialize(config)) {
            SS_LOG_ERROR(LOG_CATEGORY,
                L"ModelInference (ONNX Runtime) initialization failed — PhantomCortex cannot operate");
            m_impl->modelLoadErrors.fetch_add(1, std::memory_order_relaxed);
            return false;
        }
        SS_LOG_INFO(LOG_CATEGORY, L"ModelInference (ONNX Runtime) initialized successfully");

        // ---- Step 3: Initialize ModelCache (file management) ----
        auto& cache = ModelCache::Instance();
        if (!cache.Initialize(config.modelDirectory)) {
            SS_LOG_ERROR(LOG_CATEGORY,
                L"ModelCache initialization failed for directory: %ls",
                config.modelDirectory.c_str());
            m_impl->modelLoadErrors.fetch_add(1, std::memory_order_relaxed);
            return false;
        }
        SS_LOG_INFO(LOG_CATEGORY, L"ModelCache initialized successfully");

        // ---- Step 4: Load all available models ----
        uint32_t modelsLoaded = 0;
        for (size_t i = 0; i < CortexConstants::MODEL_COUNT; ++i) {
            const auto modelType = static_cast<CortexModelType>(i);
            auto modelPath = cache.GetModelPath(modelType);

            if (!modelPath.has_value()) {
                SS_LOG_WARN(LOG_CATEGORY,
                    L"No model file found for %ls slot — slot will be inactive",
                    kModelLabels[i]);
                continue;
            }

            if (!cache.VerifyIntegrity(modelType)) {
                SS_LOG_ERROR(LOG_CATEGORY,
                    L"Integrity verification FAILED for %ls model at: %ls",
                    kModelLabels[i], modelPath->c_str());
                m_impl->modelLoadErrors.fetch_add(1, std::memory_order_relaxed);
                continue;
            }

            if (!inference.LoadModel(modelType, *modelPath)) {
                SS_LOG_ERROR(LOG_CATEGORY,
                    L"Failed to load %ls model from: %ls",
                    kModelLabels[i], modelPath->c_str());
                m_impl->modelLoadErrors.fetch_add(1, std::memory_order_relaxed);
                continue;
            }

            ++modelsLoaded;
            SS_LOG_INFO(LOG_CATEGORY, L"Loaded %ls model from: %ls",
                kModelLabels[i], modelPath->c_str());
        }

        SS_LOG_INFO(LOG_CATEGORY, L"Model loading complete: %u of %zu models loaded",
            modelsLoaded, CortexConstants::MODEL_COUNT);

        // ---- Step 5: Log hardware capabilities ----
        SS_LOG_INFO(LOG_CATEGORY, L"Hardware capabilities — AVX2: %ls, AVX-512: %ls, DirectML (GPU): %ls",
            inference.HasAVX2()     ? L"YES" : L"NO",
            inference.HasAVX512()   ? L"YES" : L"NO",
            inference.HasDirectML() ? L"YES" : L"NO");

        // ---- Step 6: Log loaded model versions ----
        for (size_t i = 0; i < CortexConstants::MODEL_COUNT; ++i) {
            const auto modelType = static_cast<CortexModelType>(i);
            auto version = inference.GetModelVersion(modelType);
            if (version.has_value()) {
                SS_LOG_INFO(LOG_CATEGORY,
                    L"  %ls model v%u.%u.%u (hash: %.16ls...)",
                    kModelLabels[i],
                    version->major, version->minor, version->patch,
                    version->modelHash.c_str());
            }
        }

        m_impl->operational = true;
        SS_LOG_INFO(LOG_CATEGORY,
            L"PhantomCortex initialization COMPLETE — engine is operational");
        return true;

    } catch (const std::exception& ex) {
        SS_LOG_ERROR(LOG_CATEGORY,
            L"PhantomCortex initialization threw exception: %hs", ex.what());
        return false;
    } catch (...) {
        SS_LOG_ERROR(LOG_CATEGORY,
            L"PhantomCortex initialization threw unknown exception");
        return false;
    }
}

void PhantomCortex::Shutdown() noexcept {
    try {
        if (!m_impl) return;

        std::unique_lock lock(m_impl->operationalMutex);

        if (!m_impl->operational) {
            SS_LOG_DEBUG(LOG_CATEGORY, L"PhantomCortex already shut down — no-op");
            return;
        }

        SS_LOG_INFO(LOG_CATEGORY, L"Shutting down PhantomCortex AI/ML detection engine");

        // Log final statistics before teardown
        const auto count = m_impl->totalInferences.load(std::memory_order_relaxed);
        const auto totalUs = m_impl->totalInferenceTimeUs.load(std::memory_order_relaxed);
        const uint64_t avgUs = (count > 0) ? (totalUs / count) : 0;

        SS_LOG_INFO(LOG_CATEGORY,
            L"Final stats — inferences: %llu, malicious: %llu, suspicious: %llu, "
            L"benign: %llu, avg latency: %llu us, load errors: %llu",
            m_impl->totalInferences.load(std::memory_order_relaxed),
            m_impl->totalMalicious.load(std::memory_order_relaxed),
            m_impl->totalSuspicious.load(std::memory_order_relaxed),
            m_impl->totalBenign.load(std::memory_order_relaxed),
            avgUs,
            m_impl->modelLoadErrors.load(std::memory_order_relaxed));

        ModelInference::Instance().Shutdown();

        m_impl->operational = false;
        SS_LOG_INFO(LOG_CATEGORY, L"PhantomCortex shutdown complete");

    } catch (...) {
        if (m_impl) {
            m_impl->operational = false;
        }
    }
}

bool PhantomCortex::IsOperational() const noexcept {
    if (!m_impl) return false;
    std::shared_lock lock(m_impl->operationalMutex);
    return m_impl->operational;
}

// ============================================================================
// SINGLE-MODEL ANALYSIS: STATIC (PE FILE)
// ============================================================================

CortexVerdict PhantomCortex::AnalyzeFile(
    std::span<const uint8_t> fileBytes) noexcept
{
    constexpr auto kSource = CortexModelType::Static;

    // ---- Operational guard (held for entire method to prevent Shutdown race) ----
    if (!m_impl) {
        return MakeErrorVerdict(kSource, L"PhantomCortex not constructed");
    }

    std::shared_lock lock(m_impl->operationalMutex);
    if (!m_impl->operational) {
        return MakeErrorVerdict(kSource, L"PhantomCortex not operational");
    }

    // ---- Input validation ----
    if (fileBytes.empty()) {
        SS_LOG_WARN(LOG_CATEGORY, L"AnalyzeFile called with empty buffer");
        return MakeErrorVerdict(kSource, L"Empty file buffer");
    }

    if (fileBytes.size() > CortexConstants::MAX_PE_FILE_SIZE) {
        SS_LOG_WARN(LOG_CATEGORY,
            L"AnalyzeFile rejected: file size %zu exceeds MAX_PE_FILE_SIZE (%zu)",
            fileBytes.size(), CortexConstants::MAX_PE_FILE_SIZE);
        return MakeErrorVerdict(kSource, L"File exceeds maximum allowed size");
    }

    // ---- Begin timed inference ----
    const auto startTime = std::chrono::steady_clock::now();

    // ---- Feature extraction ----
    auto features = FeatureExtractor::Instance().ExtractPEFeatures(fileBytes);
    if (!features.has_value()) {
        SS_LOG_WARN(LOG_CATEGORY,
            L"PE feature extraction failed for %zu-byte file — returning benign with zero confidence",
            fileBytes.size());
        return MakeErrorVerdict(kSource, L"Feature extraction failed (invalid PE or parse error)");
    }

    if (features->size() != CortexConstants::STATIC_FEATURE_COUNT) {
        SS_LOG_ERROR(LOG_CATEGORY,
            L"Feature vector size mismatch: expected %zu, got %zu",
            CortexConstants::STATIC_FEATURE_COUNT, features->size());
        return MakeErrorVerdict(kSource, L"Feature vector dimension mismatch");
    }

    // ---- Model inference ----
    const std::array<int64_t, 2> shape = {
        1,
        static_cast<int64_t>(CortexConstants::STATIC_FEATURE_COUNT)
    };

    auto output = ModelInference::Instance().Infer(
        kSource,
        std::span<const float>(features->data(), features->size()),
        std::span<const int64_t>(shape.data(), shape.size()));

    if (!output.has_value() || output->empty()) {
        SS_LOG_ERROR(LOG_CATEGORY,
            L"Static model inference returned no output");
        return MakeErrorVerdict(kSource, L"Model inference failed");
    }

    // ---- Interpret output: single probability [malicious] ----
    const float probMalicious = ClampProbability((*output)[0]);
    const float threshold = GetThresholdForModel(m_impl->config, kSource);

    CortexVerdict verdict{};
    verdict.source     = kSource;
    verdict.confidence = probMalicious;

    if (probMalicious > threshold + 0.2f) {
        verdict.verdict = ThreatVerdict::Malicious;
    } else if (probMalicious > threshold) {
        verdict.verdict = ThreatVerdict::Suspicious;
    } else {
        verdict.verdict = ThreatVerdict::Benign;
    }

    // ---- Record timing and stats ----
    const auto endTime = std::chrono::steady_clock::now();
    verdict.inferenceTime = std::chrono::duration_cast<std::chrono::microseconds>(
        endTime - startTime);

    m_impl->RecordInference(verdict.verdict, verdict.inferenceTime);

    SS_LOG_DEBUG(LOG_CATEGORY,
        L"AnalyzeFile: verdict=%u confidence=%.4f latency=%lld us",
        static_cast<unsigned>(verdict.verdict),
        verdict.confidence,
        static_cast<long long>(verdict.inferenceTime.count()));

    return verdict;
}

// ============================================================================
// SINGLE-MODEL ANALYSIS: BEHAVIORAL (API CALL SEQUENCE)
// ============================================================================

CortexVerdict PhantomCortex::AnalyzeBehavior(
    std::span<const APICallRecord> apiCalls) noexcept
{
    constexpr auto kSource = CortexModelType::Behavioral;

    if (!m_impl) {
        return MakeErrorVerdict(kSource, L"PhantomCortex not constructed");
    }

    std::shared_lock lock(m_impl->operationalMutex);
    if (!m_impl->operational) {
        return MakeErrorVerdict(kSource, L"PhantomCortex not operational");
    }

    if (apiCalls.empty()) {
        SS_LOG_WARN(LOG_CATEGORY, L"AnalyzeBehavior called with empty API call sequence");
        return MakeErrorVerdict(kSource, L"Empty API call sequence");
    }

    const auto startTime = std::chrono::steady_clock::now();

    // ---- Feature extraction ----
    auto features = FeatureExtractor::Instance().ExtractBehavioralFeatures(apiCalls);
    if (!features.has_value()) {
        SS_LOG_WARN(LOG_CATEGORY,
            L"Behavioral feature extraction failed for %zu API calls",
            apiCalls.size());
        return MakeErrorVerdict(kSource, L"Behavioral feature extraction failed");
    }

    if (features->size() != CortexConstants::BEHAVIORAL_FEATURE_COUNT) {
        SS_LOG_ERROR(LOG_CATEGORY,
            L"Behavioral feature vector size mismatch: expected %zu, got %zu",
            CortexConstants::BEHAVIORAL_FEATURE_COUNT, features->size());
        return MakeErrorVerdict(kSource, L"Feature vector dimension mismatch");
    }

    // ---- Model inference ----
    const std::array<int64_t, 2> shape = {
        1,
        static_cast<int64_t>(CortexConstants::BEHAVIORAL_FEATURE_COUNT)
    };

    auto output = ModelInference::Instance().Infer(
        kSource,
        std::span<const float>(features->data(), features->size()),
        std::span<const int64_t>(shape.data(), shape.size()));

    if (!output.has_value() || output->size() < kModelOutputClasses[static_cast<size_t>(kSource)]) {
        SS_LOG_ERROR(LOG_CATEGORY,
            L"Behavioral model inference returned insufficient output (got %zu, expected %zu)",
            output.has_value() ? output->size() : 0u,
            kModelOutputClasses[static_cast<size_t>(kSource)]);
        return MakeErrorVerdict(kSource, L"Model inference failed");
    }

    // ---- Interpret: 20-class softmax → argmax for BehaviorCategory ----
    const auto argmax = FindArgMax(
        std::span<const float>(output->data(), kModelOutputClasses[static_cast<size_t>(kSource)]));

    const float confidence = ClampProbability(argmax.value);
    const auto category = static_cast<BehaviorCategory>(
        std::min(argmax.index, static_cast<size_t>(19)));

    const float threshold = GetThresholdForModel(m_impl->config, kSource);

    CortexVerdict verdict{};
    verdict.source           = kSource;
    verdict.confidence       = confidence;
    verdict.behaviorCategory = category;

    if (category == BehaviorCategory::Benign || confidence <= threshold) {
        verdict.verdict = ThreatVerdict::Benign;
    } else if (confidence > threshold + 0.2f) {
        verdict.verdict = ThreatVerdict::Malicious;
    } else {
        verdict.verdict = ThreatVerdict::Suspicious;
    }

    const auto endTime = std::chrono::steady_clock::now();
    verdict.inferenceTime = std::chrono::duration_cast<std::chrono::microseconds>(
        endTime - startTime);

    m_impl->RecordInference(verdict.verdict, verdict.inferenceTime);

    SS_LOG_DEBUG(LOG_CATEGORY,
        L"AnalyzeBehavior: verdict=%u category=%u confidence=%.4f latency=%lld us",
        static_cast<unsigned>(verdict.verdict),
        static_cast<unsigned>(category),
        verdict.confidence,
        static_cast<long long>(verdict.inferenceTime.count()));

    return verdict;
}

// ============================================================================
// SINGLE-MODEL ANALYSIS: MEMORY REGION
// ============================================================================

CortexVerdict PhantomCortex::AnalyzeMemory(
    const MemoryRegionInfo& region) noexcept
{
    constexpr auto kSource = CortexModelType::Memory;

    if (!m_impl) {
        return MakeErrorVerdict(kSource, L"PhantomCortex not constructed");
    }

    std::shared_lock lock(m_impl->operationalMutex);
    if (!m_impl->operational) {
        return MakeErrorVerdict(kSource, L"PhantomCortex not operational");
    }

    if (region.data.empty()) {
        SS_LOG_WARN(LOG_CATEGORY, L"AnalyzeMemory called with empty region data");
        return MakeErrorVerdict(kSource, L"Empty memory region");
    }

    if (region.data.size() > CortexConstants::MAX_MEMORY_REGION_SIZE) {
        SS_LOG_WARN(LOG_CATEGORY,
            L"AnalyzeMemory rejected: region size %zu exceeds MAX_MEMORY_REGION_SIZE (%zu)",
            region.data.size(), CortexConstants::MAX_MEMORY_REGION_SIZE);
        return MakeErrorVerdict(kSource, L"Memory region exceeds maximum allowed size");
    }

    const auto startTime = std::chrono::steady_clock::now();

    // ---- Feature extraction ----
    auto features = FeatureExtractor::Instance().ExtractMemoryFeatures(region);
    if (!features.has_value()) {
        SS_LOG_WARN(LOG_CATEGORY,
            L"Memory feature extraction failed for region at 0x%llX (%zu bytes)",
            static_cast<unsigned long long>(region.baseAddress), region.data.size());
        return MakeErrorVerdict(kSource, L"Memory feature extraction failed");
    }

    if (features->size() != CortexConstants::MEMORY_FEATURE_COUNT) {
        SS_LOG_ERROR(LOG_CATEGORY,
            L"Memory feature vector size mismatch: expected %zu, got %zu",
            CortexConstants::MEMORY_FEATURE_COUNT, features->size());
        return MakeErrorVerdict(kSource, L"Feature vector dimension mismatch");
    }

    // ---- Model inference ----
    const std::array<int64_t, 2> shape = {
        1,
        static_cast<int64_t>(CortexConstants::MEMORY_FEATURE_COUNT)
    };

    auto output = ModelInference::Instance().Infer(
        kSource,
        std::span<const float>(features->data(), features->size()),
        std::span<const int64_t>(shape.data(), shape.size()));

    if (!output.has_value() || output->size() < kModelOutputClasses[static_cast<size_t>(kSource)]) {
        SS_LOG_ERROR(LOG_CATEGORY,
            L"Memory model inference returned insufficient output (got %zu, expected %zu)",
            output.has_value() ? output->size() : 0u,
            kModelOutputClasses[static_cast<size_t>(kSource)]);
        return MakeErrorVerdict(kSource, L"Model inference failed");
    }

    // ---- Interpret: 5-class output → MemoryThreatType ----
    const auto argmax = FindArgMax(
        std::span<const float>(output->data(), kModelOutputClasses[static_cast<size_t>(kSource)]));

    const float confidence = ClampProbability(argmax.value);
    const auto threatType = static_cast<MemoryThreatType>(
        std::min(argmax.index, static_cast<size_t>(4)));

    const float threshold = GetThresholdForModel(m_impl->config, kSource);

    CortexVerdict verdict{};
    verdict.source       = kSource;
    verdict.confidence   = confidence;
    verdict.memoryThreat = threatType;

    if (threatType == MemoryThreatType::Benign || confidence <= threshold) {
        verdict.verdict = ThreatVerdict::Benign;
    } else if (confidence > threshold + 0.2f) {
        verdict.verdict = ThreatVerdict::Malicious;
    } else {
        verdict.verdict = ThreatVerdict::Suspicious;
    }

    const auto endTime = std::chrono::steady_clock::now();
    verdict.inferenceTime = std::chrono::duration_cast<std::chrono::microseconds>(
        endTime - startTime);

    m_impl->RecordInference(verdict.verdict, verdict.inferenceTime);

    SS_LOG_DEBUG(LOG_CATEGORY,
        L"AnalyzeMemory: verdict=%u threatType=%u confidence=%.4f addr=0x%llX latency=%lld us",
        static_cast<unsigned>(verdict.verdict),
        static_cast<unsigned>(threatType),
        verdict.confidence,
        static_cast<unsigned long long>(region.baseAddress),
        static_cast<long long>(verdict.inferenceTime.count()));

    return verdict;
}

// ============================================================================
// SINGLE-MODEL ANALYSIS: NETWORK FLOW
// ============================================================================

CortexVerdict PhantomCortex::AnalyzeNetwork(
    const NetworkFlowInfo& flow) noexcept
{
    constexpr auto kSource = CortexModelType::Network;

    if (!m_impl) {
        return MakeErrorVerdict(kSource, L"PhantomCortex not constructed");
    }

    std::shared_lock lock(m_impl->operationalMutex);
    if (!m_impl->operational) {
        return MakeErrorVerdict(kSource, L"PhantomCortex not operational");
    }

    const auto startTime = std::chrono::steady_clock::now();

    // ---- Feature extraction ----
    auto features = FeatureExtractor::Instance().ExtractNetworkFeatures(flow);
    if (!features.has_value()) {
        SS_LOG_WARN(LOG_CATEGORY,
            L"Network feature extraction failed for flow %u.%u.%u.%u:%u -> %u.%u.%u.%u:%u",
            (flow.srcIPv4 >> 24) & 0xFF, (flow.srcIPv4 >> 16) & 0xFF,
            (flow.srcIPv4 >> 8)  & 0xFF,  flow.srcIPv4        & 0xFF,
            flow.srcPort,
            (flow.dstIPv4 >> 24) & 0xFF, (flow.dstIPv4 >> 16) & 0xFF,
            (flow.dstIPv4 >> 8)  & 0xFF,  flow.dstIPv4        & 0xFF,
            flow.dstPort);
        return MakeErrorVerdict(kSource, L"Network feature extraction failed");
    }

    if (features->size() != CortexConstants::NETWORK_FEATURE_COUNT) {
        SS_LOG_ERROR(LOG_CATEGORY,
            L"Network feature vector size mismatch: expected %zu, got %zu",
            CortexConstants::NETWORK_FEATURE_COUNT, features->size());
        return MakeErrorVerdict(kSource, L"Feature vector dimension mismatch");
    }

    // ---- Model inference ----
    const std::array<int64_t, 2> shape = {
        1,
        static_cast<int64_t>(CortexConstants::NETWORK_FEATURE_COUNT)
    };

    auto output = ModelInference::Instance().Infer(
        kSource,
        std::span<const float>(features->data(), features->size()),
        std::span<const int64_t>(shape.data(), shape.size()));

    if (!output.has_value() || output->size() < kModelOutputClasses[static_cast<size_t>(kSource)]) {
        SS_LOG_ERROR(LOG_CATEGORY,
            L"Network model inference returned insufficient output (got %zu, expected %zu)",
            output.has_value() ? output->size() : 0u,
            kModelOutputClasses[static_cast<size_t>(kSource)]);
        return MakeErrorVerdict(kSource, L"Model inference failed");
    }

    // ---- Interpret: 8-class output → NetworkThreatType ----
    const auto argmax = FindArgMax(
        std::span<const float>(output->data(), kModelOutputClasses[static_cast<size_t>(kSource)]));

    const float confidence = ClampProbability(argmax.value);
    const auto threatType = static_cast<NetworkThreatType>(
        std::min(argmax.index, static_cast<size_t>(7)));

    const float threshold = GetThresholdForModel(m_impl->config, kSource);

    CortexVerdict verdict{};
    verdict.source        = kSource;
    verdict.confidence    = confidence;
    verdict.networkThreat = threatType;

    if (threatType == NetworkThreatType::Normal || confidence <= threshold) {
        verdict.verdict = ThreatVerdict::Benign;
    } else if (confidence > threshold + 0.2f) {
        verdict.verdict = ThreatVerdict::Malicious;
    } else {
        verdict.verdict = ThreatVerdict::Suspicious;
    }

    const auto endTime = std::chrono::steady_clock::now();
    verdict.inferenceTime = std::chrono::duration_cast<std::chrono::microseconds>(
        endTime - startTime);

    m_impl->RecordInference(verdict.verdict, verdict.inferenceTime);

    SS_LOG_DEBUG(LOG_CATEGORY,
        L"AnalyzeNetwork: verdict=%u threatType=%u confidence=%.4f latency=%lld us",
        static_cast<unsigned>(verdict.verdict),
        static_cast<unsigned>(threatType),
        verdict.confidence,
        static_cast<long long>(verdict.inferenceTime.count()));

    return verdict;
}

// ============================================================================
// SINGLE-MODEL ANALYSIS: EMULATION TRACE
// ============================================================================

CortexVerdict PhantomCortex::AnalyzeEmulationTrace(
    std::span<const EmulationEvent> events) noexcept
{
    constexpr auto kSource = CortexModelType::Emulation;

    if (!m_impl) {
        return MakeErrorVerdict(kSource, L"PhantomCortex not constructed");
    }

    std::shared_lock lock(m_impl->operationalMutex);
    if (!m_impl->operational) {
        return MakeErrorVerdict(kSource, L"PhantomCortex not operational");
    }

    if (events.empty()) {
        SS_LOG_WARN(LOG_CATEGORY, L"AnalyzeEmulationTrace called with empty event trace");
        return MakeErrorVerdict(kSource, L"Empty emulation trace");
    }

    const auto startTime = std::chrono::steady_clock::now();

    // ---- Feature extraction ----
    auto features = FeatureExtractor::Instance().ExtractEmulationFeatures(events);
    if (!features.has_value()) {
        SS_LOG_WARN(LOG_CATEGORY,
            L"Emulation feature extraction failed for trace with %zu events",
            events.size());
        return MakeErrorVerdict(kSource, L"Emulation feature extraction failed");
    }

    if (features->size() != CortexConstants::EMULATION_FEATURE_COUNT) {
        SS_LOG_ERROR(LOG_CATEGORY,
            L"Emulation feature vector size mismatch: expected %zu, got %zu",
            CortexConstants::EMULATION_FEATURE_COUNT, features->size());
        return MakeErrorVerdict(kSource, L"Feature vector dimension mismatch");
    }

    // ---- Model inference ----
    const std::array<int64_t, 2> shape = {
        1,
        static_cast<int64_t>(CortexConstants::EMULATION_FEATURE_COUNT)
    };

    auto output = ModelInference::Instance().Infer(
        kSource,
        std::span<const float>(features->data(), features->size()),
        std::span<const int64_t>(shape.data(), shape.size()));

    if (!output.has_value() || output->size() < kModelOutputClasses[static_cast<size_t>(kSource)]) {
        SS_LOG_ERROR(LOG_CATEGORY,
            L"Emulation model inference returned insufficient output (got %zu, expected %zu)",
            output.has_value() ? output->size() : 0u,
            kModelOutputClasses[static_cast<size_t>(kSource)]);
        return MakeErrorVerdict(kSource, L"Model inference failed");
    }

    // ---- Interpret: 3-class output [Benign, Suspicious, Malicious] ----
    const auto argmax = FindArgMax(
        std::span<const float>(output->data(), kModelOutputClasses[static_cast<size_t>(kSource)]));

    const float confidence = ClampProbability(argmax.value);
    const float threshold = GetThresholdForModel(m_impl->config, kSource);

    CortexVerdict verdict{};
    verdict.source     = kSource;
    verdict.confidence = confidence;

    // Class 0 = Benign, 1 = Suspicious, 2 = Malicious (aligned with ThreatVerdict)
    if (argmax.index == 0 || confidence <= threshold) {
        verdict.verdict = ThreatVerdict::Benign;
    } else if (argmax.index == 2 && confidence > threshold) {
        verdict.verdict = ThreatVerdict::Malicious;
    } else {
        verdict.verdict = ThreatVerdict::Suspicious;
    }

    const auto endTime = std::chrono::steady_clock::now();
    verdict.inferenceTime = std::chrono::duration_cast<std::chrono::microseconds>(
        endTime - startTime);

    m_impl->RecordInference(verdict.verdict, verdict.inferenceTime);

    SS_LOG_DEBUG(LOG_CATEGORY,
        L"AnalyzeEmulationTrace: verdict=%u confidence=%.4f events=%zu latency=%lld us",
        static_cast<unsigned>(verdict.verdict),
        verdict.confidence,
        events.size(),
        static_cast<long long>(verdict.inferenceTime.count()));

    return verdict;
}

// ============================================================================
// ENSEMBLE VERDICT
// ============================================================================

CortexEnsembleVerdict PhantomCortex::EnsembleVerdict(
    std::optional<CortexVerdict> staticV,
    std::optional<CortexVerdict> behavioralV,
    std::optional<CortexVerdict> memoryV,
    std::optional<CortexVerdict> networkV,
    std::optional<CortexVerdict> emulationV) noexcept
{
    CortexEnsembleVerdict ensemble{};

    // Pack individual verdicts into an array for uniform iteration
    const std::array<std::optional<CortexVerdict>*, CortexConstants::MODEL_COUNT> inputs = {
        &staticV,
        &behavioralV,
        &memoryV,
        &networkV,
        &emulationV
    };

    float weightedScoreSum = 0.0f;
    float participatingWeightSum = 0.0f;
    std::chrono::microseconds totalTime{0};
    uint32_t participantCount = 0;

    for (size_t i = 0; i < CortexConstants::MODEL_COUNT; ++i) {
        if (inputs[i]->has_value()) {
            const auto& v = inputs[i]->value();
            ensemble.modelVerdicts[i] = v;

            const float weight = Impl::kEnsembleWeights[i];
            const float score  = VerdictToScore(v.verdict);

            weightedScoreSum      += weight * v.confidence * score;
            participatingWeightSum += weight;
            totalTime             += v.inferenceTime;
            ++participantCount;
        } else {
            // Fill inactive slot with default benign verdict
            ensemble.modelVerdicts[i] = CortexVerdict{};
            ensemble.modelVerdicts[i].source = static_cast<CortexModelType>(i);
        }
    }

    ensemble.totalInferenceTime = totalTime;

    // ---- Compute ensemble confidence and final verdict ----
    if (participantCount == 0 || participatingWeightSum <= 0.0f) {
        SS_LOG_WARN(LOG_CATEGORY,
            L"EnsembleVerdict called with no participating models — returning Benign");
        ensemble.finalVerdict       = ThreatVerdict::Benign;
        ensemble.ensembleConfidence = 0.0f;
        return ensemble;
    }

    const float normalizedScore = weightedScoreSum / participatingWeightSum;
    ensemble.ensembleConfidence = ClampProbability(normalizedScore);

    // Retrieve ensemble threshold — use stored config if available, else default
    float ensembleThreshold = 0.5f;
    if (m_impl) {
        std::shared_lock lock(m_impl->operationalMutex);
        ensembleThreshold = m_impl->config.ensembleThreshold;
    }

    if (normalizedScore > ensembleThreshold + 0.2f) {
        ensemble.finalVerdict = ThreatVerdict::Malicious;
    } else if (normalizedScore > ensembleThreshold) {
        ensemble.finalVerdict = ThreatVerdict::Suspicious;
    } else {
        ensemble.finalVerdict = ThreatVerdict::Benign;
    }

    SS_LOG_DEBUG(LOG_CATEGORY,
        L"EnsembleVerdict: final=%u confidence=%.4f participants=%u totalTime=%lld us",
        static_cast<unsigned>(ensemble.finalVerdict),
        ensemble.ensembleConfidence,
        participantCount,
        static_cast<long long>(totalTime.count()));

    return ensemble;
}

// ============================================================================
// MODEL MANAGEMENT: HOT-SWAP UPDATE
// ============================================================================

bool PhantomCortex::UpdateModels(
    const std::filesystem::path& newModelDir) noexcept
{
    if (!m_impl) {
        SS_LOG_ERROR(LOG_CATEGORY, L"UpdateModels called on uninitialized PhantomCortex");
        return false;
    }

    std::unique_lock lock(m_impl->operationalMutex);

    SS_LOG_INFO(LOG_CATEGORY, L"Beginning model hot-swap update from: %ls",
        newModelDir.c_str());

    if (!std::filesystem::exists(newModelDir) ||
        !std::filesystem::is_directory(newModelDir))
    {
        SS_LOG_ERROR(LOG_CATEGORY,
            L"Model update directory does not exist or is not a directory: %ls",
            newModelDir.c_str());
        return false;
    }

    auto& inference = ModelInference::Instance();
    auto& cache     = ModelCache::Instance();

    uint32_t modelsUpdated = 0;
    uint32_t modelsFailed  = 0;

    for (size_t i = 0; i < CortexConstants::MODEL_COUNT; ++i) {
        const auto modelType = static_cast<CortexModelType>(i);

        // Construct expected path: <newModelDir>/<subdirName>/current.onnx
        const auto candidatePath =
            newModelDir / kModelSubdirs[i] / L"current.onnx";

        std::error_code ec;
        if (!std::filesystem::exists(candidatePath, ec)) {
            SS_LOG_DEBUG(LOG_CATEGORY,
                L"No updated model found for %ls at: %ls — keeping current",
                kModelLabels[i], candidatePath.c_str());
            continue;
        }

        // Validate file size before attempting load
        const auto fileSize = std::filesystem::file_size(candidatePath, ec);
        if (ec || fileSize == 0) {
            SS_LOG_ERROR(LOG_CATEGORY,
                L"Cannot read file size for %ls model: %ls",
                kModelLabels[i], candidatePath.c_str());
            m_impl->modelLoadErrors.fetch_add(1, std::memory_order_relaxed);
            ++modelsFailed;
            continue;
        }

        if (fileSize > CortexConstants::MAX_MODEL_FILE_SIZE) {
            SS_LOG_ERROR(LOG_CATEGORY,
                L"Model file for %ls exceeds MAX_MODEL_FILE_SIZE (%zu > %zu): %ls",
                kModelLabels[i], static_cast<size_t>(fileSize),
                CortexConstants::MAX_MODEL_FILE_SIZE, candidatePath.c_str());
            m_impl->modelLoadErrors.fetch_add(1, std::memory_order_relaxed);
            ++modelsFailed;
            continue;
        }

        // Swap via ModelCache for integrity verification and atomic file swap
        if (!cache.SwapModel(modelType, candidatePath)) {
            SS_LOG_ERROR(LOG_CATEGORY,
                L"ModelCache swap failed for %ls model: %ls",
                kModelLabels[i], candidatePath.c_str());
            m_impl->modelLoadErrors.fetch_add(1, std::memory_order_relaxed);
            ++modelsFailed;
            continue;
        }

        // Verify integrity after swap
        if (!cache.VerifyIntegrity(modelType)) {
            SS_LOG_ERROR(LOG_CATEGORY,
                L"Post-swap integrity check FAILED for %ls model — rolling back",
                kModelLabels[i]);
            cache.Rollback(modelType);
            m_impl->modelLoadErrors.fetch_add(1, std::memory_order_relaxed);
            ++modelsFailed;
            continue;
        }

        // Load new model into inference engine (shadow session then swap)
        auto activePath = cache.GetModelPath(modelType);
        if (!activePath.has_value()) {
            SS_LOG_ERROR(LOG_CATEGORY,
                L"ModelCache returned no path after successful swap for %ls",
                kModelLabels[i]);
            cache.Rollback(modelType);
            m_impl->modelLoadErrors.fetch_add(1, std::memory_order_relaxed);
            ++modelsFailed;
            continue;
        }

        if (!inference.LoadModel(modelType, *activePath)) {
            SS_LOG_ERROR(LOG_CATEGORY,
                L"ModelInference failed to load swapped %ls model from: %ls — rolling back",
                kModelLabels[i], activePath->c_str());
            cache.Rollback(modelType);

            // Attempt to reload the rolled-back model
            auto rollbackPath = cache.GetModelPath(modelType);
            if (rollbackPath.has_value()) {
                inference.LoadModel(modelType, *rollbackPath);
            }

            m_impl->modelLoadErrors.fetch_add(1, std::memory_order_relaxed);
            ++modelsFailed;
            continue;
        }

        ++modelsUpdated;

        auto ver = inference.GetModelVersion(modelType);
        if (ver.has_value()) {
            SS_LOG_INFO(LOG_CATEGORY,
                L"Updated %ls model to v%u.%u.%u (hash: %.16ls...)",
                kModelLabels[i], ver->major, ver->minor, ver->patch,
                ver->modelHash.c_str());
        } else {
            SS_LOG_INFO(LOG_CATEGORY,
                L"Updated %ls model (version metadata unavailable)",
                kModelLabels[i]);
        }
    }

    SS_LOG_INFO(LOG_CATEGORY,
        L"Model hot-swap complete: %u updated, %u failed, %zu unchanged",
        modelsUpdated, modelsFailed,
        CortexConstants::MODEL_COUNT - modelsUpdated - modelsFailed);

    return modelsUpdated > 0;
}

// ============================================================================
// MODEL VERSION QUERY
// ============================================================================

std::array<std::optional<ModelVersion>, CortexConstants::MODEL_COUNT>
PhantomCortex::GetModelVersions() const noexcept
{
    std::array<std::optional<ModelVersion>, CortexConstants::MODEL_COUNT> versions{};

    if (!m_impl) return versions;

    std::shared_lock lock(m_impl->operationalMutex);

    auto& inference = ModelInference::Instance();
    for (size_t i = 0; i < CortexConstants::MODEL_COUNT; ++i) {
        versions[i] = inference.GetModelVersion(static_cast<CortexModelType>(i));
    }

    return versions;
}

// ============================================================================
// RUNTIME STATISTICS
// ============================================================================

PhantomCortex::CortexStats PhantomCortex::GetStats() const noexcept
{
    CortexStats stats{};

    if (!m_impl) return stats;

    stats.totalInferences            = m_impl->totalInferences.load(std::memory_order_relaxed);
    stats.totalMaliciousDetections   = m_impl->totalMalicious.load(std::memory_order_relaxed);
    stats.totalSuspiciousDetections  = m_impl->totalSuspicious.load(std::memory_order_relaxed);
    stats.totalBenignClassifications = m_impl->totalBenign.load(std::memory_order_relaxed);
    stats.modelLoadErrors            = m_impl->modelLoadErrors.load(std::memory_order_relaxed);

    const auto count = m_impl->totalInferences.load(std::memory_order_relaxed);
    if (count > 0) {
        stats.averageInferenceTimeUs =
            m_impl->totalInferenceTimeUs.load(std::memory_order_relaxed) / count;
    }

    return stats;
}

}  // namespace AI
}  // namespace ShadowStrike
