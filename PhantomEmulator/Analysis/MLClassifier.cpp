/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * MLClassifier.cpp — Emulator ↔ PhantomCortex ML Bridge Implementation
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#include "MLClassifier.hpp"
#include "AI/ModelInference.hpp"
#include "AI/CortexTypes.hpp"

#include <algorithm>
#include <cmath>
#include <cstring>
#include <numeric>

namespace Phantom {

// Feature vector layout constants (must match Python training pipeline)
namespace FeatureLayout {
    static constexpr uint32_t kCategoryAlertCounts     = 0;    // [0..19]
    static constexpr uint32_t kCategoryMaxSeverity     = 20;   // [20..39]
    static constexpr uint32_t kCategoryMaxConfidence   = 40;   // [40..59]
    static constexpr uint32_t kBehaviorFlagExpansion   = 60;   // [60..123]
    static constexpr uint32_t kSequencePatternCounts   = 124;  // [124..143]
    static constexpr uint32_t kSequencePatternConfidence = 144; // [144..163]
    static constexpr uint32_t kMemoryFindingDistribution = 164; // [164..195]
    static constexpr uint32_t kWXTransitionFeatures    = 196;  // [196..211]
    static constexpr uint32_t kAPICallDistribution     = 212;  // [212..275]
    static constexpr uint32_t kInstructionDistribution = 276;  // [276..339]
    static constexpr uint32_t kSessionStatistics       = 340;  // [340..355]
    static constexpr uint32_t kReserved                = 356;  // [356..383]
    static constexpr uint32_t kTotalFeatures           = 384;  // Total

    static constexpr uint32_t kCategoryCount           = 20;   // BehaviorCategory count
    static constexpr uint32_t kBehaviorFlagBits        = 64;   // BehaviorFlag width
    static constexpr uint32_t kTopSequencePatterns     = 20;
    static constexpr uint32_t kMemoryBins              = 32;
    static constexpr uint32_t kWXFeatures              = 16;
    static constexpr uint32_t kAPIBins                 = 64;
    static constexpr uint32_t kInstructionBins         = 64;
    static constexpr uint32_t kSessionStats            = 16;
    static constexpr uint32_t kReservedCount           = 28;
}

// ============================================================================
// PIMPL Implementation
// ============================================================================

struct MLClassifier::Impl {
    bool enabled = false;

    // Normalize a value into [0, 1] with log scaling for wide-range counters
    static float LogNormalize(float value, float maxExpected) noexcept {
        if (value <= 0.0f) return 0.0f;
        if (value >= maxExpected) return 1.0f;
        return std::log1pf(value) / std::log1pf(maxExpected);
    }

    // Normalize a value into [0, 1] with linear scaling
    static float LinearNormalize(float value, float maxExpected) noexcept {
        if (value <= 0.0f) return 0.0f;
        if (value >= maxExpected) return 1.0f;
        return value / maxExpected;
    }
};

// ============================================================================
// Construction / Destruction
// ============================================================================

MLClassifier::MLClassifier(const EmulationConfig& config) noexcept
    : m_impl(std::make_unique<Impl>())
{
    m_impl->enabled = config.enableMLClassifier;
}

MLClassifier::~MLClassifier() noexcept = default;
MLClassifier::MLClassifier(MLClassifier&&) noexcept = default;
MLClassifier& MLClassifier::operator=(MLClassifier&&) noexcept = default;

// ============================================================================
// Feature Extraction
// ============================================================================

std::optional<std::vector<float>> MLClassifier::ExtractFeatures(
    const BehaviorMonitor& behavior,
    const MemoryTracker& memory,
    const APISequenceAnalyzer& apiSequence,
    std::span<const APICallRecord> apiLog,
    uint64_t totalInstructions,
    uint64_t totalMemoryAllocated) const noexcept
{
    if (!m_impl || !m_impl->enabled) return std::nullopt;

    using namespace FeatureLayout;

    std::vector<float> features(kTotalFeatures, 0.0f);

    // === Section 1: BehaviorCategory alert counts [0..19] ===
    const auto& alerts = behavior.GetAlerts();
    for (const auto& alert : alerts) {
        auto idx = static_cast<uint32_t>(alert.category);
        if (idx < kCategoryCount) {
            features[kCategoryAlertCounts + idx] += 1.0f;

            // Section 2: max severity per category [20..39]
            float sevNorm = static_cast<float>(alert.severity) / 4.0f;
            features[kCategoryMaxSeverity + idx] =
                std::max(features[kCategoryMaxSeverity + idx], sevNorm);

            // Section 3: max confidence per category [40..59]
            features[kCategoryMaxConfidence + idx] =
                std::max(features[kCategoryMaxConfidence + idx], alert.confidence);
        }
    }

    // Normalize alert counts with log scaling (max ~1000 alerts)
    for (uint32_t i = 0; i < kCategoryCount; ++i) {
        features[kCategoryAlertCounts + i] =
            Impl::LogNormalize(features[kCategoryAlertCounts + i], 1000.0f);
    }

    // === Section 4: BehaviorFlag bitfield expansion [60..123] ===
    auto flagBits = static_cast<uint64_t>(behavior.GetAccumulatedFlags());
    for (uint32_t i = 0; i < kBehaviorFlagBits; ++i) {
        features[kBehaviorFlagExpansion + i] =
            (flagBits & (1ULL << i)) ? 1.0f : 0.0f;
    }

    // === Section 5-6: API sequence pattern matches [124..163] ===
    const auto& matches = apiSequence.GetMatches();
    for (const auto& match : matches) {
        uint32_t patIdx = match.patternId;
        if (patIdx < kTopSequencePatterns) {
            features[kSequencePatternCounts + patIdx] += 1.0f;
            features[kSequencePatternConfidence + patIdx] =
                std::max(features[kSequencePatternConfidence + patIdx],
                         match.confidence);
        }
    }
    // Normalize pattern counts
    for (uint32_t i = 0; i < kTopSequencePatterns; ++i) {
        features[kSequencePatternCounts + i] =
            Impl::LogNormalize(features[kSequencePatternCounts + i], 100.0f);
    }

    // === Section 7: Memory finding distribution [164..195] ===
    auto wxPages = memory.GetWriteExecutePages();
    auto rwxAllocs = memory.GetRWXAllocations();
    // Bin 0: W→X page count (normalized)
    features[kMemoryFindingDistribution] =
        Impl::LogNormalize(static_cast<float>(wxPages.size()), 10000.0f);
    // Bin 1: RWX allocation count (normalized)
    features[kMemoryFindingDistribution + 1] =
        Impl::LogNormalize(static_cast<float>(rwxAllocs.size()), 1000.0f);
    // Bin 2: Unique written pages (normalized)
    features[kMemoryFindingDistribution + 2] =
        Impl::LogNormalize(
            static_cast<float>(memory.GetUniqueWrittenPages()), 50000.0f);

    // === Section 8: W→X transition features [196..211] ===
    uint32_t wxCount = memory.GetWriteExecuteCount();
    features[kWXTransitionFeatures] =
        Impl::LogNormalize(static_cast<float>(wxCount), 100000.0f);

    // If we have W→X pages, compute entropy of their address distribution
    if (!wxPages.empty()) {
        // Page address histogram: divide address space into 16 bins
        float binCounts[16] = {};
        for (auto addr : wxPages) {
            uint32_t bin = static_cast<uint32_t>(
                (addr >> 20) % 16);  // Rough spatial bucketing
            binCounts[bin] += 1.0f;
        }
        float total = static_cast<float>(wxPages.size());
        float entropy = 0.0f;
        for (int i = 0; i < 16; ++i) {
            if (binCounts[i] > 0.0f) {
                float p = binCounts[i] / total;
                entropy -= p * std::log2f(p);
            }
        }
        features[kWXTransitionFeatures + 1] = entropy / 4.0f; // Normalize (max log2(16)=4)

        // W→X page count / total unique written pages ratio
        uint32_t writtenPages = memory.GetUniqueWrittenPages();
        if (writtenPages > 0) {
            features[kWXTransitionFeatures + 2] =
                std::min(1.0f,
                    static_cast<float>(wxCount) / static_cast<float>(writtenPages));
        }
    }

    // === Section 9: API call distribution [212..275] ===
    // Histogram of API ordinals into 64 bins (ordinal % 64)
    for (const auto& call : apiLog) {
        uint32_t bin = call.ordinal % kAPIBins;
        features[kAPICallDistribution + bin] += 1.0f;
    }
    // Normalize API bins
    float maxAPIBin = *std::max_element(
        features.begin() + kAPICallDistribution,
        features.begin() + kAPICallDistribution + kAPIBins);
    if (maxAPIBin > 0.0f) {
        for (uint32_t i = 0; i < kAPIBins; ++i) {
            features[kAPICallDistribution + i] /= maxAPIBin;
        }
    }

    // === Section 10: Instruction distribution [276..339] ===
    // Note: we don't have per-instruction traces here, but we encode
    // aggregate statistics from the API call patterns as a proxy.
    // This is populated from the instruction trace if available.
    // For now, encode the API call timing distribution as a proxy:
    if (!apiLog.empty()) {
        uint64_t maxInstrCount = apiLog.back().instructionCount;
        if (maxInstrCount > 0) {
            for (const auto& call : apiLog) {
                uint32_t bin = static_cast<uint32_t>(
                    (call.instructionCount * kInstructionBins) / (maxInstrCount + 1));
                if (bin >= kInstructionBins) bin = kInstructionBins - 1;
                features[kInstructionDistribution + bin] += 1.0f;
            }
            // Normalize
            float maxBin = *std::max_element(
                features.begin() + kInstructionDistribution,
                features.begin() + kInstructionDistribution + kInstructionBins);
            if (maxBin > 0.0f) {
                for (uint32_t i = 0; i < kInstructionBins; ++i) {
                    features[kInstructionDistribution + i] /= maxBin;
                }
            }
        }
    }

    // === Section 11: Session-level statistics [340..355] ===
    // 0: Total instructions (log-normalized)
    features[kSessionStatistics] =
        Impl::LogNormalize(static_cast<float>(totalInstructions), 200'000'000.0f);
    // 1: Total API calls (log-normalized)
    features[kSessionStatistics + 1] =
        Impl::LogNormalize(static_cast<float>(apiLog.size()), 1'000'000.0f);
    // 2: Total memory allocated (log-normalized to 512 MB)
    features[kSessionStatistics + 2] =
        Impl::LogNormalize(static_cast<float>(totalMemoryAllocated), 512.0f * 1024 * 1024);
    // 3: W→X count (log-normalized)
    features[kSessionStatistics + 3] =
        Impl::LogNormalize(static_cast<float>(wxCount), 100'000.0f);
    // 4: Behavior alert count (log-normalized)
    features[kSessionStatistics + 4] =
        Impl::LogNormalize(static_cast<float>(alerts.size()), 10'000.0f);
    // 5: Max behavior severity (normalized 0..1)
    features[kSessionStatistics + 5] =
        static_cast<float>(behavior.GetMaxSeverity()) / 4.0f;
    // 6: Sequence match count (log-normalized)
    features[kSessionStatistics + 6] =
        Impl::LogNormalize(static_cast<float>(matches.size()), 1000.0f);
    // 7: Max sequence severity (normalized 0..1)
    features[kSessionStatistics + 7] =
        static_cast<float>(apiSequence.GetMaxSeverity()) / 4.0f;
    // 8: Active state machine count (normalized)
    features[kSessionStatistics + 8] =
        Impl::LinearNormalize(
            static_cast<float>(behavior.GetActiveStateMachineCount()), 50.0f);
    // 9: Unique blocked API calls
    {
        uint32_t blockedCount = 0;
        for (const auto& call : apiLog) {
            if (call.wasBlocked) ++blockedCount;
        }
        features[kSessionStatistics + 9] =
            Impl::LogNormalize(static_cast<float>(blockedCount), 10'000.0f);
    }
    // 10: RWX total size (log-normalized)
    {
        uint64_t rwxTotal = 0;
        for (const auto& [base, size] : rwxAllocs) {
            rwxTotal += size;
        }
        features[kSessionStatistics + 10] =
            Impl::LogNormalize(static_cast<float>(rwxTotal), 64.0f * 1024 * 1024);
    }
    // 11-15: Reserved (stay 0.0f)

    return features;
}

// ============================================================================
// Classification
// ============================================================================

std::optional<MLClassificationResult> MLClassifier::Classify(
    const BehaviorMonitor& behavior,
    const MemoryTracker& memory,
    const APISequenceAnalyzer& apiSequence,
    std::span<const APICallRecord> apiLog,
    uint64_t totalInstructions,
    uint64_t totalMemoryAllocated) const noexcept
{
    if (!m_impl || !m_impl->enabled) return std::nullopt;

    // Extract features
    auto features = ExtractFeatures(
        behavior, memory, apiSequence, apiLog,
        totalInstructions, totalMemoryAllocated);
    if (!features) return std::nullopt;

    // Call PhantomCortex ONNX inference
    auto& inference = ShadowStrike::AI::ModelInference::Instance();

    std::array<int64_t, 2> shape = { 1, static_cast<int64_t>(features->size()) };

    auto output = inference.Infer(
        ShadowStrike::AI::CortexModelType::Emulation,
        std::span<const float>(features->data(), features->size()),
        std::span<const int64_t>(shape.data(), shape.size()));

    MLClassificationResult result;
    result.featureCount = static_cast<uint32_t>(features->size());

    if (!output || output->empty()) {
        result.modelAvailable = false;
        return result;
    }

    result.modelAvailable = true;

    // Decode model output:
    // Output[0] = malware probability (sigmoid already applied)
    result.malwareConfidence = std::clamp((*output)[0], 0.0f, 1.0f);

    // Output[1..20] = per-category softmax scores (if model provides them)
    uint8_t bestCategory = 0;
    float bestCategoryScore = 0.0f;
    size_t numCategories = std::min<size_t>(output->size() - 1, 20);
    for (size_t i = 0; i < numCategories; ++i) {
        float score = std::clamp((*output)[i + 1], 0.0f, 1.0f);
        result.categoryScores[i] = score;
        if (score > bestCategoryScore) {
            bestCategoryScore = score;
            bestCategory = static_cast<uint8_t>(i);
        }
    }
    result.predictedCategory = bestCategory;

    return result;
}

// ============================================================================
// Status
// ============================================================================

bool MLClassifier::IsModelLoaded() const noexcept {
    auto& inference = ShadowStrike::AI::ModelInference::Instance();
    return inference.IsModelLoaded(ShadowStrike::AI::CortexModelType::Emulation);
}

bool MLClassifier::IsEnabled() const noexcept {
    return m_impl && m_impl->enabled;
}

void MLClassifier::Reset() noexcept {
    // No mutable state to reset — classifier is stateless per invocation
}

} // namespace Phantom
