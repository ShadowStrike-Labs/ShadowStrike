/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * MLClassifier.hpp — Bridge between PhantomEmulator and PhantomCortex ML
 *
 * Extracts a 384-dimensional feature vector from emulation session signals
 * (BehaviorMonitor alerts, MemoryTracker findings, APISequenceAnalyzer
 * matches, instruction/API counts) and feeds it through the
 * CortexModelType::Emulation ONNX model for on-sensor classification.
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#pragma once

#include "../Common/Types.hpp"
#include "../Common/Config.hpp"
#include "BehaviorMonitor.hpp"
#include "../Core/Memory/MemoryTracker.hpp"
#include "APISequenceAnalyzer.hpp"
#include "../WinAPI/APITypes.hpp"

#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace Phantom {

// ============================================================================
// ML Classification Result
// ============================================================================

struct MLClassificationResult {
    float       malwareConfidence   = 0.0f;  // 0.0 = benign, 1.0 = certain malware
    float       categoryScores[20] = {};     // Per MalwareCategory (indexed by enum value)
    uint8_t     predictedCategory  = 0;      // Index of highest category score
    bool        modelAvailable     = false;  // False if ONNX model not loaded
    uint32_t    featureCount       = 0;      // Sanity: should be 384
};

// ============================================================================
// ML Classifier — Emulator ↔ PhantomCortex Bridge
// ============================================================================
//
// Architecture:
//   Phantom:: namespace (emulator) owns the signals.
//   ShadowStrike::AI:: namespace (PhantomCortex) owns the ML model.
//   This class bridges the two by:
//     1. Collecting emulation signals into a flat feature vector.
//     2. Calling ModelInference::Instance().Infer(Emulation, ...).
//     3. Decoding the model output into an MLClassificationResult.
//
// The feature vector layout (384 floats) matches the Python training
// pipeline exactly:
//   [0..19]    — BehaviorCategory alert counts (20 categories)
//   [20..39]   — BehaviorCategory max severity (normalized 0..1)
//   [40..59]   — BehaviorCategory max confidence
//   [60..123]  — BehaviorFlag bitfield expansion (64 flags)
//   [124..143] — API sequence pattern match counts (top 20 patterns)
//   [144..163] — API sequence pattern max confidence
//   [164..195] — Memory finding type distribution (32 bins)
//   [196..211] — W→X transition features (page count, entropy, timing)
//   [212..275] — API call distribution (64-bin histogram by ordinal range)
//   [276..339] — Instruction category distribution (64-bin histogram)
//   [340..355] — Session-level statistics (instruction count, API count,
//                memory allocated, W→X count, etc., 16 floats)
//   [356..383] — Reserved / padding (28 floats, zeroed)
//
// Thread safety: Classify() reads from const references to BehaviorMonitor,
//   MemoryTracker, and APISequenceAnalyzer. The emulation loop must ensure
//   these are not being mutated during the Classify() call. Typically called
//   once at the end of emulation, when the loop has stopped.
//
// Performance: Feature extraction is O(n) in alert/match counts. ONNX
//   inference is bounded by the model size (~100μs on AVX2). Total overhead
//   is negligible relative to emulation time.

class MLClassifier {
public:
    explicit MLClassifier(const EmulationConfig& config) noexcept;
    ~MLClassifier() noexcept;

    MLClassifier(const MLClassifier&) = delete;
    MLClassifier& operator=(const MLClassifier&) = delete;
    MLClassifier(MLClassifier&&) noexcept;
    MLClassifier& operator=(MLClassifier&&) noexcept;

    // === Classification ===

    // Extract features and run ML inference on the emulation session.
    // Returns std::nullopt if the ML model is not loaded or config disabled.
    [[nodiscard]] std::optional<MLClassificationResult> Classify(
        const BehaviorMonitor& behavior,
        const MemoryTracker& memory,
        const APISequenceAnalyzer& apiSequence,
        std::span<const APICallRecord> apiLog,
        uint64_t totalInstructions,
        uint64_t totalMemoryAllocated) const noexcept;

    // Extract the raw 384-dim feature vector without running inference.
    // Useful for logging, debugging, or feeding to alternative models.
    [[nodiscard]] std::optional<std::vector<float>> ExtractFeatures(
        const BehaviorMonitor& behavior,
        const MemoryTracker& memory,
        const APISequenceAnalyzer& apiSequence,
        std::span<const APICallRecord> apiLog,
        uint64_t totalInstructions,
        uint64_t totalMemoryAllocated) const noexcept;

    // === Status ===
    [[nodiscard]] bool IsModelLoaded() const noexcept;
    [[nodiscard]] bool IsEnabled() const noexcept;

    void Reset() noexcept;

private:
    struct Impl;
    std::unique_ptr<Impl> m_impl;
};

} // namespace Phantom
