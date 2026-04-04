/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * APISequenceAnalyzer.hpp — API call sequence analysis for malware pattern detection
 *
 * Performs deep analysis of emulated API call sequences using multiple detection
 * techniques: N-gram pattern matching (2-gram through 8-gram) against a library
 * of ~200 known malicious API sequences, Markov chain transition probability
 * analysis, temporal burst detection, cross-thread API correlation, and sliding
 * window analysis across multiple window sizes.
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#pragma once

#include "../WinAPI/APITypes.hpp"
#include "../Common/Config.hpp"

#include <cstdint>
#include <memory>
#include <utility>
#include <vector>

namespace Phantom {

// Compact API identifier for fast sequence comparison
using APIId = uint16_t;
static constexpr APIId kInvalidAPIId = 0xFFFF;

// ============================================================================
// Match result from N-gram sequence analysis
// ============================================================================

struct SequenceMatch {
    uint16_t    patternId;          // Which pattern matched
    const char* patternName;        // Human-readable name (static storage)
    const char* mitreId;            // MITRE ATT&CK technique ID (static storage)
    float       confidence;         // 0.0–1.0 match confidence
    uint8_t     severity;           // 0-4 (maps to ThreatLevel)
    uint32_t    startCallIndex;     // Index of first call in the match
    uint32_t    endCallIndex;       // Index of last call in the match
    uint16_t    threadId;           // Thread where the match was detected
};

// ============================================================================
// Anomaly detected by Markov chain transition model
// ============================================================================

struct TransitionAnomaly {
    APIId       fromAPI;            // Source API in the transition
    APIId       toAPI;              // Target API in the transition
    double      probability;        // Observed transition probability
    double      threshold;          // Anomaly threshold that was exceeded
    uint32_t    callIndex;          // Call index where the anomaly occurred
};

// ============================================================================
// APISequenceAnalyzer — Main analysis class (PIMPL)
// ============================================================================

class APISequenceAnalyzer {
public:
    explicit APISequenceAnalyzer(const EmulationConfig& config) noexcept;
    ~APISequenceAnalyzer() noexcept;

    APISequenceAnalyzer(const APISequenceAnalyzer&) = delete;
    APISequenceAnalyzer& operator=(const APISequenceAnalyzer&) = delete;
    APISequenceAnalyzer(APISequenceAnalyzer&&) noexcept;
    APISequenceAnalyzer& operator=(APISequenceAnalyzer&&) noexcept;

    // Feed an API call into the analyzer (called for every emulated API)
    void OnAPICall(const APICallDetail& call, uint32_t callIndex) noexcept;

    // Get all sequence matches found so far
    [[nodiscard]] const std::vector<SequenceMatch>& GetMatches() const noexcept;

    // Get all Markov chain transition anomalies
    [[nodiscard]] const std::vector<TransitionAnomaly>& GetAnomalies() const noexcept;

    // Get the highest severity across all matches
    [[nodiscard]] uint8_t GetMaxSeverity() const noexcept;

    // Get total match count
    [[nodiscard]] uint32_t GetMatchCount() const noexcept;

    // Get the API call frequency distribution, sorted descending by count
    [[nodiscard]] std::vector<std::pair<APIId, uint32_t>> GetAPIFrequency() const noexcept;

    // Get the top N most suspicious API transitions (lowest probability)
    [[nodiscard]] std::vector<TransitionAnomaly> GetTopAnomalies(uint32_t n) const noexcept;

    // Reset all analysis state for reuse
    void Reset() noexcept;

private:
    struct Impl;
    std::unique_ptr<Impl> m_impl;
};

} // namespace Phantom
