/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * ThreatScorer.hpp — Aggregated threat scoring and malware classification
 *
 * Consumes all behavioral signals, API sequence matches, memory findings,
 * and MITRE ATT&CK mappings to produce a final threat verdict:
 * Clean / Suspicious / Likely / Malicious / Critical.
 *
 * Maintains per-category scores (Trojan, Ransomware, RAT, …) so that the
 * primary and secondary malware classifications are data-driven rather than
 * heuristic guesses.
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#pragma once

#include "../Common/Types.hpp"
#include "../Common/Config.hpp"
#include "AnalysisTypes.hpp"

#include <cstdint>
#include <memory>
#include <string>
#include <utility>
#include <vector>

namespace Phantom {

// ============================================================================
// Malware Category Classification
// ============================================================================

enum class MalwareCategory : uint8_t {
    Unknown = 0,
    Trojan,
    Ransomware,
    Worm,
    Backdoor,
    RAT,
    Dropper,
    Downloader,
    Rootkit,
    Keylogger,
    Spyware,
    Adware,
    CoinMiner,
    Wiper,
    BankingTrojan,
    InfoStealer,
    Botnet,
    Exploit,
    APTImplant,
    Fileless,
    Count_,
};

// ============================================================================
// Threat Verdict — the final output of the scoring pipeline
// ============================================================================

struct ThreatVerdict {
    ThreatLevel      level              = ThreatLevel::Clean;
    float            score              = 0.0f;
    float            confidence         = 0.0f;
    MalwareCategory  primaryCategory    = MalwareCategory::Unknown;
    MalwareCategory  secondaryCategory  = MalwareCategory::Unknown;
    std::string      summary;
    std::vector<std::string> reasons;
};

// ============================================================================
// Individual Scoring Factor
// ============================================================================

struct ScoringFactor {
    std::string source;
    std::string description;
    float       weight      = 0.0f;
    float       score       = 0.0f;
    float       confidence  = 0.0f;
};

// ============================================================================
// ThreatScorer — aggregates all signals into a verdict
// ============================================================================

class ThreatScorer {
public:
    explicit ThreatScorer(const EmulationConfig& config) noexcept;
    ~ThreatScorer() noexcept;

    ThreatScorer(const ThreatScorer&) = delete;
    ThreatScorer& operator=(const ThreatScorer&) = delete;

    // === Add Scoring Factors ===
    void AddBehaviorAlert(const BehaviorAlert& alert) noexcept;
    void AddSequenceMatch(const SequenceMatch& match) noexcept;
    void AddMemoryFinding(const MemoryFindingDetail& finding) noexcept;
    void AddBehaviorFlags(BehaviorFlag flags) noexcept;
    void AddMITRETechnique(const char* techniqueId, float confidence) noexcept;
    void AddPackerDetection(PackerType packer) noexcept;
    void AddEvasionAttempt(const std::string& technique, float severity) noexcept;
    void AddCustomFactor(const ScoringFactor& factor) noexcept;

    // === Verdict Generation ===
    [[nodiscard]] ThreatVerdict GenerateVerdict() const noexcept;

    // === Score Breakdown ===
    [[nodiscard]] const std::vector<ScoringFactor>& GetFactors() const noexcept;
    [[nodiscard]] float GetRawScore() const noexcept;
    [[nodiscard]] float GetNormalizedScore() const noexcept;

    // === Category Classification ===
    [[nodiscard]] MalwareCategory ClassifyMalware() const noexcept;
    [[nodiscard]] std::vector<std::pair<MalwareCategory, float>> GetCategoryScores() const noexcept;

    void Reset() noexcept;

private:
    struct Impl;
    std::unique_ptr<Impl> m_impl;
};

} // namespace Phantom
