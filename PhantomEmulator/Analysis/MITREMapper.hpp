/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * MITREMapper.hpp — Maps detected behaviors to MITRE ATT&CK Enterprise techniques
 *
 * Maintains a database of ~90 MITRE ATT&CK techniques across all 11 tactics.
 * As behavioral signals arrive (API calls, behavior flags, memory findings),
 * the mapper identifies which techniques are being employed and records the
 * evidence chain for each. Kill-chain coverage is tracked to assess
 * sophistication — an attack spanning many tactics is more concerning.
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#pragma once

#include "../Common/Types.hpp"
#include "AnalysisTypes.hpp"

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace Phantom {

// ============================================================================
// MITRE Technique Record — one per observed technique
// ============================================================================

struct MITRETechnique {
    const char*              id          = nullptr;
    const char*              name        = nullptr;
    const char*              tactic      = nullptr;
    const char*              description = nullptr;
    float                    confidence  = 0.0f;
    std::vector<std::string> evidence;
};

// ============================================================================
// Tactic-level Summary
// ============================================================================

struct MITRETacticSummary {
    const char* tactic         = nullptr;
    uint32_t    techniqueCount = 0;
    float       maxConfidence  = 0.0f;
};

// ============================================================================
// MITREMapper — maps events to ATT&CK techniques
// ============================================================================

class MITREMapper {
public:
    MITREMapper() noexcept;
    ~MITREMapper() noexcept;

    MITREMapper(const MITREMapper&) = delete;
    MITREMapper& operator=(const MITREMapper&) = delete;

    // === Map Events to Techniques ===
    void OnBehaviorAlert(const BehaviorAlert& alert) noexcept;
    void OnBehaviorFlags(BehaviorFlag flags) noexcept;
    void OnAPICall(const APICallDetail& call) noexcept;
    void OnMemoryFinding(const MemoryFindingDetail& finding) noexcept;
    void OnPackerDetected(PackerType packer) noexcept;
    void OnEvasionAttempt(const std::string& technique) noexcept;

    // === Query Results ===
    [[nodiscard]] const std::vector<MITRETechnique>& GetMappedTechniques() const noexcept;
    [[nodiscard]] uint32_t GetTechniqueCount() const noexcept;
    [[nodiscard]] std::vector<MITRETacticSummary> GetTacticSummary() const noexcept;
    [[nodiscard]] std::vector<const MITRETechnique*> GetByTactic(const char* tactic) const noexcept;
    [[nodiscard]] const MITRETechnique* GetById(const char* id) const noexcept;

    // === Kill Chain Coverage ===
    [[nodiscard]] uint32_t GetKillChainCoverage() const noexcept;

    void Reset() noexcept;

private:
    struct Impl;
    std::unique_ptr<Impl> m_impl;
};

} // namespace Phantom
