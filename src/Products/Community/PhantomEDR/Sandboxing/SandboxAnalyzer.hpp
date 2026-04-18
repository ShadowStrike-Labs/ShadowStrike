/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * AGPL-3.0 — see LICENSE.txt
 */
#pragma once

#include "Products/Community/PhantomEDR/Sandboxing/SandboxTypes.hpp"

#include <memory>
#include <optional>
#include <string_view>
#include <vector>

namespace ShadowStrike::Products::PhantomEDR::Sandboxing {

class SandboxAnalyzerImpl;

/// Parses detonation artifacts: filesystem changes, registry modifications,
/// network IOCs, process trees. Assigns behavior tags, MITRE ATT&CK mappings,
/// threat scores, and a final verdict.
class SandboxAnalyzer final {
public:
    [[nodiscard]] static SandboxAnalyzer& Instance();
    [[nodiscard]] bool Initialize();
    void Shutdown();
    [[nodiscard]] bool IsInitialized() const noexcept;

    /// Analyze raw detonation artifacts and produce a fully-scored DetonationResult.
    [[nodiscard]] DetonationResult Analyze(DetonationResult rawResult) const;

    /// Get cached analysis result by submission ID.
    [[nodiscard]] std::optional<DetonationResult> GetAnalysis(std::string_view submissionId) const;

    /// Get all analyses matching a sha256.
    [[nodiscard]] std::vector<DetonationResult> GetAnalysesByHash(std::string_view sha256) const;

    /// Get recent analyses (most recent first).
    [[nodiscard]] std::vector<DetonationResult> GetRecentAnalyses(uint32_t maxResults = 50) const;

private:
    SandboxAnalyzer();
    ~SandboxAnalyzer();
    SandboxAnalyzer(const SandboxAnalyzer&) = delete;
    SandboxAnalyzer& operator=(const SandboxAnalyzer&) = delete;
    SandboxAnalyzer(SandboxAnalyzer&&) = delete;
    SandboxAnalyzer& operator=(SandboxAnalyzer&&) = delete;
    std::unique_ptr<SandboxAnalyzerImpl> m_impl;
};

} // namespace ShadowStrike::Products::PhantomEDR::Sandboxing
