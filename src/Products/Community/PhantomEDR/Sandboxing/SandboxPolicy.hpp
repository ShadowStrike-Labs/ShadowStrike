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

class SandboxPolicyImpl;

/// Policy engine controlling automatic sandbox submission.
/// Evaluates file metadata against configurable rules to decide
/// whether a file should be auto-submitted for detonation.
class SandboxPolicy final {
public:
    [[nodiscard]] static SandboxPolicy& Instance();
    [[nodiscard]] bool Initialize();
    void Shutdown();
    [[nodiscard]] bool IsInitialized() const noexcept;

    /// Evaluate whether a file should be submitted based on current rules.
    [[nodiscard]] bool ShouldSubmit(std::string_view filePath, std::string_view sha256,
                                    uint64_t fileSize, uint32_t detectionConfidence,
                                    int32_t reputationScore) const;

    /// Get the rule that matched (if any) for the last ShouldSubmit call on this thread.
    [[nodiscard]] std::optional<SubmitRule> GetLastMatchedRule() const;

    /// Rule management
    [[nodiscard]] bool AddRule(const SubmitRule& rule);
    [[nodiscard]] bool RemoveRule(std::string_view ruleId);
    [[nodiscard]] bool SetRuleEnabled(std::string_view ruleId, bool enabled);
    [[nodiscard]] std::optional<SubmitRule> GetRule(std::string_view ruleId) const;
    [[nodiscard]] std::vector<SubmitRule> GetAllRules() const;
    [[nodiscard]] uint32_t GetRuleCount() const;

private:
    SandboxPolicy();
    ~SandboxPolicy();
    SandboxPolicy(const SandboxPolicy&) = delete;
    SandboxPolicy& operator=(const SandboxPolicy&) = delete;
    SandboxPolicy(SandboxPolicy&&) = delete;
    SandboxPolicy& operator=(SandboxPolicy&&) = delete;
    std::unique_ptr<SandboxPolicyImpl> m_impl;
};

} // namespace ShadowStrike::Products::PhantomEDR::Sandboxing
