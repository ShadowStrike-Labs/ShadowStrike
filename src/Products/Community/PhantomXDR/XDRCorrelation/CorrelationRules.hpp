/*
 * ShadowStrike - Enterprise NGAV/EDR/XDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * AGPL-3.0 — see LICENSE.txt
 */

#pragma once

/// @file CorrelationRules.hpp
/// @brief Cross-domain correlation rule CRUD, evaluation engine, and
///        default rule installation.

#include "XDRTypes.hpp"
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace ShadowStrike::Products::PhantomXDR::XDRCorrelation {

class CorrelationRulesImpl;

/// Meyers' singleton rule engine.
/// Manages correlation rules, evaluates them against event windows,
/// and produces CorrelationMatch objects.
class CorrelationRules final {
public:
    [[nodiscard]] static CorrelationRules& Instance();
    [[nodiscard]] static bool HasInstance() noexcept;

    [[nodiscard]] bool Initialize();
    void               Shutdown();
    [[nodiscard]] bool IsInitialized() const noexcept;

    // ── CRUD ─────────────────────────────────────────────────────
    [[nodiscard]] bool AddRule(const CorrelationRule& rule);
    [[nodiscard]] bool RemoveRule(std::string_view ruleId);
    [[nodiscard]] bool UpdateRule(const CorrelationRule& rule);

    [[nodiscard]] std::optional<CorrelationRule> GetRule(std::string_view ruleId) const;
    [[nodiscard]] std::vector<CorrelationRule>   GetActiveRules() const;
    [[nodiscard]] std::vector<CorrelationRule>   GetAllRules() const;
    [[nodiscard]] uint32_t                       GetRuleCount() const;

    // ── Evaluation ───────────────────────────────────────────────
    [[nodiscard]] std::vector<CorrelationMatch> Evaluate(
        const std::vector<XDREvent>& windowEvents) const;

    // ── Defaults & Import/Export ─────────────────────────────────
    [[nodiscard]] bool        InstallDefaultRules();
    [[nodiscard]] uint32_t    ImportRulesFromJson(std::string_view json);
    [[nodiscard]] std::string ExportRulesToJson() const;

private:
    CorrelationRules();
    ~CorrelationRules();
    CorrelationRules(const CorrelationRules&) = delete;
    CorrelationRules& operator=(const CorrelationRules&) = delete;

    std::unique_ptr<CorrelationRulesImpl> m_impl;
};

} // namespace ShadowStrike::Products::PhantomXDR::XDRCorrelation
