/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * AGPL-3.0 — see LICENSE.txt
 */
#pragma once

#include "Products/Community/PhantomEDR/PolicyEngine/PolicyTypes.hpp"

#include <memory>
#include <optional>
#include <string_view>
#include <vector>

namespace ShadowStrike::Products::PhantomEDR::PolicyEngine {

class PolicyManagerImpl;

/// Local policy management — CRUD for policy definitions and rules.
/// Persists to SQLite. Community edition: single-endpoint, local only.
class PolicyManager final {
public:
    [[nodiscard]] static PolicyManager& Instance();
    [[nodiscard]] bool Initialize();
    void Shutdown();
    [[nodiscard]] bool IsInitialized() const noexcept;

    [[nodiscard]] std::string CreatePolicy(const PolicyDefinition& policy);
    [[nodiscard]] bool UpdatePolicy(const PolicyDefinition& policy);
    [[nodiscard]] bool DeletePolicy(std::string_view policyId);
    [[nodiscard]] bool SetPolicyStatus(std::string_view policyId, PolicyStatus status);

    [[nodiscard]] std::optional<PolicyDefinition> GetPolicy(std::string_view policyId) const;
    [[nodiscard]] std::vector<PolicyDefinition> QueryPolicies(const PolicyQueryParams& params) const;
    [[nodiscard]] uint32_t GetActivePolicyCount() const;

    [[nodiscard]] bool AddRule(std::string_view policyId, const PolicyRule& rule);
    [[nodiscard]] bool RemoveRule(std::string_view policyId, std::string_view ruleId);

private:
    PolicyManager();
    ~PolicyManager();
    PolicyManager(const PolicyManager&) = delete;
    PolicyManager& operator=(const PolicyManager&) = delete;
    PolicyManager(PolicyManager&&) = delete;
    PolicyManager& operator=(PolicyManager&&) = delete;
    std::unique_ptr<PolicyManagerImpl> m_impl;
};

} // namespace ShadowStrike::Products::PhantomEDR::PolicyEngine
