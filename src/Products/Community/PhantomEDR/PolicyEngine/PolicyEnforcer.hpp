/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * AGPL-3.0 — see LICENSE.txt
 */
#pragma once

#include "Products/Community/PhantomEDR/PolicyEngine/PolicyTypes.hpp"

#include <memory>
#include <string_view>
#include <vector>

namespace ShadowStrike::Products::PhantomEDR::PolicyEngine {

class PolicyEnforcerImpl;

/// Continuous drift detection and auto-remediation engine.
/// Periodically checks active policy rules against system state.
/// Can operate in Audit (log only) or Enforce (auto-remediate) mode.
class PolicyEnforcer final {
public:
    [[nodiscard]] static PolicyEnforcer& Instance();
    [[nodiscard]] bool Initialize();
    void Shutdown();
    [[nodiscard]] bool IsInitialized() const noexcept;

    /// Run a one-shot compliance check against all active policies.
    [[nodiscard]] std::vector<DriftRecord> CheckCompliance() const;

    /// Run compliance check for a specific policy.
    [[nodiscard]] std::vector<DriftRecord> CheckPolicy(std::string_view policyId) const;

    /// Attempt to remediate a specific drift.
    [[nodiscard]] bool Remediate(std::string_view driftId);

    /// Get all detected drifts.
    [[nodiscard]] std::vector<DriftRecord> QueryDrifts(const DriftQueryParams& params) const;

    /// Start background enforcement loop.
    void Start();
    /// Stop background enforcement loop.
    void Stop();

private:
    PolicyEnforcer();
    ~PolicyEnforcer();
    PolicyEnforcer(const PolicyEnforcer&) = delete;
    PolicyEnforcer& operator=(const PolicyEnforcer&) = delete;
    PolicyEnforcer(PolicyEnforcer&&) = delete;
    PolicyEnforcer& operator=(PolicyEnforcer&&) = delete;
    std::unique_ptr<PolicyEnforcerImpl> m_impl;
};

} // namespace ShadowStrike::Products::PhantomEDR::PolicyEngine
