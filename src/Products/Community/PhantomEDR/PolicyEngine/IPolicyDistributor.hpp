/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * AGPL-3.0 — see LICENSE.txt
 */
#pragma once

#include "Products/Community/PhantomEDR/PolicyEngine/PolicyTypes.hpp"

#include <string_view>
#include <vector>

namespace ShadowStrike::Products::PhantomEDR::PolicyEngine {

/// Interface for policy distribution backends.
/// Community: local file-based (PolicyManager handles it directly).
/// Pro/Enterprise: cloud push via fleet management server.
class IPolicyDistributor {
public:
    virtual ~IPolicyDistributor() = default;

    /// Push a policy to target endpoints. Returns number of endpoints reached.
    [[nodiscard]] virtual uint32_t DistributePolicy(const PolicyDefinition& policy) = 0;

    /// Revoke a policy from all endpoints.
    [[nodiscard]] virtual bool RevokePolicy(std::string_view policyId) = 0;

    /// Query which endpoints have acknowledged a given policy version.
    [[nodiscard]] virtual uint32_t GetAcknowledgmentCount(std::string_view policyId,
                                                          uint32_t version) const = 0;

    /// Backend name for logging.
    [[nodiscard]] virtual std::string_view BackendName() const noexcept = 0;
};

} // namespace ShadowStrike::Products::PhantomEDR::PolicyEngine
