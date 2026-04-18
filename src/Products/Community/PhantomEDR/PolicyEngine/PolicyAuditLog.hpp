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

class PolicyAuditLogImpl;

/// Immutable audit log for all policy-related actions.
/// Records who-changed-what-when for compliance and forensics.
class PolicyAuditLog final {
public:
    [[nodiscard]] static PolicyAuditLog& Instance();
    [[nodiscard]] bool Initialize();
    void Shutdown();
    [[nodiscard]] bool IsInitialized() const noexcept;

    /// Record an audit entry.
    void Record(AuditAction action, std::string_view policyId,
                std::string_view actor, std::string_view details);

    /// Query audit entries.
    [[nodiscard]] std::vector<AuditEntry> Query(const AuditQueryParams& params) const;

    /// Get total entry count.
    [[nodiscard]] uint64_t GetEntryCount() const;

private:
    PolicyAuditLog();
    ~PolicyAuditLog();
    PolicyAuditLog(const PolicyAuditLog&) = delete;
    PolicyAuditLog& operator=(const PolicyAuditLog&) = delete;
    PolicyAuditLog(PolicyAuditLog&&) = delete;
    PolicyAuditLog& operator=(PolicyAuditLog&&) = delete;
    std::unique_ptr<PolicyAuditLogImpl> m_impl;
};

} // namespace ShadowStrike::Products::PhantomEDR::PolicyEngine
