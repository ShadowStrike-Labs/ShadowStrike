/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */
#pragma once

#include "Products/Community/PhantomEDR/Compliance/ComplianceTypes.hpp"

#include <memory>
#include <optional>
#include <string_view>
#include <vector>

namespace ShadowStrike::Products::PhantomEDR::Compliance {

class CompliancePoliciesImpl;

class CompliancePolicies final {
public:
    [[nodiscard]] static CompliancePolicies& Instance();
    [[nodiscard]] bool Initialize();
    void Shutdown();
    [[nodiscard]] bool IsInitialized() const noexcept;

    [[nodiscard]] std::vector<ComplianceCheckDef> GetChecksForFramework(ComplianceFramework framework) const;
    [[nodiscard]] std::vector<ComplianceCheckDef> GetAllChecks() const;
    [[nodiscard]] std::optional<ComplianceCheckDef> GetCheck(std::string_view checkId) const;
    [[nodiscard]] uint32_t GetCheckCount(ComplianceFramework framework) const;

    [[nodiscard]] bool AddCustomCheck(const ComplianceCheckDef& check);
    [[nodiscard]] bool RemoveCustomCheck(std::string_view checkId);
    [[nodiscard]] bool SetCheckEnabled(std::string_view checkId, bool enabled);

private:
    CompliancePolicies();
    ~CompliancePolicies();
    CompliancePolicies(const CompliancePolicies&) = delete;
    CompliancePolicies& operator=(const CompliancePolicies&) = delete;
    CompliancePolicies(CompliancePolicies&&) = delete;
    CompliancePolicies& operator=(CompliancePolicies&&) = delete;
    std::unique_ptr<CompliancePoliciesImpl> m_impl;
};

} // namespace ShadowStrike::Products::PhantomEDR::Compliance
