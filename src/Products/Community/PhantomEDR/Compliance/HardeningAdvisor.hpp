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
#include <string_view>
#include <vector>

namespace ShadowStrike::Products::PhantomEDR::Compliance {

class HardeningAdvisorImpl;

class HardeningAdvisor final {
public:
    [[nodiscard]] static HardeningAdvisor& Instance();
    [[nodiscard]] bool Initialize();
    void Shutdown();
    [[nodiscard]] bool IsInitialized() const noexcept;

    [[nodiscard]] std::vector<HardeningRecommendation> Analyze(const ComplianceScanResult& scan) const;
    [[nodiscard]] std::vector<HardeningRecommendation> GetAutoFixable(const ComplianceScanResult& scan) const;

    [[nodiscard]] bool ApplyFix(const HardeningRecommendation& rec);
    [[nodiscard]] bool DryRunFix(const HardeningRecommendation& rec, std::string& description) const;
    [[nodiscard]] uint32_t ApplyAllAutoFixes(const std::vector<HardeningRecommendation>& recs);

private:
    HardeningAdvisor();
    ~HardeningAdvisor();
    HardeningAdvisor(const HardeningAdvisor&) = delete;
    HardeningAdvisor& operator=(const HardeningAdvisor&) = delete;
    HardeningAdvisor(HardeningAdvisor&&) = delete;
    HardeningAdvisor& operator=(HardeningAdvisor&&) = delete;
    std::unique_ptr<HardeningAdvisorImpl> m_impl;
};

} // namespace ShadowStrike::Products::PhantomEDR::Compliance
