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

class ComplianceEngineImpl;

class ComplianceEngine final {
public:
    [[nodiscard]] static ComplianceEngine& Instance();
    [[nodiscard]] bool Initialize();
    void Shutdown();
    [[nodiscard]] bool IsInitialized() const noexcept;

    [[nodiscard]] ComplianceScanResult RunScan(ComplianceFramework framework);
    [[nodiscard]] ComplianceScanResult RunAllFrameworks();
    [[nodiscard]] ComplianceCheckResult EvaluateCheck(const ComplianceCheckDef& check);

    [[nodiscard]] std::vector<ComplianceScanResult> GetScanHistory(
        ComplianceFramework framework, uint32_t maxResults = 50) const;
    [[nodiscard]] std::optional<ComplianceScanResult> GetLatestScan(
        ComplianceFramework framework) const;

private:
    ComplianceEngine();
    ~ComplianceEngine();
    ComplianceEngine(const ComplianceEngine&) = delete;
    ComplianceEngine& operator=(const ComplianceEngine&) = delete;
    ComplianceEngine(ComplianceEngine&&) = delete;
    ComplianceEngine& operator=(ComplianceEngine&&) = delete;
    std::unique_ptr<ComplianceEngineImpl> m_impl;
};

} // namespace ShadowStrike::Products::PhantomEDR::Compliance
