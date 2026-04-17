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
#include <string>
#include <string_view>

namespace ShadowStrike::Products::PhantomEDR::Compliance {

class ComplianceReporterImpl;

class ComplianceReporter final {
public:
    [[nodiscard]] static ComplianceReporter& Instance();
    [[nodiscard]] bool Initialize();
    void Shutdown();
    [[nodiscard]] bool IsInitialized() const noexcept;

    [[nodiscard]] std::string GenerateJsonReport(const ComplianceScanResult& scan) const;
    [[nodiscard]] std::string GenerateHtmlReport(const ComplianceScanResult& scan) const;
    [[nodiscard]] bool ExportJsonToFile(const ComplianceScanResult& scan, std::string_view filePath) const;
    [[nodiscard]] bool ExportHtmlToFile(const ComplianceScanResult& scan, std::string_view filePath) const;

private:
    ComplianceReporter();
    ~ComplianceReporter();
    ComplianceReporter(const ComplianceReporter&) = delete;
    ComplianceReporter& operator=(const ComplianceReporter&) = delete;
    ComplianceReporter(ComplianceReporter&&) = delete;
    ComplianceReporter& operator=(ComplianceReporter&&) = delete;
    std::unique_ptr<ComplianceReporterImpl> m_impl;
};

} // namespace ShadowStrike::Products::PhantomEDR::Compliance
