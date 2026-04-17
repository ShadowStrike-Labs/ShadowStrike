/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */
#pragma once

#include <memory>
#include <string_view>
#include <vector>

#include "Products/Community/PhantomEDR/IncidentResponse/IncidentTypes.hpp"
#include "PhantomCore/Communication/AlertSystem.hpp"
#include "Products/Community/PhantomEDR/Telemetry/TelemetryTypes.hpp"

namespace ShadowStrike::Products::PhantomEDR::IncidentResponse {

class AlertCorrelatorImpl;

class AlertCorrelator final {
public:
    [[nodiscard]] static AlertCorrelator& Instance();

    [[nodiscard]] bool Initialize();
    void Shutdown();
    [[nodiscard]] bool IsInitialized() const;

    void IngestAlert(const ShadowStrike::Communication::Alert& alert);
    void IngestTelemetryEvent(const ShadowStrike::Products::PhantomEDR::Telemetry::TelemetryEvent& event);

    [[nodiscard]] bool AddCorrelationRule(const CorrelationRule& rule);
    [[nodiscard]] bool RemoveCorrelationRule(std::string_view ruleId);
    [[nodiscard]] std::vector<CorrelationRule> GetCorrelationRules() const;

    void FlushPendingCorrelations();

    [[nodiscard]] uint64_t GetTotalAlertsProcessed() const;
    [[nodiscard]] uint64_t GetTotalIncidentsCreated() const;

private:
    AlertCorrelator();
    ~AlertCorrelator();

    AlertCorrelator(const AlertCorrelator&) = delete;
    AlertCorrelator& operator=(const AlertCorrelator&) = delete;
    AlertCorrelator(AlertCorrelator&&) = delete;
    AlertCorrelator& operator=(AlertCorrelator&&) = delete;

    std::unique_ptr<AlertCorrelatorImpl> m_impl;
};

} // namespace ShadowStrike::Products::PhantomEDR::IncidentResponse
