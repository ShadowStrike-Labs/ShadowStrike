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
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "Products/Community/PhantomEDR/IncidentResponse/IncidentTypes.hpp"

namespace ShadowStrike::Products::PhantomEDR::IncidentResponse {

class IncidentManagerImpl;

class IncidentManager final {
public:
    [[nodiscard]] static IncidentManager& Instance();

    [[nodiscard]] bool Initialize();
    void Shutdown();
    [[nodiscard]] bool IsInitialized() const;

    [[nodiscard]] std::string CreateIncident(const Incident& incident);
    [[nodiscard]] bool UpdateIncident(const Incident& incident);
    [[nodiscard]] std::optional<Incident> GetIncident(std::string_view incidentId) const;
    [[nodiscard]] std::vector<Incident> QueryIncidents(const IncidentQueryParams& params) const;
    [[nodiscard]] bool TransitionStatus(std::string_view incidentId, IncidentStatus newStatus);
    [[nodiscard]] bool AddNote(std::string_view incidentId, std::string_view note);
    [[nodiscard]] bool AssignIncident(std::string_view incidentId, std::string_view assignee);
    [[nodiscard]] bool MergeIncidents(std::string_view primaryId, std::string_view secondaryId);
    [[nodiscard]] uint64_t GetOpenIncidentCount() const;
    [[nodiscard]] std::vector<Incident> GetRecentIncidents(size_t count) const;

private:
    IncidentManager();
    ~IncidentManager();

    IncidentManager(const IncidentManager&) = delete;
    IncidentManager& operator=(const IncidentManager&) = delete;
    IncidentManager(IncidentManager&&) = delete;
    IncidentManager& operator=(IncidentManager&&) = delete;

    std::unique_ptr<IncidentManagerImpl> m_impl;
};

} // namespace ShadowStrike::Products::PhantomEDR::IncidentResponse
