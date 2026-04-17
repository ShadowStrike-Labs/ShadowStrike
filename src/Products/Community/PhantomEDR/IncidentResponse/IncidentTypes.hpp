/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */
/**
 * @file IncidentTypes.hpp
 * @brief Shared types for the IncidentResponse subsystem.
 */
#pragma once

#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "PhantomCore/Communication/AlertSystem.hpp"

namespace ShadowStrike::Products::PhantomEDR::IncidentResponse {

// ============================================================================
// SEVERITY
// ============================================================================

enum class IncidentSeverity : uint8_t {
    Unknown  = 0,
    Info     = 1,
    Low      = 2,
    Medium   = 3,
    High     = 4,
    Critical = 5
};

// ============================================================================
// STATUS  (lifecycle states)
// ============================================================================

enum class IncidentStatus : uint8_t {
    New           = 0,
    Triaged       = 1,
    Investigating = 2,
    Containing    = 3,
    Remediating   = 4,
    Closed        = 5,
    FalsePositive = 6
};

// ============================================================================
// PHASE  (maps 1-to-1 with status - convenience for UI grouping)
// ============================================================================

enum class IncidentPhase : uint8_t {
    New           = 0,
    Triaged       = 1,
    Investigating = 2,
    Containing    = 3,
    Remediating   = 4,
    Closed        = 5,
    FalsePositive = 6
};

// ============================================================================
// ACTION ENUMS  (defined before Incident so vectors can reference them)
// ============================================================================

enum class ContainmentAction : uint8_t {
    IsolateNetwork = 0,
    TerminateProcess,
    LockAccount,
    QuarantineFile,
    BlockIP,
    DisableService
};

enum class RemediationAction : uint8_t {
    QuarantineFile = 0,
    DeleteFile,
    RollbackRegistry,
    RemoveService,
    RemoveScheduledTask,
    RestoreBackup
};

// ============================================================================
// INCIDENT RECORD
// ============================================================================

struct Incident {
    std::string                                   incidentId;
    std::string                                   title;
    std::string                                   description;
    IncidentSeverity                              severity  = IncidentSeverity::Unknown;
    IncidentStatus                                status    = IncidentStatus::New;
    IncidentPhase                                 phase     = IncidentPhase::New;
    std::string                                   assignee;
    std::chrono::system_clock::time_point         createdAt{};
    std::chrono::system_clock::time_point         updatedAt{};
    std::optional<std::chrono::system_clock::time_point> closedAt;
    double                                        score = 0.0;
    std::vector<uint32_t>                         affectedProcessIds;
    std::vector<std::wstring>                     affectedFiles;
    std::vector<std::string>                      relatedAlertIds;
    std::vector<uint64_t>                         relatedEventIds;
    std::vector<std::string>                      mitreAttackIds;
    std::vector<ContainmentAction>                containmentActions;
    std::vector<RemediationAction>                remediationActions;
    std::vector<std::pair<std::chrono::system_clock::time_point, std::string>> notes;
};

// ============================================================================
// QUERY PARAMETERS
// ============================================================================

struct IncidentQueryParams {
    std::optional<IncidentStatus>                          status;
    std::optional<IncidentSeverity>                        minSeverity;
    std::optional<std::chrono::system_clock::time_point>   startTime;
    std::optional<std::chrono::system_clock::time_point>   endTime;
    uint32_t maxResults = 100;
    uint32_t offset     = 0;
};

// ============================================================================
// CORRELATION RULE
// ============================================================================

struct CorrelationRule {
    std::string                                      ruleId;
    std::string                                      name;
    std::string                                      description;
    uint32_t                                         timeWindowSeconds = 300;
    uint32_t                                         minAlertCount     = 3;
    std::vector<ShadowStrike::Communication::AlertType> requiredAlertTypes;
    IncidentSeverity                                 minSeverity = IncidentSeverity::Medium;
    bool                                             enabled = true;
};

// ============================================================================
// STRING CONVERTERS
// ============================================================================

[[nodiscard]] constexpr std::string_view ToString(ContainmentAction action) noexcept {
    switch (action) {
        case ContainmentAction::IsolateNetwork:   return "IsolateNetwork";
        case ContainmentAction::TerminateProcess: return "TerminateProcess";
        case ContainmentAction::LockAccount:      return "LockAccount";
        case ContainmentAction::QuarantineFile:   return "QuarantineFile";
        case ContainmentAction::BlockIP:          return "BlockIP";
        case ContainmentAction::DisableService:   return "DisableService";
    }
    return "Unknown";
}

[[nodiscard]] constexpr std::string_view ToString(RemediationAction action) noexcept {
    switch (action) {
        case RemediationAction::QuarantineFile:      return "QuarantineFile";
        case RemediationAction::DeleteFile:          return "DeleteFile";
        case RemediationAction::RollbackRegistry:    return "RollbackRegistry";
        case RemediationAction::RemoveService:       return "RemoveService";
        case RemediationAction::RemoveScheduledTask: return "RemoveScheduledTask";
        case RemediationAction::RestoreBackup:       return "RestoreBackup";
    }
    return "Unknown";
}

} // namespace ShadowStrike::Products::PhantomEDR::IncidentResponse
