/*
 * ShadowStrike - Enterprise NGAV/EDR/XDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * AGPL-3.0 — see LICENSE.txt
 */

#pragma once

/// @file SOARTypes.hpp
/// @brief Shared types for the local SOAR subsystem.

#include <chrono>
#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace ShadowStrike::Products::PhantomXDR::SOARLocal {

using TimePoint = std::chrono::system_clock::time_point;

enum class PlaybookStatus : uint8_t {
    Disabled = 0,
    Active   = 1,
    Testing  = 2,
};

enum class ActionType : uint8_t {
    IsolateEndpoint = 0,
    BlockIP         = 1,
    BlockDomain     = 2,
    KillProcess     = 3,
    QuarantineFile  = 4,
    BlockSender     = 5,
    DisableAccount  = 6,
    AlertSOC        = 7,
    LogEvent        = 8,
    RunScript       = 9,
};

enum class TriggerType : uint8_t {
    CorrelationMatch = 0,
    SeverityThreshold = 1,
    ManualTrigger     = 2,
    ScheduledScan     = 3,
};

enum class ActionResult : uint8_t {
    Success = 0,
    Failed  = 1,
    Skipped = 2,
    TimedOut = 3,
    Pending  = 4,
};

struct SOARAction {
    std::string                             actionId;
    ActionType                              type;
    std::string                             target;
    std::map<std::string, std::string>      parameters;
    ActionResult                            result{ActionResult::Pending};
    std::string                             resultDetail;
    TimePoint                               executedAt{};
};

struct PlaybookTrigger {
    TriggerType type;
    std::string sourceRuleId;
    uint8_t     minSeverity{0};
    std::string domainFilter;
};

struct Playbook {
    std::string             playbookId;
    std::string             name;
    std::string             description;
    PlaybookStatus          status{PlaybookStatus::Active};
    PlaybookTrigger         trigger;
    std::vector<SOARAction> actions;
    TimePoint               createdAt{};
    TimePoint               updatedAt{};
};

struct PlaybookExecution {
    std::string             executionId;
    std::string             playbookId;
    std::string             triggerId;
    TimePoint               startTime{};
    TimePoint               endTime{};
    std::vector<SOARAction> actionResults;
    bool                    success{false};
    std::string             summary;
};

} // namespace ShadowStrike::Products::PhantomXDR::SOARLocal
