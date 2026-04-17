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

#include <chrono>
#include <cctype>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include <nlohmann/json.hpp>

namespace ShadowStrike::Products::PhantomEDR::Playbooks {

using Json = nlohmann::json;

enum class PlaybookStepType : uint8_t {
    Action = 0,
    Condition = 1,
    Sequence = 2,
    Parallel = 3,
    Loop = 4,
    Delay = 5
};

enum class PlaybookActionType : uint8_t {
    IsolateEndpoint = 0,
    KillProcess = 1,
    QuarantineFile = 2,
    BlockIP = 3,
    DisableUser = 4,
    CollectEvidence = 5,
    EnrichIOC = 6,
    NotifyLocal = 7
};

enum class PlaybookRunStatus : uint8_t {
    Pending = 0,
    Running = 1,
    Success = 2,
    Failed = 3,
    Cancelled = 4,
    TimedOut = 5,
    PartialSuccess = 6
};

enum class PlaybookTriggerType : uint8_t {
    Alert = 0,
    Schedule = 1,
    Manual = 2,
    OnDemand = 3
};

enum class PlaybookComparisonOperator : uint8_t {
    Exists = 0,
    Equals = 1,
    NotEquals = 2,
    GreaterThan = 3,
    GreaterThanOrEqual = 4,
    LessThan = 5,
    LessThanOrEqual = 6,
    Contains = 7,
    In = 8
};

enum class PlaybookFailureMode : uint8_t {
    Stop = 0,
    Continue = 1
};

struct PlaybookCondition {
    std::string path;
    PlaybookComparisonOperator op = PlaybookComparisonOperator::Exists;
    Json value;
    bool negate = false;
};

struct PlaybookStep {
    std::string id;
    std::string name;
    PlaybookStepType type = PlaybookStepType::Sequence;
    PlaybookActionType action = PlaybookActionType::NotifyLocal;
    PlaybookCondition condition;
    std::vector<PlaybookStep> steps;
    std::vector<PlaybookStep> elseSteps;
    Json parameters = Json::object();
    std::string itemsPath;
    std::string iteratorName;
    uint32_t repeatCount = 0;
    uint64_t delayMs = 0;
    std::string storeResultAs;
    PlaybookFailureMode onFailure = PlaybookFailureMode::Stop;
    uint32_t timeoutMs = 0;
    bool enabled = true;
};

struct PlaybookDefinition {
    std::string id;
    std::string name;
    std::string description;
    std::string version;
    bool enabled = true;
    uint32_t defaultTimeoutMs = 300000;
    Json defaultContext = Json::object();
    std::vector<PlaybookStep> steps;
};

struct ActionResult {
    PlaybookActionType action = PlaybookActionType::NotifyLocal;
    bool success = false;
    std::string message;
    Json details = Json::object();
    uint64_t durationMs = 0;
};

struct StepExecutionResult {
    std::string runId;
    std::string stepId;
    PlaybookStepType type = PlaybookStepType::Action;
    PlaybookRunStatus status = PlaybookRunStatus::Pending;
    bool success = false;
    size_t stepIndex = 0;
    std::chrono::system_clock::time_point startedAt{};
    std::chrono::system_clock::time_point completedAt{};
    std::string message;
    Json output = Json::object();
};

struct PlaybookRunRecord {
    std::string runId;
    std::string playbookId;
    PlaybookTriggerType triggerType = PlaybookTriggerType::OnDemand;
    std::string triggerReference;
    PlaybookRunStatus status = PlaybookRunStatus::Pending;
    std::chrono::system_clock::time_point startedAt{};
    std::optional<std::chrono::system_clock::time_point> completedAt;
    Json inputContext = Json::object();
    Json outputContext = Json::object();
    std::string errorMessage;
    std::vector<StepExecutionResult> stepResults;
};

struct PlaybookJobRecord {
    std::string jobId;
    std::string playbookId;
    PlaybookTriggerType triggerType = PlaybookTriggerType::Manual;
    std::string scheduleExpression;
    Json alertFilter = Json::object();
    Json manualContext = Json::object();
    bool enabled = true;
    std::chrono::system_clock::time_point nextRunAt{};
    std::optional<std::chrono::system_clock::time_point> lastRunAt;
    std::chrono::system_clock::time_point createdAt{};
    std::chrono::system_clock::time_point updatedAt{};
    PlaybookRunStatus lastStatus = PlaybookRunStatus::Pending;
    std::string lastError;
};

[[nodiscard]] constexpr std::string_view ToString(const PlaybookStepType value) noexcept {
    switch (value) {
        case PlaybookStepType::Action: return "action";
        case PlaybookStepType::Condition: return "condition";
        case PlaybookStepType::Sequence: return "sequence";
        case PlaybookStepType::Parallel: return "parallel";
        case PlaybookStepType::Loop: return "loop";
        case PlaybookStepType::Delay: return "delay";
    }

    return "action";
}

[[nodiscard]] constexpr std::string_view ToString(const PlaybookActionType value) noexcept {
    switch (value) {
        case PlaybookActionType::IsolateEndpoint: return "isolate_endpoint";
        case PlaybookActionType::KillProcess: return "kill_process";
        case PlaybookActionType::QuarantineFile: return "quarantine_file";
        case PlaybookActionType::BlockIP: return "block_ip";
        case PlaybookActionType::DisableUser: return "disable_user";
        case PlaybookActionType::CollectEvidence: return "collect_evidence";
        case PlaybookActionType::EnrichIOC: return "enrich_ioc";
        case PlaybookActionType::NotifyLocal: return "notify_local";
    }

    return "notify_local";
}

[[nodiscard]] constexpr std::string_view ToString(const PlaybookRunStatus value) noexcept {
    switch (value) {
        case PlaybookRunStatus::Pending: return "pending";
        case PlaybookRunStatus::Running: return "running";
        case PlaybookRunStatus::Success: return "success";
        case PlaybookRunStatus::Failed: return "failed";
        case PlaybookRunStatus::Cancelled: return "cancelled";
        case PlaybookRunStatus::TimedOut: return "timed_out";
        case PlaybookRunStatus::PartialSuccess: return "partial_success";
    }

    return "pending";
}

[[nodiscard]] constexpr std::string_view ToString(const PlaybookTriggerType value) noexcept {
    switch (value) {
        case PlaybookTriggerType::Alert: return "alert";
        case PlaybookTriggerType::Schedule: return "schedule";
        case PlaybookTriggerType::Manual: return "manual";
        case PlaybookTriggerType::OnDemand: return "on_demand";
    }

    return "on_demand";
}

[[nodiscard]] constexpr std::string_view ToString(const PlaybookComparisonOperator value) noexcept {
    switch (value) {
        case PlaybookComparisonOperator::Exists: return "exists";
        case PlaybookComparisonOperator::Equals: return "equals";
        case PlaybookComparisonOperator::NotEquals: return "not_equals";
        case PlaybookComparisonOperator::GreaterThan: return "gt";
        case PlaybookComparisonOperator::GreaterThanOrEqual: return "gte";
        case PlaybookComparisonOperator::LessThan: return "lt";
        case PlaybookComparisonOperator::LessThanOrEqual: return "lte";
        case PlaybookComparisonOperator::Contains: return "contains";
        case PlaybookComparisonOperator::In: return "in";
    }

    return "exists";
}

[[nodiscard]] constexpr std::string_view ToString(const PlaybookFailureMode value) noexcept {
    switch (value) {
        case PlaybookFailureMode::Stop: return "stop";
        case PlaybookFailureMode::Continue: return "continue";
    }

    return "stop";
}

[[nodiscard]] inline std::string NormalizeEnumToken(std::string_view value) {
    std::string result;
    result.reserve(value.size());

    for (const unsigned char ch : value) {
        if (ch == '-' || ch == ' ') {
            result.push_back('_');
        } else {
            result.push_back(static_cast<char>(std::tolower(ch)));
        }
    }

    return result;
}

[[nodiscard]] inline std::optional<PlaybookStepType> PlaybookStepTypeFromString(std::string_view value) {
    const std::string token = NormalizeEnumToken(value);
    if (token == "action") {
        return PlaybookStepType::Action;
    }
    if (token == "condition" || token == "if") {
        return PlaybookStepType::Condition;
    }
    if (token == "sequence") {
        return PlaybookStepType::Sequence;
    }
    if (token == "parallel") {
        return PlaybookStepType::Parallel;
    }
    if (token == "loop" || token == "foreach" || token == "for_each") {
        return PlaybookStepType::Loop;
    }
    if (token == "delay" || token == "sleep") {
        return PlaybookStepType::Delay;
    }
    return std::nullopt;
}

[[nodiscard]] inline std::optional<PlaybookActionType> PlaybookActionTypeFromString(std::string_view value) {
    const std::string token = NormalizeEnumToken(value);
    if (token == "isolate_endpoint" || token == "isolate") {
        return PlaybookActionType::IsolateEndpoint;
    }
    if (token == "kill_process" || token == "terminate_process") {
        return PlaybookActionType::KillProcess;
    }
    if (token == "quarantine_file" || token == "quarantine") {
        return PlaybookActionType::QuarantineFile;
    }
    if (token == "block_ip") {
        return PlaybookActionType::BlockIP;
    }
    if (token == "disable_user" || token == "lock_account") {
        return PlaybookActionType::DisableUser;
    }
    if (token == "collect_evidence") {
        return PlaybookActionType::CollectEvidence;
    }
    if (token == "enrich_ioc") {
        return PlaybookActionType::EnrichIOC;
    }
    if (token == "notify_local" || token == "notify") {
        return PlaybookActionType::NotifyLocal;
    }
    return std::nullopt;
}

[[nodiscard]] inline std::optional<PlaybookRunStatus> PlaybookRunStatusFromString(std::string_view value) {
    const std::string token = NormalizeEnumToken(value);
    if (token == "pending") {
        return PlaybookRunStatus::Pending;
    }
    if (token == "running") {
        return PlaybookRunStatus::Running;
    }
    if (token == "success") {
        return PlaybookRunStatus::Success;
    }
    if (token == "failed") {
        return PlaybookRunStatus::Failed;
    }
    if (token == "cancelled") {
        return PlaybookRunStatus::Cancelled;
    }
    if (token == "timed_out" || token == "timeout") {
        return PlaybookRunStatus::TimedOut;
    }
    if (token == "partial_success" || token == "partial") {
        return PlaybookRunStatus::PartialSuccess;
    }
    return std::nullopt;
}

[[nodiscard]] inline std::optional<PlaybookTriggerType> PlaybookTriggerTypeFromString(std::string_view value) {
    const std::string token = NormalizeEnumToken(value);
    if (token == "alert") {
        return PlaybookTriggerType::Alert;
    }
    if (token == "schedule" || token == "scheduled") {
        return PlaybookTriggerType::Schedule;
    }
    if (token == "manual") {
        return PlaybookTriggerType::Manual;
    }
    if (token == "on_demand" || token == "ondemand") {
        return PlaybookTriggerType::OnDemand;
    }
    return std::nullopt;
}

[[nodiscard]] inline std::optional<PlaybookComparisonOperator> PlaybookComparisonOperatorFromString(
    std::string_view value) {
    const std::string token = NormalizeEnumToken(value);
    if (token == "exists") {
        return PlaybookComparisonOperator::Exists;
    }
    if (token == "equals" || token == "eq") {
        return PlaybookComparisonOperator::Equals;
    }
    if (token == "not_equals" || token == "neq" || token == "not_eq") {
        return PlaybookComparisonOperator::NotEquals;
    }
    if (token == "gt" || token == "greater_than") {
        return PlaybookComparisonOperator::GreaterThan;
    }
    if (token == "gte" || token == "greater_than_or_equal") {
        return PlaybookComparisonOperator::GreaterThanOrEqual;
    }
    if (token == "lt" || token == "less_than") {
        return PlaybookComparisonOperator::LessThan;
    }
    if (token == "lte" || token == "less_than_or_equal") {
        return PlaybookComparisonOperator::LessThanOrEqual;
    }
    if (token == "contains") {
        return PlaybookComparisonOperator::Contains;
    }
    if (token == "in") {
        return PlaybookComparisonOperator::In;
    }
    return std::nullopt;
}

[[nodiscard]] inline std::optional<PlaybookFailureMode> PlaybookFailureModeFromString(std::string_view value) {
    const std::string token = NormalizeEnumToken(value);
    if (token == "stop" || token == "abort") {
        return PlaybookFailureMode::Stop;
    }
    if (token == "continue") {
        return PlaybookFailureMode::Continue;
    }
    return std::nullopt;
}

} // namespace ShadowStrike::Products::PhantomEDR::Playbooks
