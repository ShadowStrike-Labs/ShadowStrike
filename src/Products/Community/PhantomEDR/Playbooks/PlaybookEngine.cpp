/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */
#include "pch.h"
#include "Products/Community/PhantomEDR/Playbooks/PlaybookEngine.hpp"

#include "Products/Community/PhantomEDR/Playbooks/PlaybookAction.hpp"
#include "Products/Community/PhantomEDR/Playbooks/PlaybookLibrary.hpp"
#include "PhantomCore/Database/DatabaseManager.hpp"
#include "PhantomCore/Utils/FileUtils.hpp"
#include "PhantomCore/Utils/Logger.hpp"
#include "PhantomCore/Utils/StringUtils.hpp"

#include <future>
#include <map>
#include <memory>
#include <shared_mutex>
#include <thread>
#include <unordered_map>

namespace ShadowStrike::Products::PhantomEDR::Playbooks {

namespace {

using ShadowStrike::Database::DatabaseError;
using ShadowStrike::Database::DatabaseManager;
using ShadowStrike::Database::QueryResult;
using ShadowStrike::Utils::Logger;
namespace FileUtils = ShadowStrike::Utils::FileUtils;
namespace StringUtils = ShadowStrike::Utils::StringUtils;

constexpr std::string_view kLogPrefix = "[PlaybookEngine]";
constexpr std::string_view kCreateDefinitionsSql = R"(
    CREATE TABLE IF NOT EXISTS playbook_definitions (
        playbook_id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        description TEXT NOT NULL,
        version TEXT NOT NULL,
        enabled INTEGER NOT NULL,
        built_in INTEGER NOT NULL,
        definition_json TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL
    );
)";

constexpr std::string_view kCreateRunsSql = R"(
    CREATE TABLE IF NOT EXISTS playbook_runs (
        run_id TEXT PRIMARY KEY,
        playbook_id TEXT NOT NULL,
        trigger_type INTEGER NOT NULL,
        trigger_reference TEXT NOT NULL,
        status INTEGER NOT NULL,
        started_at INTEGER NOT NULL,
        completed_at INTEGER NOT NULL,
        input_context_json TEXT NOT NULL,
        output_context_json TEXT NOT NULL,
        error_message TEXT NOT NULL
    );
)";

constexpr std::string_view kCreateStepsSql = R"(
    CREATE TABLE IF NOT EXISTS playbook_run_steps (
        run_id TEXT NOT NULL,
        step_index INTEGER NOT NULL,
        step_id TEXT NOT NULL,
        step_type INTEGER NOT NULL,
        status INTEGER NOT NULL,
        started_at INTEGER NOT NULL,
        completed_at INTEGER NOT NULL,
        success INTEGER NOT NULL,
        message TEXT NOT NULL,
        output_json TEXT NOT NULL,
        PRIMARY KEY (run_id, step_index)
    );
)";

constexpr std::string_view kCreateIndexesSql = R"(
    CREATE INDEX IF NOT EXISTS idx_playbook_runs_playbook_started ON playbook_runs(playbook_id, started_at DESC);
    CREATE INDEX IF NOT EXISTS idx_playbook_run_steps_run ON playbook_run_steps(run_id, step_index ASC);
)";

[[nodiscard]] int64_t ToUnixMillis(const std::chrono::system_clock::time_point value) noexcept {
    return std::chrono::duration_cast<std::chrono::milliseconds>(value.time_since_epoch()).count();
}

[[nodiscard]] std::chrono::system_clock::time_point FromUnixMillis(const int64_t value) noexcept {
    return std::chrono::system_clock::time_point{ std::chrono::milliseconds(value) };
}

[[nodiscard]] std::string MakeStableId(
    const std::string_view prefix,
    const std::string_view source,
    const uint64_t entropy) {
    uint64_t hash = 14695981039346656037ull;
    for (const unsigned char ch : source) {
        hash ^= static_cast<uint64_t>(ch);
        hash *= 1099511628211ull;
    }
    hash ^= entropy;
    hash *= 1099511628211ull;
    return std::format("{}-{:016x}", prefix, hash);
}

[[nodiscard]] Json GetJsonPath(const Json& value, std::string_view path) {
    if (path.empty()) {
        return value;
    }

    const auto segments = StringUtils::Split(StringUtils::ToWide(std::string(path)), L".");
    const Json* current = &value;

    for (const auto& segmentWide : segments) {
        const std::string segment = StringUtils::ToNarrow(segmentWide);
        if (segment.empty()) {
            return Json();
        }

        if (current->is_object()) {
            const auto it = current->find(segment);
            if (it == current->end()) {
                return Json();
            }
            current = &(*it);
            continue;
        }

        if (current->is_array()) {
            try {
                const size_t index = static_cast<size_t>(std::stoull(segment));
                if (index >= current->size()) {
                    return Json();
                }
                current = &(*current)[index];
                continue;
            } catch (...) {
                return Json();
            }
        }

        return Json();
    }

    return *current;
}

void SetJsonPath(Json& root, const std::string_view path, const Json& value) {
    if (path.empty()) {
        return;
    }

    const auto segments = StringUtils::Split(StringUtils::ToWide(std::string(path)), L".");
    Json* current = &root;

    for (size_t i = 0; i < segments.size(); ++i) {
        const std::string segment = StringUtils::ToNarrow(segments[i]);
        if (segment.empty()) {
            return;
        }

        if (i + 1 == segments.size()) {
            (*current)[segment] = value;
            return;
        }

        if (!(*current)[segment].is_object()) {
            (*current)[segment] = Json::object();
        }
        current = &(*current)[segment];
    }
}

[[nodiscard]] std::string JsonScalarToString(const Json& value) {
    if (value.is_string()) {
        return value.get<std::string>();
    }
    if (value.is_boolean()) {
        return value.get<bool>() ? "true" : "false";
    }
    if (value.is_number_integer()) {
        return std::to_string(value.get<int64_t>());
    }
    if (value.is_number_unsigned()) {
        return std::to_string(value.get<uint64_t>());
    }
    if (value.is_number_float()) {
        return std::format("{}", value.get<double>());
    }
    return value.dump();
}

[[nodiscard]] Json ResolveTemplateValue(std::string_view text, const Json& context) {
    const size_t open = text.find("{{");
    const size_t close = text.rfind("}}");
    if (open == std::string_view::npos || close == std::string_view::npos || close <= open + 2) {
        return Json(std::string(text));
    }

    if (open == 0 && close + 2 == text.size()) {
        const std::string expression = std::string(text.substr(2, close - 2));
        const std::string trimmed = StringUtils::ToNarrow(StringUtils::TrimCopy(StringUtils::ToWide(expression)));
        const Json value = GetJsonPath(context, trimmed);
        return value.is_discarded() ? Json() : value;
    }

    std::string resolved;
    resolved.reserve(text.size());
    size_t offset = 0;
    while (offset < text.size()) {
        const size_t tokenStart = text.find("{{", offset);
        if (tokenStart == std::string_view::npos) {
            resolved.append(text.substr(offset));
            break;
        }

        resolved.append(text.substr(offset, tokenStart - offset));
        const size_t tokenEnd = text.find("}}", tokenStart + 2);
        if (tokenEnd == std::string_view::npos) {
            resolved.append(text.substr(tokenStart));
            break;
        }

        const std::string expression = std::string(text.substr(tokenStart + 2, tokenEnd - tokenStart - 2));
        const std::string trimmed = StringUtils::ToNarrow(StringUtils::TrimCopy(StringUtils::ToWide(expression)));
        const Json tokenValue = GetJsonPath(context, trimmed);
        resolved.append(JsonScalarToString(tokenValue));
        offset = tokenEnd + 2;
    }

    return Json(resolved);
}

[[nodiscard]] Json ResolveTemplates(const Json& value, const Json& context) {
    if (value.is_string()) {
        return ResolveTemplateValue(value.get_ref<const std::string&>(), context);
    }

    if (value.is_array()) {
        Json result = Json::array();
        for (const auto& item : value) {
            result.push_back(ResolveTemplates(item, context));
        }
        return result;
    }

    if (value.is_object()) {
        Json result = Json::object();
        for (const auto& [key, child] : value.items()) {
            result[key] = ResolveTemplates(child, context);
        }
        return result;
    }

    return value;
}

void DeepMerge(Json& target, const Json& source) {
    if (!target.is_object() || !source.is_object()) {
        target = source;
        return;
    }

    for (const auto& [key, value] : source.items()) {
        if (target.contains(key) && target[key].is_object() && value.is_object()) {
            DeepMerge(target[key], value);
        } else {
            target[key] = value;
        }
    }
}

[[nodiscard]] bool CompareJsonValues(const Json& lhs, const PlaybookComparisonOperator op, const Json& rhs) {
    switch (op) {
        case PlaybookComparisonOperator::Exists:
            return !lhs.is_null();
        case PlaybookComparisonOperator::Equals:
            return lhs == rhs;
        case PlaybookComparisonOperator::NotEquals:
            return lhs != rhs;
        case PlaybookComparisonOperator::Contains:
            if (lhs.is_string()) {
                return lhs.get_ref<const std::string&>().find(JsonScalarToString(rhs)) != std::string::npos;
            }
            if (lhs.is_array()) {
                for (const auto& item : lhs) {
                    if (item == rhs) {
                        return true;
                    }
                }
            }
            return false;
        case PlaybookComparisonOperator::In:
            if (!rhs.is_array()) {
                return false;
            }
            for (const auto& item : rhs) {
                if (item == lhs) {
                    return true;
                }
            }
            return false;
        case PlaybookComparisonOperator::GreaterThan:
        case PlaybookComparisonOperator::GreaterThanOrEqual:
        case PlaybookComparisonOperator::LessThan:
        case PlaybookComparisonOperator::LessThanOrEqual: {
            if (lhs.is_number() && rhs.is_number()) {
                const double left = lhs.get<double>();
                const double right = rhs.get<double>();
                if (op == PlaybookComparisonOperator::GreaterThan) {
                    return left > right;
                }
                if (op == PlaybookComparisonOperator::GreaterThanOrEqual) {
                    return left >= right;
                }
                if (op == PlaybookComparisonOperator::LessThan) {
                    return left < right;
                }
                return left <= right;
            }

            const std::string left = JsonScalarToString(lhs);
            const std::string right = JsonScalarToString(rhs);
            if (op == PlaybookComparisonOperator::GreaterThan) {
                return left > right;
            }
            if (op == PlaybookComparisonOperator::GreaterThanOrEqual) {
                return left >= right;
            }
            if (op == PlaybookComparisonOperator::LessThan) {
                return left < right;
            }
            return left <= right;
        }
    }

    return false;
}

[[nodiscard]] PlaybookCondition ParseCondition(const Json& document) {
    if (!document.is_object()) {
        throw std::runtime_error("Condition must be an object");
    }

    PlaybookCondition condition;
    condition.path = document.value("path", "");
    if (condition.path.empty()) {
        throw std::runtime_error("Condition path is required");
    }

    const auto op = PlaybookComparisonOperatorFromString(document.value("operator", "exists"));
    if (!op.has_value()) {
        throw std::runtime_error("Unsupported condition operator");
    }
    condition.op = *op;

    if (document.contains("value")) {
        condition.value = document["value"];
    }
    condition.negate = document.value("negate", false);
    return condition;
}

[[nodiscard]] PlaybookStep ParseStep(const Json& document) {
    if (!document.is_object()) {
        throw std::runtime_error("Step must be a JSON object");
    }

    PlaybookStep step;
    step.id = document.value("id", "");
    step.name = document.value("name", step.id);
    step.enabled = document.value("enabled", true);
    step.storeResultAs = document.value("store_result_as", "");
    step.timeoutMs = document.value("timeout_ms", 0u);
    step.repeatCount = document.value("count", 0u);
    step.delayMs = document.value("duration_ms", document.value("delay_ms", 0ull));
    step.itemsPath = document.value("items_path", "");
    step.iteratorName = document.value("iterator", "item");

    const auto type = PlaybookStepTypeFromString(document.value("type", "action"));
    if (!type.has_value()) {
        throw std::runtime_error("Unsupported playbook step type");
    }
    step.type = *type;

    if (const auto failureMode = PlaybookFailureModeFromString(document.value("on_failure", "stop")); failureMode.has_value()) {
        step.onFailure = *failureMode;
    }

    switch (step.type) {
        case PlaybookStepType::Action: {
            const auto action = PlaybookActionTypeFromString(document.value("action", ""));
            if (!action.has_value()) {
                throw std::runtime_error("Action step requires a supported action");
            }
            step.action = *action;
            step.parameters = document.value("parameters", Json::object());
            break;
        }
        case PlaybookStepType::Condition: {
            step.condition = ParseCondition(document.at("condition"));
            if (!document.contains("then") || !document["then"].is_array()) {
                throw std::runtime_error("Condition step requires a then array");
            }
            for (const auto& child : document["then"]) {
                step.steps.push_back(ParseStep(child));
            }
            if (document.contains("else")) {
                if (!document["else"].is_array()) {
                    throw std::runtime_error("Condition else must be an array");
                }
                for (const auto& child : document["else"]) {
                    step.elseSteps.push_back(ParseStep(child));
                }
            }
            break;
        }
        case PlaybookStepType::Sequence:
        case PlaybookStepType::Parallel:
        case PlaybookStepType::Loop: {
            if (!document.contains("steps") || !document["steps"].is_array()) {
                throw std::runtime_error("Composite steps require a steps array");
            }
            for (const auto& child : document["steps"]) {
                step.steps.push_back(ParseStep(child));
            }
            break;
        }
        case PlaybookStepType::Delay:
            if (step.delayMs == 0) {
                throw std::runtime_error("Delay step requires duration_ms");
            }
            break;
    }

    if (step.id.empty()) {
        step.id = MakeStableId("step", step.name.empty() ? ToString(step.type) : step.name, step.steps.size());
    }
    if (step.name.empty()) {
        step.name = step.id;
    }

    return step;
}

[[nodiscard]] PlaybookDefinition ParsePlaybook(const Json& document) {
    if (!document.is_object()) {
        throw std::runtime_error("Playbook document must be an object");
    }

    PlaybookDefinition playbook;
    playbook.id = document.value("id", "");
    playbook.name = document.value("name", playbook.id);
    playbook.description = document.value("description", "");
    playbook.version = document.value("version", "1.0.0");
    playbook.enabled = document.value("enabled", true);
    playbook.defaultTimeoutMs = document.value("default_timeout_ms", 300000u);
    playbook.defaultContext = document.value("default_context", Json::object());

    if (playbook.id.empty()) {
        throw std::runtime_error("Playbook id is required");
    }
    if (!document.contains("steps") || !document["steps"].is_array()) {
        throw std::runtime_error("Playbook steps array is required");
    }

    for (const auto& step : document["steps"]) {
        playbook.steps.push_back(ParseStep(step));
    }

    return playbook;
}

[[nodiscard]] Json SerializeCondition(const PlaybookCondition& condition) {
    Json document = {
        { "path", condition.path },
        { "operator", ToString(condition.op) },
        { "negate", condition.negate }
    };
    if (!condition.value.is_null()) {
        document["value"] = condition.value;
    }
    return document;
}

[[nodiscard]] Json SerializeStep(const PlaybookStep& step) {
    Json document = {
        { "id", step.id },
        { "name", step.name },
        { "type", ToString(step.type) },
        { "enabled", step.enabled },
        { "store_result_as", step.storeResultAs },
        { "timeout_ms", step.timeoutMs },
        { "on_failure", ToString(step.onFailure) }
    };

    switch (step.type) {
        case PlaybookStepType::Action:
            document["action"] = ToString(step.action);
            document["parameters"] = step.parameters;
            break;
        case PlaybookStepType::Condition:
            document["condition"] = SerializeCondition(step.condition);
            document["then"] = Json::array();
            for (const auto& child : step.steps) {
                document["then"].push_back(SerializeStep(child));
            }
            document["else"] = Json::array();
            for (const auto& child : step.elseSteps) {
                document["else"].push_back(SerializeStep(child));
            }
            break;
        case PlaybookStepType::Sequence:
        case PlaybookStepType::Parallel:
            document["steps"] = Json::array();
            for (const auto& child : step.steps) {
                document["steps"].push_back(SerializeStep(child));
            }
            break;
        case PlaybookStepType::Loop:
            document["items_path"] = step.itemsPath;
            document["iterator"] = step.iteratorName;
            document["count"] = step.repeatCount;
            document["steps"] = Json::array();
            for (const auto& child : step.steps) {
                document["steps"].push_back(SerializeStep(child));
            }
            break;
        case PlaybookStepType::Delay:
            document["duration_ms"] = step.delayMs;
            break;
    }

    return document;
}

[[nodiscard]] Json SerializePlaybook(const PlaybookDefinition& playbook) {
    Json document = {
        { "id", playbook.id },
        { "name", playbook.name },
        { "description", playbook.description },
        { "version", playbook.version },
        { "enabled", playbook.enabled },
        { "default_timeout_ms", playbook.defaultTimeoutMs },
        { "default_context", playbook.defaultContext },
        { "steps", Json::array() }
    };

    for (const auto& step : playbook.steps) {
        document["steps"].push_back(SerializeStep(step));
    }
    return document;
}

[[nodiscard]] PlaybookDefinition RowToPlaybook(QueryResult& result) {
    return ParsePlaybook(Json::parse(result.GetString(5)));
}

[[nodiscard]] StepExecutionResult RowToStepResult(QueryResult& result) {
    StepExecutionResult stepResult;
    stepResult.runId = result.GetString(0);
    stepResult.stepIndex = static_cast<size_t>(result.GetInt64(1));
    stepResult.stepId = result.GetString(2);
    stepResult.type = static_cast<PlaybookStepType>(result.GetInt(3));
    stepResult.status = static_cast<PlaybookRunStatus>(result.GetInt(4));
    stepResult.startedAt = FromUnixMillis(result.GetInt64(5));
    stepResult.completedAt = FromUnixMillis(result.GetInt64(6));
    stepResult.success = result.GetInt(7) != 0;
    stepResult.message = result.GetString(8);
    stepResult.output = Json::parse(result.GetString(9), nullptr, false);
    if (stepResult.output.is_discarded()) {
        stepResult.output = Json::object();
    }
    return stepResult;
}

struct ExecutionAccumulator {
    bool hardFailure = false;
    bool sawFailure = false;
};

} // namespace

class PlaybookEngineImpl {
public:
    bool initialized = false;
    mutable std::shared_mutex mutex;
    std::unordered_map<std::string, PlaybookDefinition> playbooks;

    [[nodiscard]] bool EnsureSchema() const {
        DatabaseError dbError;
        if (!DatabaseManager::Instance().Execute(kCreateDefinitionsSql.data(), &dbError) ||
            !DatabaseManager::Instance().Execute(kCreateRunsSql.data(), &dbError) ||
            !DatabaseManager::Instance().Execute(kCreateStepsSql.data(), &dbError) ||
            !DatabaseManager::Instance().Execute(kCreateIndexesSql.data(), &dbError)) {
            Logger::Error(
                "{} Failed to initialize schema: {}",
                kLogPrefix,
                StringUtils::ToNarrow(dbError.message));
            return false;
        }

        return true;
    }

    [[nodiscard]] bool PersistPlaybook(const PlaybookDefinition& playbook, const bool builtIn) const {
        DatabaseError dbError;
        const auto now = ToUnixMillis(std::chrono::system_clock::now());
        return DatabaseManager::Instance().ExecuteWithParams(
            "INSERT INTO playbook_definitions "
            "(playbook_id, name, description, version, enabled, built_in, definition_json, created_at, updated_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) "
            "ON CONFLICT(playbook_id) DO UPDATE SET "
            "name = excluded.name, description = excluded.description, version = excluded.version, "
            "enabled = excluded.enabled, built_in = excluded.built_in, definition_json = excluded.definition_json, "
            "updated_at = excluded.updated_at;",
            &dbError,
            playbook.id,
            playbook.name,
            playbook.description,
            playbook.version,
            playbook.enabled ? 1 : 0,
            builtIn ? 1 : 0,
            SerializePlaybook(playbook).dump(),
            now,
            now);
    }

    [[nodiscard]] bool PersistRunStart(const PlaybookRunRecord& run) const {
        DatabaseError dbError;
        return DatabaseManager::Instance().ExecuteWithParams(
            "INSERT INTO playbook_runs "
            "(run_id, playbook_id, trigger_type, trigger_reference, status, started_at, completed_at, input_context_json, output_context_json, error_message) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);",
            &dbError,
            run.runId,
            run.playbookId,
            static_cast<int>(run.triggerType),
            run.triggerReference,
            static_cast<int>(run.status),
            ToUnixMillis(run.startedAt),
            int64_t{ 0 },
            run.inputContext.dump(),
            run.outputContext.dump(),
            run.errorMessage);
    }

    [[nodiscard]] bool PersistStepResult(const StepExecutionResult& step) const {
        DatabaseError dbError;
        return DatabaseManager::Instance().ExecuteWithParams(
            "INSERT OR REPLACE INTO playbook_run_steps "
            "(run_id, step_index, step_id, step_type, status, started_at, completed_at, success, message, output_json) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);",
            &dbError,
            step.runId,
            static_cast<int64_t>(step.stepIndex),
            step.stepId,
            static_cast<int>(step.type),
            static_cast<int>(step.status),
            ToUnixMillis(step.startedAt),
            ToUnixMillis(step.completedAt),
            step.success ? 1 : 0,
            step.message,
            step.output.dump());
    }

    [[nodiscard]] bool PersistRunFinish(const PlaybookRunRecord& run) const {
        DatabaseError dbError;
        return DatabaseManager::Instance().ExecuteWithParams(
            "UPDATE playbook_runs "
            "SET status = ?, completed_at = ?, output_context_json = ?, error_message = ? "
            "WHERE run_id = ?;",
            &dbError,
            static_cast<int>(run.status),
            run.completedAt.has_value() ? ToUnixMillis(*run.completedAt) : int64_t{ 0 },
            run.outputContext.dump(),
            run.errorMessage,
            run.runId);
    }

    [[nodiscard]] bool EvaluateCondition(const PlaybookCondition& condition, const Json& context) const {
        Json lhs = GetJsonPath(context, condition.path);
        if (lhs.is_discarded()) {
            lhs = Json();
        }

        const bool comparison = CompareJsonValues(lhs, condition.op, ResolveTemplates(condition.value, context));
        return condition.negate ? !comparison : comparison;
    }

    StepExecutionResult ExecuteStep(
        const PlaybookStep& step,
        Json& context,
        const std::string_view runId,
        std::atomic_size_t& stepIndex,
        ExecutionAccumulator& accumulator) const {
        StepExecutionResult result;
        result.runId = std::string(runId);
        result.stepId = step.id;
        result.type = step.type;
        result.status = PlaybookRunStatus::Running;
        result.stepIndex = ++stepIndex;
        result.startedAt = std::chrono::system_clock::now();

        auto finish = [&](const bool success, const PlaybookRunStatus status, std::string message, Json output) {
            result.success = success;
            result.status = status;
            result.message = std::move(message);
            result.output = std::move(output);
            result.completedAt = std::chrono::system_clock::now();
            [[maybe_unused]] const bool persisted = PersistStepResult(result);
            if (!success) {
                accumulator.sawFailure = true;
                if (step.onFailure == PlaybookFailureMode::Stop) {
                    accumulator.hardFailure = true;
                }
            }
            return result;
        };

        if (!step.enabled) {
            return finish(true, PlaybookRunStatus::Success, "Step disabled", Json::object({ { "skipped", true } }));
        }

        switch (step.type) {
            case PlaybookStepType::Action: {
                Json resolvedParameters = ResolveTemplates(step.parameters, context);
                ActionResult actionResult = PlaybookAction::Instance().ExecuteAction(step.action, resolvedParameters, context, runId);
                Json output = {
                    { "action", ToString(step.action) },
                    { "message", actionResult.message },
                    { "details", actionResult.details },
                    { "duration_ms", actionResult.durationMs }
                };

                if (actionResult.success) {
                    if (!step.storeResultAs.empty()) {
                        SetJsonPath(context, step.storeResultAs, actionResult.details);
                    } else {
                        SetJsonPath(context, std::format("results.{}", step.id), actionResult.details);
                    }
                    return finish(true, PlaybookRunStatus::Success, actionResult.message, output);
                }

                return finish(false, PlaybookRunStatus::Failed, actionResult.message, output);
            }
            case PlaybookStepType::Delay: {
                const uint64_t effectiveDelayMs = std::min<uint64_t>(step.delayMs, 3600000ull);
                std::this_thread::sleep_for(std::chrono::milliseconds(effectiveDelayMs));
                return finish(
                    true,
                    PlaybookRunStatus::Success,
                    std::format("Delayed execution by {}ms", effectiveDelayMs),
                    Json::object({ { "delay_ms", effectiveDelayMs } }));
            }
            case PlaybookStepType::Condition: {
                const bool branch = EvaluateCondition(step.condition, context);
                Json output = {
                    { "matched", branch },
                    { "path", step.condition.path },
                    { "operator", ToString(step.condition.op) }
                };

                const auto& branchSteps = branch ? step.steps : step.elseSteps;
                Json branchResults = Json::array();
                for (const auto& child : branchSteps) {
                    StepExecutionResult childResult = ExecuteStep(child, context, runId, stepIndex, accumulator);
                    branchResults.push_back({
                        { "step_id", childResult.stepId },
                        { "success", childResult.success },
                        { "status", ToString(childResult.status) }
                    });
                    if (accumulator.hardFailure) {
                        output["branch_results"] = branchResults;
                        return finish(false, PlaybookRunStatus::Failed, "Condition branch failed", output);
                    }
                }

                output["branch_results"] = branchResults;
                return finish(true, PlaybookRunStatus::Success, branch ? "Condition matched" : "Condition not matched", output);
            }
            case PlaybookStepType::Sequence: {
                Json childResults = Json::array();
                for (const auto& child : step.steps) {
                    StepExecutionResult childResult = ExecuteStep(child, context, runId, stepIndex, accumulator);
                    childResults.push_back({
                        { "step_id", childResult.stepId },
                        { "success", childResult.success },
                        { "status", ToString(childResult.status) }
                    });
                    if (accumulator.hardFailure) {
                        return finish(false, PlaybookRunStatus::Failed, "Sequence aborted by failing child step", Json::object({ { "children", childResults } }));
                    }
                }
                return finish(true, PlaybookRunStatus::Success, "Sequence completed", Json::object({ { "children", childResults } }));
            }
            case PlaybookStepType::Parallel: {
                struct BranchResult {
                    Json branchContext;
                    StepExecutionResult stepResult;
                };

                std::vector<std::future<BranchResult>> futures;
                futures.reserve(step.steps.size());
                for (const auto& child : step.steps) {
                    futures.emplace_back(std::async(std::launch::async, [&]() {
                        Json branchContext = context;
                        std::atomic_size_t& branchIndex = stepIndex;
                        ExecutionAccumulator branchAccumulator;
                        StepExecutionResult branchResult = ExecuteStep(child, branchContext, runId, branchIndex, branchAccumulator);
                        return BranchResult{ std::move(branchContext), std::move(branchResult) };
                    }));
                }

                Json mergedBranchContexts = Json::object();
                Json branchResults = Json::array();
                bool success = true;
                for (auto& future : futures) {
                    BranchResult branch = future.get();
                    mergedBranchContexts[branch.stepResult.stepId] = branch.branchContext;
                    branchResults.push_back({
                        { "step_id", branch.stepResult.stepId },
                        { "success", branch.stepResult.success },
                        { "status", ToString(branch.stepResult.status) }
                    });
                    success = success && branch.stepResult.success;
                }

                context["parallel"][step.id] = mergedBranchContexts;
                return finish(
                    success,
                    success ? PlaybookRunStatus::Success : PlaybookRunStatus::PartialSuccess,
                    success ? "Parallel execution completed" : "Parallel execution completed with failures",
                    Json::object({ { "branches", branchResults } }));
            }
            case PlaybookStepType::Loop: {
                Json loopResults = Json::array();
                size_t iterationCount = 0;

                if (!step.itemsPath.empty()) {
                    Json items = GetJsonPath(context, step.itemsPath);
                    if (!items.is_array()) {
                        return finish(false, PlaybookRunStatus::Failed, "Loop items_path did not resolve to an array", Json::object());
                    }

                    iterationCount = items.size();
                    for (size_t i = 0; i < items.size(); ++i) {
                        context["loop"][step.iteratorName] = items[i];
                        context["loop"]["index"] = i;
                        Json iterationSummary = Json::array();
                        for (const auto& child : step.steps) {
                            StepExecutionResult childResult = ExecuteStep(child, context, runId, stepIndex, accumulator);
                            iterationSummary.push_back({
                                { "step_id", childResult.stepId },
                                { "success", childResult.success },
                                { "status", ToString(childResult.status) }
                            });
                            if (accumulator.hardFailure) {
                                loopResults.push_back(iterationSummary);
                                return finish(false, PlaybookRunStatus::Failed, "Loop aborted by failing child step", Json::object({ { "iterations", loopResults } }));
                            }
                        }
                        loopResults.push_back(iterationSummary);
                    }
                } else {
                    iterationCount = step.repeatCount;
                    for (size_t i = 0; i < step.repeatCount; ++i) {
                        context["loop"][step.iteratorName] = i;
                        context["loop"]["index"] = i;
                        Json iterationSummary = Json::array();
                        for (const auto& child : step.steps) {
                            StepExecutionResult childResult = ExecuteStep(child, context, runId, stepIndex, accumulator);
                            iterationSummary.push_back({
                                { "step_id", childResult.stepId },
                                { "success", childResult.success },
                                { "status", ToString(childResult.status) }
                            });
                            if (accumulator.hardFailure) {
                                loopResults.push_back(iterationSummary);
                                return finish(false, PlaybookRunStatus::Failed, "Loop aborted by failing child step", Json::object({ { "iterations", loopResults } }));
                            }
                        }
                        loopResults.push_back(iterationSummary);
                    }
                }

                if (!step.storeResultAs.empty()) {
                    SetJsonPath(context, step.storeResultAs, loopResults);
                }

                return finish(
                    true,
                    PlaybookRunStatus::Success,
                    std::format("Loop completed after {} iteration(s)", iterationCount),
                    Json::object({ { "iterations", loopResults } }));
            }
        }

        return finish(false, PlaybookRunStatus::Failed, "Unsupported step type", Json::object());
    }

    [[nodiscard]] std::optional<PlaybookRunRecord> LoadRunInternal(const std::string& runId) const {
        DatabaseError dbError;
        auto runRows = DatabaseManager::Instance().QueryWithParams(
            "SELECT run_id, playbook_id, trigger_type, trigger_reference, status, started_at, completed_at, "
            "input_context_json, output_context_json, error_message FROM playbook_runs WHERE run_id = ?;",
            &dbError,
            runId);

        if (!runRows.Next()) {
            return std::nullopt;
        }

        PlaybookRunRecord record;
        record.runId = runRows.GetString(0);
        record.playbookId = runRows.GetString(1);
        record.triggerType = static_cast<PlaybookTriggerType>(runRows.GetInt(2));
        record.triggerReference = runRows.GetString(3);
        record.status = static_cast<PlaybookRunStatus>(runRows.GetInt(4));
        record.startedAt = FromUnixMillis(runRows.GetInt64(5));
        const int64_t completedAt = runRows.GetInt64(6);
        if (completedAt != 0) {
            record.completedAt = FromUnixMillis(completedAt);
        }
        record.inputContext = Json::parse(runRows.GetString(7), nullptr, false);
        record.outputContext = Json::parse(runRows.GetString(8), nullptr, false);
        if (record.inputContext.is_discarded()) {
            record.inputContext = Json::object();
        }
        if (record.outputContext.is_discarded()) {
            record.outputContext = Json::object();
        }
        record.errorMessage = runRows.GetString(9);

        auto stepRows = DatabaseManager::Instance().QueryWithParams(
            "SELECT run_id, step_index, step_id, step_type, status, started_at, completed_at, success, message, output_json "
            "FROM playbook_run_steps WHERE run_id = ? ORDER BY step_index ASC;",
            &dbError,
            runId);
        while (stepRows.Next()) {
            record.stepResults.push_back(RowToStepResult(stepRows));
        }

        return record;
    }
};

PlaybookEngine& PlaybookEngine::Instance() {
    static PlaybookEngine instance;
    return instance;
}

PlaybookEngine::PlaybookEngine()
    : m_impl(std::make_unique<PlaybookEngineImpl>()) {
}

PlaybookEngine::~PlaybookEngine() = default;

bool PlaybookEngine::Initialize() {
    std::unique_lock lock(m_impl->mutex);
    if (m_impl->initialized) {
        return true;
    }

    if (!m_impl->EnsureSchema()) {
        return false;
    }
    if (!PlaybookAction::Instance().Initialize()) {
        return false;
    }
    if (!PlaybookLibrary::Instance().Initialize()) {
        return false;
    }

    for (const auto& document : PlaybookLibrary::Instance().GetPlaybookDocuments()) {
        const PlaybookDefinition playbook = ParsePlaybook(document);
        m_impl->playbooks[playbook.id] = playbook;
        if (!m_impl->PersistPlaybook(playbook, true)) {
            Logger::Warn("{} Unable to persist built-in playbook {}", kLogPrefix, playbook.id);
        }
    }

    m_impl->initialized = true;
    Logger::Info("{} Initialized successfully", kLogPrefix);
    return true;
}

void PlaybookEngine::Shutdown() {
    std::unique_lock lock(m_impl->mutex);
    if (!m_impl->initialized) {
        return;
    }

    m_impl->playbooks.clear();
    m_impl->initialized = false;
    Logger::Info("{} Shutdown complete", kLogPrefix);
}

bool PlaybookEngine::IsInitialized() const {
    std::shared_lock lock(m_impl->mutex);
    return m_impl->initialized;
}

bool PlaybookEngine::LoadPlaybookFromJson(const std::string_view playbookJson, std::string* registeredId) {
    try {
        const Json document = Json::parse(playbookJson);
        const PlaybookDefinition playbook = ParsePlaybook(document);
        if (!RegisterPlaybook(playbook, false)) {
            return false;
        }
        if (registeredId != nullptr) {
            *registeredId = playbook.id;
        }
        return true;
    } catch (const std::exception& ex) {
        Logger::Error("{} Failed to load playbook JSON: {}", kLogPrefix, ex.what());
        return false;
    }
}

bool PlaybookEngine::LoadPlaybookFromFile(const std::wstring_view path, std::string* registeredId) {
    std::string content;
    FileUtils::Error error;
    if (!FileUtils::ReadAllTextUtf8(path, content, &error)) {
        Logger::Error("{} Failed to read playbook file: {}", kLogPrefix, error.message);
        return false;
    }

    return LoadPlaybookFromJson(content, registeredId);
}

bool PlaybookEngine::RegisterPlaybook(const PlaybookDefinition& playbook, const bool builtIn) {
    if (!IsInitialized() && !Initialize()) {
        return false;
    }

    std::unique_lock lock(m_impl->mutex);
    m_impl->playbooks[playbook.id] = playbook;
    if (!m_impl->PersistPlaybook(playbook, builtIn)) {
        Logger::Error("{} Failed to persist playbook {}", kLogPrefix, playbook.id);
        return false;
    }

    Logger::Info("{} Registered playbook {}", kLogPrefix, playbook.id);
    return true;
}

std::optional<PlaybookDefinition> PlaybookEngine::GetPlaybook(const std::string_view playbookId) const {
    std::shared_lock lock(m_impl->mutex);
    const auto it = m_impl->playbooks.find(std::string(playbookId));
    if (it != m_impl->playbooks.end()) {
        return it->second;
    }

    DatabaseError dbError;
    auto rows = DatabaseManager::Instance().QueryWithParams(
        "SELECT playbook_id, name, description, version, enabled, definition_json "
        "FROM playbook_definitions WHERE playbook_id = ?;",
        &dbError,
        std::string(playbookId));
    if (!rows.Next()) {
        return std::nullopt;
    }

    return RowToPlaybook(rows);
}

std::vector<PlaybookDefinition> PlaybookEngine::ListPlaybooks() const {
    std::shared_lock lock(m_impl->mutex);
    std::vector<PlaybookDefinition> playbooks;
    playbooks.reserve(m_impl->playbooks.size());
    for (const auto& [_, playbook] : m_impl->playbooks) {
        playbooks.push_back(playbook);
    }
    return playbooks;
}

std::optional<PlaybookRunRecord> PlaybookEngine::ExecutePlaybook(
    const std::string_view playbookId,
    const Json& context,
    const PlaybookTriggerType trigger,
    const std::string_view triggerReference) {
    const auto playbook = GetPlaybook(playbookId);
    if (!playbook.has_value()) {
        Logger::Error("{} Failed to load playbook: {}", kLogPrefix, playbookId);
        return std::nullopt;
    }

    Json executionContext = playbook->defaultContext;
    DeepMerge(executionContext, context);
    executionContext["playbook"] = {
        { "id", playbook->id },
        { "name", playbook->name },
        { "version", playbook->version }
    };

    PlaybookRunRecord run;
    run.runId = MakeStableId("run", playbook->id, static_cast<uint64_t>(ToUnixMillis(std::chrono::system_clock::now())));
    run.playbookId = playbook->id;
    run.triggerType = trigger;
    run.triggerReference = std::string(triggerReference);
    run.status = PlaybookRunStatus::Running;
    run.startedAt = std::chrono::system_clock::now();
    run.inputContext = executionContext;
    run.outputContext = executionContext;

    if (!m_impl->PersistRunStart(run)) {
        Logger::Error("{} Failed to persist run start for {}", kLogPrefix, playbook->id);
        return std::nullopt;
    }

    std::atomic_size_t stepIndex = 0;
    ExecutionAccumulator accumulator;
    for (const auto& step : playbook->steps) {
        StepExecutionResult stepResult = m_impl->ExecuteStep(step, run.outputContext, run.runId, stepIndex, accumulator);
        run.stepResults.push_back(stepResult);
        if (accumulator.hardFailure) {
            run.status = PlaybookRunStatus::Failed;
            run.errorMessage = stepResult.message;
            break;
        }
    }

    if (run.status != PlaybookRunStatus::Failed) {
        run.status = accumulator.sawFailure ? PlaybookRunStatus::PartialSuccess : PlaybookRunStatus::Success;
    }
    run.completedAt = std::chrono::system_clock::now();

    if (!m_impl->PersistRunFinish(run)) {
        Logger::Error("{} Failed to finalize playbook run {}", kLogPrefix, run.runId);
        return std::nullopt;
    }

    Logger::Info("{} Playbook {} completed with status {}", kLogPrefix, playbook->id, ToString(run.status));
    return run;
}

std::optional<PlaybookRunRecord> PlaybookEngine::GetRun(const std::string_view runId) const {
    return m_impl->LoadRunInternal(std::string(runId));
}

std::vector<PlaybookRunRecord> PlaybookEngine::GetRunHistory(
    const std::string_view playbookId,
    const uint32_t maxRecords) const {
    std::vector<PlaybookRunRecord> runs;
    DatabaseError dbError;
    auto rows = DatabaseManager::Instance().QueryWithParams(
        "SELECT run_id FROM playbook_runs WHERE playbook_id = ? ORDER BY started_at DESC LIMIT ?;",
        &dbError,
        std::string(playbookId),
        static_cast<int>(maxRecords));

    while (rows.Next()) {
        if (auto run = m_impl->LoadRunInternal(rows.GetString(0)); run.has_value()) {
            runs.push_back(std::move(*run));
        }
    }

    return runs;
}

} // namespace ShadowStrike::Products::PhantomEDR::Playbooks
