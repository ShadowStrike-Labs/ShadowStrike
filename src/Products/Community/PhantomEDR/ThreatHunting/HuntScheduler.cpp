#include "pch.h"
#include "Products/Community/PhantomEDR/ThreatHunting/HuntScheduler.hpp"

#include <algorithm>
#include <chrono>
#include <condition_variable>
#include <cctype>
#include <format>
#include <memory>
#include <mutex>
#include <optional>
#include <shared_mutex>
#include <sstream>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

#include <nlohmann/json.hpp>

#include "PhantomCore/Database/DatabaseManager.hpp"
#include "PhantomCore/Utils/Logger.hpp"
#include "PhantomCore/Utils/StringUtils.hpp"
#include "Products/Community/PhantomEDR/ThreatHunting/HuntRuleManager.hpp"

namespace ShadowStrike::Products::PhantomEDR::ThreatHunting {

namespace {

using json = nlohmann::json;
using Clock = std::chrono::system_clock;
using ShadowStrike::Database::DatabaseError;
using ShadowStrike::Database::DatabaseManager;
using ShadowStrike::Database::QueryResult;
namespace StringUtils = ShadowStrike::Utils::StringUtils;

constexpr std::string_view kLogPrefix = "[HuntScheduler]";
constexpr auto kSchedulerPollInterval = std::chrono::seconds(30);
constexpr auto kMaxBackoff = std::chrono::hours(24);
constexpr uint32_t kMaxJobHistoryRecords = 500;

constexpr std::string_view kCreateSchedulesSql = R"(
    CREATE TABLE IF NOT EXISTS hunt_schedules (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        description TEXT NOT NULL,
        query_or_rule_id TEXT NOT NULL,
        frequency INTEGER NOT NULL,
        custom_interval_sec INTEGER NOT NULL,
        next_run_time INTEGER NOT NULL,
        last_run_time INTEGER NOT NULL,
        created_at INTEGER NOT NULL,
        enabled INTEGER NOT NULL,
        max_results_cached INTEGER NOT NULL,
        consecutive_failures INTEGER NOT NULL,
        last_status INTEGER NOT NULL
    );
)";

constexpr std::string_view kCreateJobHistorySql = R"(
    CREATE TABLE IF NOT EXISTS hunt_job_history (
        job_id TEXT PRIMARY KEY,
        schedule_id TEXT NOT NULL,
        status INTEGER NOT NULL,
        result_json TEXT NOT NULL,
        error_message TEXT NOT NULL,
        started_at INTEGER NOT NULL,
        completed_at INTEGER NOT NULL
    );
)";

constexpr std::string_view kCreateSchedulerIndexSql = R"(
    CREATE INDEX IF NOT EXISTS idx_hunt_schedules_next_run ON hunt_schedules(enabled, next_run_time);
    CREATE INDEX IF NOT EXISTS idx_hunt_job_history_schedule_started ON hunt_job_history(schedule_id, started_at DESC);
)";

constexpr std::string_view kUpsertScheduleSql = R"(
    INSERT INTO hunt_schedules (
        id, name, description, query_or_rule_id, frequency, custom_interval_sec,
        next_run_time, last_run_time, created_at, enabled, max_results_cached,
        consecutive_failures, last_status
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(id) DO UPDATE SET
        name = excluded.name,
        description = excluded.description,
        query_or_rule_id = excluded.query_or_rule_id,
        frequency = excluded.frequency,
        custom_interval_sec = excluded.custom_interval_sec,
        next_run_time = excluded.next_run_time,
        last_run_time = excluded.last_run_time,
        created_at = excluded.created_at,
        enabled = excluded.enabled,
        max_results_cached = excluded.max_results_cached,
        consecutive_failures = excluded.consecutive_failures,
        last_status = excluded.last_status;
)";

constexpr std::string_view kDeleteScheduleSql = R"(
    DELETE FROM hunt_schedules WHERE id = ?;
)";

constexpr std::string_view kUpdateScheduleStateSql = R"(
    UPDATE hunt_schedules
       SET enabled = ?,
           next_run_time = ?,
           last_status = ?
     WHERE id = ?;
)";

constexpr std::string_view kSelectScheduleSql = R"(
    SELECT id, name, description, query_or_rule_id, frequency, custom_interval_sec,
           next_run_time, last_run_time, created_at, enabled, max_results_cached,
           consecutive_failures, last_status
      FROM hunt_schedules
     WHERE id = ?;
)";

constexpr std::string_view kSelectAllSchedulesSql = R"(
    SELECT id, name, description, query_or_rule_id, frequency, custom_interval_sec,
           next_run_time, last_run_time, created_at, enabled, max_results_cached,
           consecutive_failures, last_status
      FROM hunt_schedules
     ORDER BY next_run_time ASC;
)";

constexpr std::string_view kSelectDueSchedulesSql = R"(
    SELECT id, name, description, query_or_rule_id, frequency, custom_interval_sec,
           next_run_time, last_run_time, created_at, enabled, max_results_cached,
           consecutive_failures, last_status
      FROM hunt_schedules
     WHERE enabled = 1
       AND next_run_time <= ?
     ORDER BY next_run_time ASC;
)";

constexpr std::string_view kInsertJobHistorySql = R"(
    INSERT INTO hunt_job_history (
        job_id, schedule_id, status, result_json, error_message, started_at, completed_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?);
)";

constexpr std::string_view kUpdateJobHistorySql = R"(
    UPDATE hunt_job_history
       SET status = ?,
           result_json = ?,
           error_message = ?,
           completed_at = ?
     WHERE job_id = ?;
)";

constexpr std::string_view kSelectJobHistorySqlPrefix = R"(
    SELECT job_id, schedule_id, status, result_json, error_message, started_at, completed_at
      FROM hunt_job_history
     WHERE schedule_id = ?
     ORDER BY started_at DESC
     LIMIT ?
)";

constexpr std::string_view kSelectLatestJobSql = R"(
    SELECT job_id, schedule_id, status, result_json, error_message, started_at, completed_at
      FROM hunt_job_history
     WHERE schedule_id = ?
     ORDER BY started_at DESC
     LIMIT 1;
)";

constexpr std::string_view kUpdateRunStateSql = R"(
    UPDATE hunt_schedules
       SET next_run_time = ?,
           last_run_time = ?,
           enabled = ?,
           consecutive_failures = ?,
           last_status = ?
     WHERE id = ?;
)";

[[nodiscard]] std::string TrimCopy(std::string_view value)
{
    size_t begin = 0;
    while (begin < value.size() && std::isspace(static_cast<unsigned char>(value[begin])) != 0) {
        ++begin;
    }

    size_t end = value.size();
    while (end > begin && std::isspace(static_cast<unsigned char>(value[end - 1])) != 0) {
        --end;
    }

    return std::string(value.substr(begin, end - begin));
}

[[nodiscard]] std::string ToLowerCopy(std::string_view value)
{
    std::string result(value);
    std::transform(
        result.begin(),
        result.end(),
        result.begin(),
        [](unsigned char ch) { return static_cast<char>(std::tolower(ch)); });
    return result;
}

[[nodiscard]] int64_t ToUnixSeconds(const Clock::time_point& value) noexcept
{
    return std::chrono::duration_cast<std::chrono::seconds>(value.time_since_epoch()).count();
}

[[nodiscard]] Clock::time_point FromUnixSeconds(int64_t value) noexcept
{
    return Clock::time_point{std::chrono::seconds(value)};
}

[[nodiscard]] bool IsDefaultTime(const Clock::time_point& value) noexcept
{
    return value.time_since_epoch().count() == 0;
}

[[nodiscard]] uint64_t Fnv1a64(std::string_view text) noexcept
{
    uint64_t hash = 14695981039346656037ull;
    for (const unsigned char ch : text) {
        hash ^= static_cast<uint64_t>(ch);
        hash *= 1099511628211ull;
    }
    return hash;
}

[[nodiscard]] std::string MakeJobId(std::string_view scheduleId, const Clock::time_point& startedAt)
{
    return std::format(
        "job-{:016x}",
        Fnv1a64(std::format("{}|{}", scheduleId, ToUnixSeconds(startedAt))));
}

[[nodiscard]] ScheduledHunt RowToSchedule(QueryResult& result)
{
    ScheduledHunt schedule;
    schedule.id = result.GetString(0);
    schedule.name = result.GetString(1);
    schedule.description = result.GetString(2);
    schedule.queryOrRuleId = result.GetString(3);
    schedule.frequency = static_cast<ScheduleFrequency>(result.GetInt(4));
    schedule.customInterval = std::chrono::seconds(result.GetInt64(5));
    schedule.nextRunTime = FromUnixSeconds(result.GetInt64(6));
    schedule.lastRunTime = FromUnixSeconds(result.GetInt64(7));
    schedule.createdAt = FromUnixSeconds(result.GetInt64(8));
    schedule.enabled = result.GetInt(9) != 0;
    schedule.maxResultsCached = static_cast<uint32_t>(result.GetInt(10));
    schedule.consecutiveFailures = static_cast<uint32_t>(result.GetInt(11));
    schedule.lastStatus = static_cast<HuntJobStatus>(result.GetInt(12));
    return schedule;
}

[[nodiscard]] json SerializeMatch(const HuntMatch& match)
{
    json node;
    node["eventId"] = match.eventId;
    node["ruleId"] = match.ruleId;
    node["ruleName"] = match.ruleName;
    node["severity"] = static_cast<int>(match.severity);
    node["mitreAttackId"] = match.mitreAttackId;
    node["description"] = match.description;
    node["matchTime"] = ToUnixSeconds(match.matchTime);
    node["eventTime"] = ToUnixSeconds(match.eventTime);
    node["processId"] = match.processId;
    node["processName"] = StringUtils::ToNarrow(match.processName);
    node["processPath"] = StringUtils::ToNarrow(match.processPath);
    node["userName"] = StringUtils::ToNarrow(match.userName);
    node["matchedFields"] = match.matchedFields;
    return node;
}

[[nodiscard]] HuntMatch DeserializeMatch(const json& node)
{
    HuntMatch match;
    match.eventId = node.value("eventId", uint64_t{0});
    match.ruleId = node.value("ruleId", std::string{});
    match.ruleName = node.value("ruleName", std::string{});
    match.severity = static_cast<RuleSeverity>(node.value("severity", 0));
    match.mitreAttackId = node.value("mitreAttackId", std::string{});
    match.description = node.value("description", std::string{});
    match.matchTime = FromUnixSeconds(node.value("matchTime", int64_t{0}));
    match.eventTime = FromUnixSeconds(node.value("eventTime", int64_t{0}));
    match.processId = node.value("processId", uint32_t{0});
    match.processName = StringUtils::ToWide(node.value("processName", std::string{}));
    match.processPath = StringUtils::ToWide(node.value("processPath", std::string{}));
    match.userName = StringUtils::ToWide(node.value("userName", std::string{}));
    if (node.contains("matchedFields") && node["matchedFields"].is_object()) {
        for (auto it = node["matchedFields"].begin(); it != node["matchedFields"].end(); ++it) {
            if (it.value().is_string()) {
                match.matchedFields.emplace(it.key(), it.value().get<std::string>());
            }
        }
    }
    return match;
}

[[nodiscard]] std::string SerializeHuntResult(const HuntResult& result)
{
    json node;
    node["queryOrRuleId"] = result.queryOrRuleId;
    node["queryOrRuleName"] = result.queryOrRuleName;
    node["totalMatches"] = result.totalMatches;
    node["hasMore"] = result.hasMore;
    node["executionTimeMs"] = result.executionTime.count();
    node["executedAt"] = ToUnixSeconds(result.executedAt);
    node["matches"] = json::array();

    for (const auto& match : result.matches) {
        node["matches"].push_back(SerializeMatch(match));
    }

    return node.dump();
}

[[nodiscard]] HuntResult DeserializeHuntResult(std::string_view rawJson)
{
    HuntResult result;
    if (rawJson.empty()) {
        return result;
    }

    try {
        const json parsed = json::parse(rawJson, nullptr, true, true);
        result.queryOrRuleId = parsed.value("queryOrRuleId", std::string{});
        result.queryOrRuleName = parsed.value("queryOrRuleName", std::string{});
        result.totalMatches = parsed.value("totalMatches", uint64_t{0});
        result.hasMore = parsed.value("hasMore", false);
        result.executionTime = std::chrono::milliseconds(parsed.value("executionTimeMs", int64_t{0}));
        result.executedAt = FromUnixSeconds(parsed.value("executedAt", int64_t{0}));
        if (parsed.contains("matches") && parsed["matches"].is_array()) {
            for (const auto& item : parsed["matches"]) {
                result.matches.push_back(DeserializeMatch(item));
            }
        }
    }
    catch (const std::exception& ex) {
        ShadowStrike::Utils::Logger::Warn("{} Failed to deserialize HuntResult JSON: {}", kLogPrefix, ex.what());
    }

    return result;
}

[[nodiscard]] HuntJobRecord RowToJobRecord(QueryResult& result)
{
    HuntJobRecord record;
    record.jobId = result.GetString(0);
    record.scheduleId = result.GetString(1);
    record.status = static_cast<HuntJobStatus>(result.GetInt(2));
    record.result = DeserializeHuntResult(result.GetString(3));
    record.errorMessage = result.GetString(4);
    record.startedAt = FromUnixSeconds(result.GetInt64(5));
    record.completedAt = FromUnixSeconds(result.GetInt64(6));
    return record;
}

[[nodiscard]] QueryField ParseQueryField(std::string_view fieldText)
{
    const std::string field = ToLowerCopy(fieldText);
    if (field == "timestamp") return QueryField::Timestamp;
    if (field == "category") return QueryField::Category;
    if (field == "severity") return QueryField::Severity;
    if (field == "process_id" || field == "processid" || field == "pid") return QueryField::ProcessId;
    if (field == "process_name" || field == "processname" || field == "image") return QueryField::ProcessName;
    if (field == "process_path" || field == "processpath") return QueryField::ProcessPath;
    if (field == "parent_process_id" || field == "parentprocessid" || field == "ppid") return QueryField::ParentProcessId;
    if (field == "user_name" || field == "username" || field == "user") return QueryField::UserName;
    if (field == "mitre_attack_id" || field == "mitreattackid") return QueryField::MitreAttackId;
    if (field == "source_ip" || field == "sourceip") return QueryField::SourceIP;
    if (field == "dest_ip" || field == "destip") return QueryField::DestIP;
    if (field == "dest_port" || field == "destport") return QueryField::DestPort;
    if (field == "file_path" || field == "filepath") return QueryField::FilePath;
    if (field == "file_hash" || field == "filehash") return QueryField::FileHash;
    if (field == "registry_key" || field == "registrykey") return QueryField::RegistryKey;
    if (field == "registry_value" || field == "registryvalue") return QueryField::RegistryValue;
    if (field == "domain_name" || field == "domainname") return QueryField::DomainName;
    return QueryField::CommandLine;
}

[[nodiscard]] QueryOperator ParseQueryOperator(std::string_view opText)
{
    const std::string op = ToLowerCopy(opText);
    if (op == "not_equals" || op == "notequals") return QueryOperator::NotEquals;
    if (op == "contains") return QueryOperator::Contains;
    if (op == "startswith") return QueryOperator::StartsWith;
    if (op == "endswith") return QueryOperator::EndsWith;
    if (op == "greater_than" || op == "greaterthan" || op == "gt") return QueryOperator::GreaterThan;
    if (op == "less_than" || op == "lessthan" || op == "lt") return QueryOperator::LessThan;
    if (op == "in") return QueryOperator::In;
    if (op == "regex" || op == "re") return QueryOperator::Regex;
    if (op == "exists") return QueryOperator::Exists;
    return QueryOperator::Equals;
}

[[nodiscard]] QueryValue ParseQueryValue(const json& value)
{
    if (value.is_string()) {
        return value.get<std::string>();
    }
    if (value.is_number_integer()) {
        return value.get<int64_t>();
    }
    if (value.is_number_unsigned()) {
        return value.get<uint64_t>();
    }
    if (value.is_number_float()) {
        return value.get<double>();
    }
    if (value.is_array()) {
        std::vector<std::string> values;
        values.reserve(value.size());
        for (const auto& item : value) {
            if (item.is_string()) {
                values.push_back(item.get<std::string>());
            } else if (item.is_number_integer()) {
                values.push_back(std::to_string(item.get<int64_t>()));
            }
        }
        return values;
    }
    return std::string{};
}

[[nodiscard]] std::optional<HuntQuery> ParseHuntQueryJson(const std::string& rawJson)
{
    if (rawJson.empty()) {
        return std::nullopt;
    }

    try {
        const json parsed = json::parse(rawJson, nullptr, true, true);
        if (!parsed.is_object()) {
            return std::nullopt;
        }

        HuntQuery query;
        query.name = parsed.value("name", std::string{});
        query.description = parsed.value("description", std::string{});
        query.logic = ToLowerCopy(parsed.value("logic", std::string{"and"})) == "or"
            ? QueryLogic::Or
            : QueryLogic::And;
        query.maxResults = parsed.value("maxResults", 10000u);
        query.offset = parsed.value("offset", 0u);

        if (parsed.contains("conditions") && parsed["conditions"].is_array()) {
            for (const auto& item : parsed["conditions"]) {
                if (!item.is_object()) {
                    continue;
                }

                QueryCondition condition;
                condition.field = ParseQueryField(item.value("field", std::string{}));
                condition.op = ParseQueryOperator(item.value("op", std::string{}));
                condition.negate = item.value("negate", false);
                condition.value = ParseQueryValue(item.contains("value") ? item["value"] : json{});
                query.conditions.push_back(std::move(condition));
            }
        }

        return query;
    }
    catch (const std::exception& ex) {
        ShadowStrike::Utils::Logger::Warn("{} Failed to parse scheduled HuntQuery JSON: {}", kLogPrefix, ex.what());
        return std::nullopt;
    }
}

[[nodiscard]] std::vector<std::string> QueryValueToStrings(const QueryValue& value)
{
    return std::visit(
        [](const auto& actual) -> std::vector<std::string> {
            using T = std::decay_t<decltype(actual)>;
            if constexpr (std::is_same_v<T, std::vector<std::string>>) {
                return actual;
            } else if constexpr (std::is_same_v<T, std::wstring>) {
                return {StringUtils::ToNarrow(actual)};
            } else if constexpr (std::is_same_v<T, std::string>) {
                return {actual};
            } else if constexpr (std::is_same_v<T, int64_t>) {
                return {std::to_string(actual)};
            } else if constexpr (std::is_same_v<T, uint64_t>) {
                return {std::to_string(actual)};
            } else if constexpr (std::is_same_v<T, double>) {
                return {std::format("{}", actual)};
            } else {
                return {};
            }
        },
        value);
}

[[nodiscard]] std::optional<int64_t> QueryValueToInt64(const QueryValue& value)
{
    return std::visit(
        [](const auto& actual) -> std::optional<int64_t> {
            using T = std::decay_t<decltype(actual)>;
            if constexpr (std::is_same_v<T, int64_t>) {
                return actual;
            } else if constexpr (std::is_same_v<T, uint64_t>) {
                if (actual > static_cast<uint64_t>(std::numeric_limits<int64_t>::max())) {
                    return std::nullopt;
                }
                return static_cast<int64_t>(actual);
            } else if constexpr (std::is_same_v<T, double>) {
                return static_cast<int64_t>(actual);
            } else if constexpr (std::is_same_v<T, std::string>) {
                try {
                    return std::stoll(actual);
                }
                catch (...) {
                    return std::nullopt;
                }
            } else if constexpr (std::is_same_v<T, std::wstring>) {
                try {
                    return std::stoll(StringUtils::ToNarrow(actual));
                }
                catch (...) {
                    return std::nullopt;
                }
            } else {
                return std::nullopt;
            }
        },
        value);
}

[[nodiscard]] std::string QueryValueToString(const QueryValue& value)
{
    const auto values = QueryValueToStrings(value);
    return values.empty() ? std::string{} : values.front();
}

[[nodiscard]] HuntResult ExecuteCustomQuery(const HuntQuery& query, std::string_view identity, std::string_view name)
{
    HuntResult result;
    result.queryOrRuleId = std::string(identity);
    result.queryOrRuleName = std::string(name);
    result.executedAt = Clock::now();

    const auto started = std::chrono::steady_clock::now();

    std::string sql =
        "SELECT event_id, timestamp_ns, category, severity, process_id, process_name, process_path, user_name, "
        "mitre_attack_id, payload_json, metadata_json FROM telemetry_events WHERE 1 = 1";
    std::vector<std::string> params;

    for (const auto& condition : query.conditions) {
        switch (condition.field) {
        case QueryField::ProcessId:
            if (const auto value = QueryValueToInt64(condition.value); value.has_value()) {
                sql += " AND process_id = ?";
                params.push_back(std::to_string(*value));
            }
            break;
        case QueryField::ProcessName:
            sql += " AND LOWER(process_name) LIKE ?";
            params.push_back(std::format("%{}%", ToLowerCopy(QueryValueToString(condition.value))));
            break;
        case QueryField::ProcessPath:
            sql += " AND LOWER(process_path) LIKE ?";
            params.push_back(std::format("%{}%", ToLowerCopy(QueryValueToString(condition.value))));
            break;
        case QueryField::MitreAttackId:
            sql += " AND LOWER(mitre_attack_id) LIKE ?";
            params.push_back(std::format("%{}%", ToLowerCopy(QueryValueToString(condition.value))));
            break;
        case QueryField::UserName:
            sql += " AND LOWER(user_name) LIKE ?";
            params.push_back(std::format("%{}%", ToLowerCopy(QueryValueToString(condition.value))));
            break;
        default:
            sql += " AND LOWER(payload_json) LIKE ?";
            params.push_back(std::format("%{}%", ToLowerCopy(QueryValueToString(condition.value))));
            break;
        }
    }

    sql += " ORDER BY timestamp_ns DESC;";

    DatabaseError dbError;
    QueryResult rows = DatabaseManager::Instance().QueryWithParamsVector(sql, params, &dbError);
    if (dbError.HasError()) {
        ShadowStrike::Utils::Logger::Error(
            "{} Scheduled custom query failed: {}",
            kLogPrefix,
            StringUtils::ToNarrow(dbError.message));
        result.executionTime = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - started);
        return result;
    }

    while (rows.Next()) {
        HuntMatch match;
        match.eventId = static_cast<uint64_t>(rows.GetInt64(0));
        match.ruleId = std::string(identity);
        match.ruleName = std::string(name);
        match.severity = RuleSeverity::Medium;
        match.mitreAttackId = rows.GetString(8);
        match.description = query.description;
        match.matchTime = Clock::now();
        match.eventTime = Clock::time_point(std::chrono::duration_cast<Clock::duration>(std::chrono::nanoseconds(rows.GetInt64(1))));
        match.processId = static_cast<uint32_t>(rows.GetInt(4));
        match.processName = StringUtils::ToWide(rows.GetString(5));
        match.processPath = StringUtils::ToWide(rows.GetString(6));
        match.userName = StringUtils::ToWide(rows.GetString(7));
        match.matchedFields.emplace("payload", rows.GetString(9));
        result.matches.push_back(std::move(match));
    }

    result.totalMatches = result.matches.size();
    if (query.maxResults > 0 && result.matches.size() > query.maxResults) {
        result.hasMore = true;
        result.matches.resize(query.maxResults);
    }
    result.executionTime = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - started);
    return result;
}

[[nodiscard]] Clock::time_point CalculateBaseNextRun(const ScheduledHunt& schedule, const Clock::time_point& from)
{
    switch (schedule.frequency) {
    case ScheduleFrequency::Once:
        return from;
    case ScheduleFrequency::Hourly:
        return from + std::chrono::hours(1);
    case ScheduleFrequency::Daily:
        return from + std::chrono::hours(24);
    case ScheduleFrequency::Weekly:
        return from + std::chrono::hours(24 * 7);
    case ScheduleFrequency::Custom:
    default:
        return from + std::max(std::chrono::seconds(1), schedule.customInterval);
    }
}

[[nodiscard]] Clock::time_point CalculateFailureBackoff(const ScheduledHunt& schedule, uint32_t failureCount, const Clock::time_point& from)
{
    std::chrono::seconds baseDelay = schedule.frequency == ScheduleFrequency::Custom
        ? std::max(std::chrono::seconds(30), schedule.customInterval)
        : std::chrono::minutes(5);

    for (uint32_t i = 1; i < failureCount; ++i) {
        if (baseDelay >= std::chrono::duration_cast<std::chrono::seconds>(kMaxBackoff / 2)) {
            baseDelay = std::chrono::duration_cast<std::chrono::seconds>(kMaxBackoff);
            break;
        }
        baseDelay *= 2;
    }

    if (baseDelay > std::chrono::duration_cast<std::chrono::seconds>(kMaxBackoff)) {
        baseDelay = std::chrono::duration_cast<std::chrono::seconds>(kMaxBackoff);
    }

    return from + baseDelay;
}

} // namespace

class HuntSchedulerImpl final {
public:
    [[nodiscard]] bool Initialize()
    {
        std::unique_lock lock(m_mutex);
        if (m_initialized) {
            return true;
        }

        if (!DatabaseManager::Instance().IsInitialized()) {
            ShadowStrike::Utils::Logger::Error("{} DatabaseManager is not initialized", kLogPrefix);
            return false;
        }

        if (!HuntRuleManager::Instance().IsInitialized()) {
            (void)HuntRuleManager::Instance().Initialize();
        }

        DatabaseError dbError;
        if (!DatabaseManager::Instance().Execute(std::string(kCreateSchedulesSql), &dbError) ||
            !DatabaseManager::Instance().Execute(std::string(kCreateJobHistorySql), &dbError) ||
            !DatabaseManager::Instance().Execute(std::string(kCreateSchedulerIndexSql), &dbError))
        {
            ShadowStrike::Utils::Logger::Error(
                "{} Failed to initialise scheduler schema: {}",
                kLogPrefix,
                StringUtils::ToNarrow(dbError.message));
            return false;
        }

        m_initialized = true;
        ShadowStrike::Utils::Logger::Info("{} Initialized", kLogPrefix);
        return true;
    }

    void Shutdown()
    {
        Stop();

        std::unique_lock lock(m_mutex);
        m_initialized = false;
        ShadowStrike::Utils::Logger::Info("{} Shutdown complete", kLogPrefix);
    }

    [[nodiscard]] bool IsInitialized() const noexcept
    {
        std::shared_lock lock(m_mutex);
        return m_initialized;
    }

    [[nodiscard]] bool ScheduleHunt(ScheduledHunt&& schedule)
    {
        std::unique_lock lock(m_mutex);
        if (!m_initialized) {
            return false;
        }

        const auto now = Clock::now();
        if (schedule.id.empty()) {
            schedule.id = std::format("schedule-{:016x}", Fnv1a64(std::format("{}|{}|{}", schedule.name, schedule.description, schedule.queryOrRuleId)));
        }
        if (IsDefaultTime(schedule.createdAt)) {
            schedule.createdAt = now;
        }
        if (IsDefaultTime(schedule.nextRunTime)) {
            schedule.nextRunTime = now;
        }
        if (schedule.maxResultsCached == 0) {
            schedule.maxResultsCached = 10000;
        }

        DatabaseError dbError;
        const bool success = DatabaseManager::Instance().ExecuteWithParams(
            kUpsertScheduleSql,
            &dbError,
            schedule.id,
            schedule.name,
            schedule.description,
            schedule.queryOrRuleId,
            static_cast<int>(schedule.frequency),
            static_cast<int64_t>(schedule.customInterval.count()),
            ToUnixSeconds(schedule.nextRunTime),
            ToUnixSeconds(schedule.lastRunTime),
            ToUnixSeconds(schedule.createdAt),
            schedule.enabled ? 1 : 0,
            static_cast<int>(schedule.maxResultsCached),
            static_cast<int>(schedule.consecutiveFailures),
            static_cast<int>(schedule.lastStatus));

        if (!success) {
            ShadowStrike::Utils::Logger::Error(
                "{} Failed to schedule hunt {}: {}",
                kLogPrefix,
                schedule.id,
                StringUtils::ToNarrow(dbError.message));
            return false;
        }

        SignalWorker();
        return true;
    }

    [[nodiscard]] bool CancelSchedule(const std::string& scheduleId)
    {
        std::unique_lock lock(m_mutex);
        if (!m_initialized || scheduleId.empty()) {
            return false;
        }

        DatabaseError dbError;
        const bool success = DatabaseManager::Instance().ExecuteWithParams(kDeleteScheduleSql, &dbError, scheduleId);
        if (success) {
            SignalWorker();
        } else {
            ShadowStrike::Utils::Logger::Error(
                "{} Failed to cancel schedule {}: {}",
                kLogPrefix,
                scheduleId,
                StringUtils::ToNarrow(dbError.message));
        }
        return success;
    }

    [[nodiscard]] bool PauseSchedule(const std::string& scheduleId)
    {
        std::unique_lock lock(m_mutex);
        if (!m_initialized || scheduleId.empty()) {
            return false;
        }

        DatabaseError dbError;
        return DatabaseManager::Instance().ExecuteWithParams(
            kUpdateScheduleStateSql,
            &dbError,
            0,
            ToUnixSeconds(Clock::now()),
            static_cast<int>(HuntJobStatus::Paused),
            scheduleId);
    }

    [[nodiscard]] bool ResumeSchedule(const std::string& scheduleId)
    {
        std::unique_lock lock(m_mutex);
        if (!m_initialized || scheduleId.empty()) {
            return false;
        }

        const auto schedule = GetScheduleUnlocked(scheduleId);
        if (!schedule.has_value()) {
            return false;
        }

        const auto nextRun = schedule->nextRunTime > Clock::now() ? schedule->nextRunTime : Clock::now();
        DatabaseError dbError;
        const bool success = DatabaseManager::Instance().ExecuteWithParams(
            kUpdateScheduleStateSql,
            &dbError,
            1,
            ToUnixSeconds(nextRun),
            static_cast<int>(HuntJobStatus::Pending),
            scheduleId);
        if (success) {
            SignalWorker();
        }
        return success;
    }

    [[nodiscard]] std::optional<ScheduledHunt> GetSchedule(const std::string& scheduleId)
    {
        std::shared_lock lock(m_mutex);
        return GetScheduleUnlocked(scheduleId);
    }

    [[nodiscard]] std::vector<ScheduledHunt> GetAllSchedules()
    {
        std::shared_lock lock(m_mutex);
        std::vector<ScheduledHunt> schedules;
        if (!m_initialized) {
            return schedules;
        }

        DatabaseError dbError;
        QueryResult rows = DatabaseManager::Instance().Query(kSelectAllSchedulesSql, &dbError);
        if (dbError.HasError()) {
            ShadowStrike::Utils::Logger::Error(
                "{} Failed to enumerate schedules: {}",
                kLogPrefix,
                StringUtils::ToNarrow(dbError.message));
            return schedules;
        }

        while (rows.Next()) {
            schedules.push_back(RowToSchedule(rows));
        }
        return schedules;
    }

    [[nodiscard]] std::vector<HuntJobRecord> GetJobHistory(const std::string& scheduleId, uint32_t maxRecords)
    {
        std::shared_lock lock(m_mutex);
        std::vector<HuntJobRecord> records;
        if (!m_initialized || scheduleId.empty()) {
            return records;
        }

        const uint32_t effectiveMax = std::clamp<uint32_t>(maxRecords, 1u, kMaxJobHistoryRecords);
        DatabaseError dbError;
        QueryResult rows = DatabaseManager::Instance().QueryWithParams(
            kSelectJobHistorySqlPrefix,
            &dbError,
            scheduleId,
            static_cast<int>(effectiveMax));

        if (dbError.HasError()) {
            ShadowStrike::Utils::Logger::Error(
                "{} Failed to load job history for {}: {}",
                kLogPrefix,
                scheduleId,
                StringUtils::ToNarrow(dbError.message));
            return records;
        }

        while (rows.Next()) {
            records.push_back(RowToJobRecord(rows));
        }
        return records;
    }

    [[nodiscard]] std::optional<HuntJobRecord> GetLatestJob(const std::string& scheduleId)
    {
        std::shared_lock lock(m_mutex);
        if (!m_initialized || scheduleId.empty()) {
            return std::nullopt;
        }

        DatabaseError dbError;
        QueryResult row = DatabaseManager::Instance().QueryWithParams(kSelectLatestJobSql, &dbError, scheduleId);
        if (dbError.HasError() || !row.Next()) {
            return std::nullopt;
        }
        return RowToJobRecord(row);
    }

    void Start()
    {
        std::unique_lock lock(m_workerMutex);
        if (m_workerThread.joinable()) {
            return;
        }

        m_workerExited = false;
        m_wakeRequested = false;
        m_workerThread = std::jthread([this](std::stop_token stopToken) {
            WorkerLoop(stopToken);
        });

        ShadowStrike::Utils::Logger::Info("{} Background scheduler started", kLogPrefix);
    }

    void Stop()
    {
        std::jthread worker;
        {
            std::unique_lock lock(m_workerMutex);
            if (!m_workerThread.joinable()) {
                return;
            }

            m_workerThread.request_stop();
            m_wakeRequested = true;
            m_workerCv.notify_all();

            if (!m_workerExitCv.wait_for(lock, std::chrono::seconds(5), [this] { return m_workerExited; })) {
                ShadowStrike::Utils::Logger::Error("{} Worker did not signal shutdown within 5 seconds", kLogPrefix);
            }

            worker = std::move(m_workerThread);
        }

        if (worker.joinable()) {
            worker.join();
        }

        ShadowStrike::Utils::Logger::Info("{} Background scheduler stopped", kLogPrefix);
    }

private:
    [[nodiscard]] std::optional<ScheduledHunt> GetScheduleUnlocked(const std::string& scheduleId)
    {
        if (!m_initialized || scheduleId.empty()) {
            return std::nullopt;
        }

        DatabaseError dbError;
        QueryResult row = DatabaseManager::Instance().QueryWithParams(kSelectScheduleSql, &dbError, scheduleId);
        if (dbError.HasError() || !row.Next()) {
            return std::nullopt;
        }
        return RowToSchedule(row);
    }

    void SignalWorker()
    {
        std::lock_guard lock(m_workerMutex);
        m_wakeRequested = true;
        m_workerCv.notify_all();
    }

    void WorkerLoop(std::stop_token stopToken)
    {
        ShadowStrike::Utils::Logger::Debug("{} Worker thread entered", kLogPrefix);

        while (!stopToken.stop_requested()) {
            ProcessDueSchedules();

            std::unique_lock lock(m_workerMutex);
            m_workerCv.wait_for(lock, kSchedulerPollInterval, [this, &stopToken] {
                return stopToken.stop_requested() || std::exchange(m_wakeRequested, false);
            });
        }

        {
            std::lock_guard lock(m_workerMutex);
            m_workerExited = true;
        }
        m_workerExitCv.notify_all();
        ShadowStrike::Utils::Logger::Debug("{} Worker thread exiting", kLogPrefix);
    }

    void ProcessDueSchedules()
    {
        std::vector<ScheduledHunt> dueSchedules;
        {
            std::shared_lock lock(m_mutex);
            if (!m_initialized) {
                return;
            }

            DatabaseError dbError;
            QueryResult rows = DatabaseManager::Instance().QueryWithParams(
                kSelectDueSchedulesSql,
                &dbError,
                ToUnixSeconds(Clock::now()));

            if (dbError.HasError()) {
                ShadowStrike::Utils::Logger::Error(
                    "{} Failed to load due schedules: {}",
                    kLogPrefix,
                    StringUtils::ToNarrow(dbError.message));
                return;
            }

            while (rows.Next()) {
                dueSchedules.push_back(RowToSchedule(rows));
            }
        }

        for (const auto& schedule : dueSchedules) {
            ExecuteSchedule(schedule);
        }
    }

    void ExecuteSchedule(ScheduledHunt schedule)
    {
        const auto startedAt = Clock::now();
        const std::string jobId = MakeJobId(schedule.id, startedAt);

        {
            DatabaseError dbError;
            (void)DatabaseManager::Instance().ExecuteWithParams(
                kInsertJobHistorySql,
                &dbError,
                jobId,
                schedule.id,
                static_cast<int>(HuntJobStatus::Running),
                std::string{},
                std::string{},
                ToUnixSeconds(startedAt),
                0);
            (void)DatabaseManager::Instance().ExecuteWithParams(
                kUpdateRunStateSql,
                &dbError,
                ToUnixSeconds(schedule.nextRunTime),
                ToUnixSeconds(schedule.lastRunTime),
                schedule.enabled ? 1 : 0,
                static_cast<int>(schedule.consecutiveFailures),
                static_cast<int>(HuntJobStatus::Running),
                schedule.id);
        }

        HuntResult result;
        HuntJobStatus finalStatus = HuntJobStatus::Completed;
        std::string errorMessage;

        try {
            const auto maybeRule = HuntRuleManager::Instance().GetRule(schedule.queryOrRuleId);
            if (maybeRule.has_value()) {
                result = HuntRuleManager::Instance().EvaluateRule(schedule.queryOrRuleId);
            } else {
                const auto query = ParseHuntQueryJson(schedule.queryOrRuleId);
                if (!query.has_value()) {
                    throw std::runtime_error("schedule payload is neither a known rule ID nor valid HuntQuery JSON");
                }
                result = ExecuteCustomQuery(*query, schedule.id, schedule.name);
            }
        }
        catch (const std::exception& ex) {
            finalStatus = HuntJobStatus::Failed;
            errorMessage = ex.what();
        }

        const auto completedAt = Clock::now();
        const bool success = finalStatus == HuntJobStatus::Completed;

        if (success) {
            schedule.consecutiveFailures = 0;
            schedule.lastStatus = HuntJobStatus::Completed;
            schedule.lastRunTime = completedAt;
            if (schedule.frequency == ScheduleFrequency::Once) {
                schedule.enabled = false;
                schedule.nextRunTime = completedAt;
            } else {
                schedule.nextRunTime = CalculateBaseNextRun(schedule, completedAt);
            }
        } else {
            ++schedule.consecutiveFailures;
            schedule.lastStatus = HuntJobStatus::Failed;
            schedule.lastRunTime = completedAt;
            schedule.nextRunTime = CalculateFailureBackoff(schedule, schedule.consecutiveFailures, completedAt);
        }

        DatabaseError dbError;
        (void)DatabaseManager::Instance().ExecuteWithParams(
            kUpdateJobHistorySql,
            &dbError,
            static_cast<int>(finalStatus),
            SerializeHuntResult(result),
            errorMessage,
            ToUnixSeconds(completedAt),
            jobId);

        (void)DatabaseManager::Instance().ExecuteWithParams(
            kUpdateRunStateSql,
            &dbError,
            ToUnixSeconds(schedule.nextRunTime),
            ToUnixSeconds(schedule.lastRunTime),
            schedule.enabled ? 1 : 0,
            static_cast<int>(schedule.consecutiveFailures),
            static_cast<int>(schedule.lastStatus),
            schedule.id);
    }

    mutable std::shared_mutex m_mutex;
    bool m_initialized = false;

    std::mutex m_workerMutex;
    std::condition_variable m_workerCv;
    std::condition_variable m_workerExitCv;
    std::jthread m_workerThread;
    bool m_workerExited = true;
    bool m_wakeRequested = false;
};

HuntScheduler::HuntScheduler()
    : m_impl(std::make_unique<HuntSchedulerImpl>())
{
}

HuntScheduler::~HuntScheduler()
{
    if (m_impl != nullptr && m_impl->IsInitialized()) {
        Shutdown();
    }
}

HuntScheduler& HuntScheduler::Instance()
{
    static HuntScheduler instance;
    return instance;
}

bool HuntScheduler::Initialize()
{
    return m_impl->Initialize();
}

void HuntScheduler::Shutdown()
{
    m_impl->Shutdown();
}

bool HuntScheduler::IsInitialized() const noexcept
{
    return m_impl->IsInitialized();
}

bool HuntScheduler::ScheduleHunt(ScheduledHunt&& schedule)
{
    return m_impl->ScheduleHunt(std::move(schedule));
}

bool HuntScheduler::CancelSchedule(const std::string& scheduleId)
{
    return m_impl->CancelSchedule(scheduleId);
}

bool HuntScheduler::PauseSchedule(const std::string& scheduleId)
{
    return m_impl->PauseSchedule(scheduleId);
}

bool HuntScheduler::ResumeSchedule(const std::string& scheduleId)
{
    return m_impl->ResumeSchedule(scheduleId);
}

std::optional<ScheduledHunt> HuntScheduler::GetSchedule(const std::string& scheduleId)
{
    return m_impl->GetSchedule(scheduleId);
}

std::vector<ScheduledHunt> HuntScheduler::GetAllSchedules()
{
    return m_impl->GetAllSchedules();
}

std::vector<HuntJobRecord> HuntScheduler::GetJobHistory(const std::string& scheduleId, uint32_t maxRecords)
{
    return m_impl->GetJobHistory(scheduleId, maxRecords);
}

std::optional<HuntJobRecord> HuntScheduler::GetLatestJob(const std::string& scheduleId)
{
    return m_impl->GetLatestJob(scheduleId);
}

void HuntScheduler::Start()
{
    m_impl->Start();
}

void HuntScheduler::Stop()
{
    m_impl->Stop();
}

} // namespace ShadowStrike::Products::PhantomEDR::ThreatHunting
