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
#include "pch.h"
#include "Products/Community/PhantomEDR/ThreatHunting/HuntQueryEngine.hpp"

#include "PhantomCore/Database/DatabaseManager.hpp"
#include "PhantomCore/Utils/Logger.hpp"
#include "PhantomCore/Utils/StringUtils.hpp"
#include "Products/Community/PhantomEDR/Telemetry/TelemetryTypes.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cctype>
#include <cmath>
#include <limits>
#include <optional>
#include <regex>
#include <shared_mutex>
#include <string_view>
#include <unordered_map>

namespace ShadowStrike::Products::PhantomEDR::ThreatHunting {

class HuntQueryEngineImpl final {
public:
    std::atomic<bool> initialized{ false };
    mutable std::shared_mutex mutex;
};

namespace {

using ShadowStrike::Database::DatabaseError;
using ShadowStrike::Database::DatabaseManager;
using ShadowStrike::Database::QueryResult;
using ShadowStrike::Utils::Logger;
namespace StringUtils = ShadowStrike::Utils::StringUtils;
namespace Telemetry = ShadowStrike::Products::PhantomEDR::Telemetry;

constexpr uint32_t kDefaultMaxResults = 10000;
constexpr uint32_t kMaxQueryResults = 100000;
constexpr uint32_t kPostFilterBatchSize = 2048;

struct EventRow final {
    uint64_t eventId = 0;
    int64_t timestampNs = 0;
    int category = 0;
    int severity = 0;
    uint32_t processId = 0;
    uint32_t parentProcessId = 0;
    uint32_t threadId = 0;
    std::string processName;
    std::string processPath;
    std::string userName;
    std::string sessionId;
    std::string mitreAttackId;
    std::string payloadJson;
    std::string metadataJson;
};

struct QueryPlan final {
    std::string whereClause;
    std::vector<std::string> params;
    std::vector<QueryCondition> postFilters;
};

[[nodiscard]] std::string ToLowerAscii(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](const unsigned char ch) {
        return static_cast<char>(std::tolower(ch));
    });
    return value;
}

[[nodiscard]] std::string TrimCopy(std::string_view value) {
    size_t start = 0;
    size_t end = value.size();
    while (start < end && std::isspace(static_cast<unsigned char>(value[start])) != 0) {
        ++start;
    }
    while (end > start && std::isspace(static_cast<unsigned char>(value[end - 1])) != 0) {
        --end;
    }
    return std::string(value.substr(start, end - start));
}

[[nodiscard]] std::string StripTrailingSemicolons(std::string sql) {
    while (!sql.empty() && (sql.back() == ';' || std::isspace(static_cast<unsigned char>(sql.back())) != 0)) {
        sql.pop_back();
    }
    return sql;
}

[[nodiscard]] int64_t ToEpochNanoseconds(const std::chrono::system_clock::time_point& timePoint) noexcept {
    return std::chrono::duration_cast<std::chrono::nanoseconds>(timePoint.time_since_epoch()).count();
}

[[nodiscard]] std::chrono::system_clock::time_point FromEpochNanoseconds(const int64_t ns) noexcept {
    return std::chrono::system_clock::time_point{
        std::chrono::duration_cast<std::chrono::system_clock::duration>(std::chrono::nanoseconds(ns))
    };
}

[[nodiscard]] std::string EscapeLikeValue(std::string_view value) {
    std::string escaped;
    escaped.reserve(value.size() + 8);
    for (const char ch : value) {
        if (ch == '\\' || ch == '%' || ch == '_') {
            escaped.push_back('\\');
        }
        escaped.push_back(ch);
    }
    return escaped;
}

[[nodiscard]] std::string MakeLikePattern(
    std::string_view value,
    const bool prefixWildcard,
    const bool suffixWildcard) {
    std::string pattern;
    pattern.reserve(value.size() + 4);
    if (prefixWildcard) {
        pattern.push_back('%');
    }
    pattern += EscapeLikeValue(value);
    if (suffixWildcard) {
        pattern.push_back('%');
    }
    return pattern;
}

[[nodiscard]] std::string QueryValueToString(const QueryValue& value) {
    return std::visit([](const auto& current) -> std::string {
        using CurrentType = std::decay_t<decltype(current)>;
        if constexpr (std::is_same_v<CurrentType, std::string>) {
            return current;
        } else if constexpr (std::is_same_v<CurrentType, std::wstring>) {
            return StringUtils::ToNarrow(current);
        } else if constexpr (std::is_same_v<CurrentType, int64_t>) {
            return std::to_string(current);
        } else if constexpr (std::is_same_v<CurrentType, uint64_t>) {
            return std::to_string(current);
        } else if constexpr (std::is_same_v<CurrentType, double>) {
            return std::to_string(current);
        } else {
            return current.empty() ? std::string{} : current.front();
        }
    }, value);
}

[[nodiscard]] std::vector<std::string> QueryValueToStrings(const QueryValue& value) {
    if (const auto* values = std::get_if<std::vector<std::string>>(&value)) {
        return *values;
    }
    return { QueryValueToString(value) };
}

[[nodiscard]] std::optional<double> TryParseDouble(const QueryValue& value) {
    return std::visit([](const auto& current) -> std::optional<double> {
        using CurrentType = std::decay_t<decltype(current)>;
        try {
            if constexpr (std::is_same_v<CurrentType, std::string>) {
                if (current.empty()) {
                    return std::nullopt;
                }
                return std::stod(current);
            } else if constexpr (std::is_same_v<CurrentType, std::wstring>) {
                if (current.empty()) {
                    return std::nullopt;
                }
                return std::stod(current);
            } else if constexpr (std::is_same_v<CurrentType, int64_t>) {
                return static_cast<double>(current);
            } else if constexpr (std::is_same_v<CurrentType, uint64_t>) {
                return static_cast<double>(current);
            } else if constexpr (std::is_same_v<CurrentType, double>) {
                return current;
            } else {
                if (current.empty()) {
                    return std::nullopt;
                }
                return std::stod(current.front());
            }
        } catch (...) {
            return std::nullopt;
        }
    }, value);
}

[[nodiscard]] std::optional<int64_t> TryParseInt64FromString(std::string_view value) {
    try {
        if (value.empty()) {
            return std::nullopt;
        }
        size_t consumed = 0;
        const auto parsed = std::stoll(std::string(value), &consumed, 10);
        if (consumed != value.size()) {
            return std::nullopt;
        }
        return parsed;
    } catch (...) {
        return std::nullopt;
    }
}

[[nodiscard]] std::optional<int64_t> TryMapCategoryValue(const QueryValue& value) {
    if (const auto numeric = TryParseDouble(value); numeric.has_value()) {
        return static_cast<int64_t>(*numeric);
    }

    const std::string text = ToLowerAscii(QueryValueToString(value));
    if (text == "process") return static_cast<int64_t>(Telemetry::EventCategory::Process);
    if (text == "file") return static_cast<int64_t>(Telemetry::EventCategory::File);
    if (text == "registry") return static_cast<int64_t>(Telemetry::EventCategory::Registry);
    if (text == "network") return static_cast<int64_t>(Telemetry::EventCategory::Network);
    if (text == "dns") return static_cast<int64_t>(Telemetry::EventCategory::DNS);
    if (text == "module") return static_cast<int64_t>(Telemetry::EventCategory::Module);
    if (text == "user") return static_cast<int64_t>(Telemetry::EventCategory::User);
    if (text == "service") return static_cast<int64_t>(Telemetry::EventCategory::Service);
    if (text == "wmi") return static_cast<int64_t>(Telemetry::EventCategory::WMI);
    if (text == "powershell") return static_cast<int64_t>(Telemetry::EventCategory::PowerShell);
    if (text == "amsi") return static_cast<int64_t>(Telemetry::EventCategory::AMSI);
    return std::nullopt;
}

[[nodiscard]] std::optional<int64_t> TryMapSeverityValue(const QueryValue& value) {
    if (const auto numeric = TryParseDouble(value); numeric.has_value()) {
        return static_cast<int64_t>(*numeric);
    }

    const std::string text = ToLowerAscii(QueryValueToString(value));
    if (text == "info" || text == "informational") return 0;
    if (text == "low") return 1;
    if (text == "medium") return 2;
    if (text == "high") return 3;
    if (text == "critical") return 4;
    return std::nullopt;
}

[[nodiscard]] std::optional<int64_t> ResolveNumericQueryValue(const QueryField field, const QueryValue& value) {
    switch (field) {
        case QueryField::Category:
            return TryMapCategoryValue(value);
        case QueryField::Severity:
            return TryMapSeverityValue(value);
        default: {
            if (const auto numeric = TryParseDouble(value); numeric.has_value()) {
                return static_cast<int64_t>(*numeric);
            }

            const auto raw = QueryValueToString(value);
            return TryParseInt64FromString(raw);
        }
    }
}

[[nodiscard]] std::string CategoryToString(const int category) {
    switch (static_cast<Telemetry::EventCategory>(category)) {
        case Telemetry::EventCategory::Process: return "process";
        case Telemetry::EventCategory::File: return "file";
        case Telemetry::EventCategory::Registry: return "registry";
        case Telemetry::EventCategory::Network: return "network";
        case Telemetry::EventCategory::DNS: return "dns";
        case Telemetry::EventCategory::Module: return "module";
        case Telemetry::EventCategory::User: return "user";
        case Telemetry::EventCategory::Service: return "service";
        case Telemetry::EventCategory::WMI: return "wmi";
        case Telemetry::EventCategory::PowerShell: return "powershell";
        case Telemetry::EventCategory::AMSI: return "amsi";
        default: return std::to_string(category);
    }
}

[[nodiscard]] std::string SeverityToString(const int severity) {
    switch (severity) {
        case 0: return "info";
        case 1: return "low";
        case 2: return "medium";
        case 3: return "high";
        case 4: return "critical";
        default: return std::to_string(severity);
    }
}

[[nodiscard]] RuleSeverity ToRuleSeverity(const int severity) noexcept {
    switch (severity) {
        case 0: return RuleSeverity::Informational;
        case 1: return RuleSeverity::Low;
        case 2: return RuleSeverity::Medium;
        case 3: return RuleSeverity::High;
        case 4: return RuleSeverity::Critical;
        default: return RuleSeverity::Medium;
    }
}

[[nodiscard]] EventRow ReadTelemetryRow(QueryResult& result) {
    EventRow row;
    row.eventId = static_cast<uint64_t>(std::max<int64_t>(0, result.GetInt64(0)));
    row.timestampNs = result.GetInt64(1);
    row.category = result.GetInt(2);
    row.severity = result.GetInt(3);
    row.processId = static_cast<uint32_t>(std::max(0, result.GetInt(4)));
    row.parentProcessId = static_cast<uint32_t>(std::max(0, result.GetInt(5)));
    row.threadId = static_cast<uint32_t>(std::max(0, result.GetInt(6)));
    row.processName = result.IsNull(7) ? std::string{} : result.GetString(7);
    row.processPath = result.IsNull(8) ? std::string{} : result.GetString(8);
    row.userName = result.IsNull(9) ? std::string{} : result.GetString(9);
    row.sessionId = result.IsNull(10) ? std::string{} : result.GetString(10);
    row.mitreAttackId = result.IsNull(11) ? std::string{} : result.GetString(11);
    row.payloadJson = result.IsNull(12) ? std::string{} : result.GetString(12);
    row.metadataJson = result.IsNull(13) ? std::string{} : result.GetString(13);
    return row;
}

[[nodiscard]] std::string GetFieldText(const EventRow& row, const QueryField field) {
    switch (field) {
        case QueryField::Timestamp: return std::to_string(row.timestampNs);
        case QueryField::Category: return CategoryToString(row.category);
        case QueryField::Severity: return SeverityToString(row.severity);
        case QueryField::ProcessId: return std::to_string(row.processId);
        case QueryField::ProcessName: return row.processName;
        case QueryField::ProcessPath: return row.processPath;
        case QueryField::ParentProcessId: return std::to_string(row.parentProcessId);
        case QueryField::UserName: return row.userName;
        case QueryField::MitreAttackId: return row.mitreAttackId;
        case QueryField::SourceIP:
        case QueryField::DestIP:
        case QueryField::DestPort:
        case QueryField::FilePath:
        case QueryField::FileHash:
        case QueryField::RegistryKey:
        case QueryField::RegistryValue:
        case QueryField::DomainName:
        case QueryField::CommandLine:
            return row.payloadJson + '\n' + row.metadataJson;
    }
    return {};
}

[[nodiscard]] bool EvaluateStringOperator(
    const std::string& actual,
    const QueryOperator op,
    const QueryValue& value) {
    const std::string left = ToLowerAscii(actual);

    switch (op) {
        case QueryOperator::Equals:
            return left == ToLowerAscii(QueryValueToString(value));
        case QueryOperator::NotEquals:
            return left != ToLowerAscii(QueryValueToString(value));
        case QueryOperator::Contains:
            return left.find(ToLowerAscii(QueryValueToString(value))) != std::string::npos;
        case QueryOperator::StartsWith: {
            const std::string needle = ToLowerAscii(QueryValueToString(value));
            return left.rfind(needle, 0) == 0;
        }
        case QueryOperator::EndsWith: {
            const std::string needle = ToLowerAscii(QueryValueToString(value));
            return left.size() >= needle.size()
                && left.compare(left.size() - needle.size(), needle.size(), needle) == 0;
        }
        case QueryOperator::Regex: {
            try {
                const std::regex pattern(QueryValueToString(value), std::regex::ECMAScript | std::regex::icase);
                return std::regex_search(actual, pattern);
            } catch (...) {
                return false;
            }
        }
        case QueryOperator::Exists:
            return !actual.empty();
        case QueryOperator::In: {
            for (const auto& candidate : QueryValueToStrings(value)) {
                if (left == ToLowerAscii(candidate)) {
                    return true;
                }
            }
            return false;
        }
        default:
            return false;
    }
}

[[nodiscard]] bool EvaluateNumericOperator(
    const int64_t actual,
    const QueryOperator op,
    const QueryValue& value,
    const QueryField field) {
    if (op == QueryOperator::Exists) {
        return true;
    }

    if (op == QueryOperator::In) {
        for (const auto& candidate : QueryValueToStrings(value)) {
            if (const auto numeric = ResolveNumericQueryValue(field, QueryValue{ candidate });
                numeric.has_value() && *numeric == actual) {
                return true;
            }
        }
        return false;
    }

    const auto numeric = ResolveNumericQueryValue(field, value);
    if (!numeric.has_value()) {
        return false;
    }

    switch (op) {
        case QueryOperator::Equals: return actual == *numeric;
        case QueryOperator::NotEquals: return actual != *numeric;
        case QueryOperator::GreaterThan: return actual > *numeric;
        case QueryOperator::LessThan: return actual < *numeric;
        case QueryOperator::Contains:
        case QueryOperator::StartsWith:
        case QueryOperator::EndsWith:
        case QueryOperator::Regex:
            return EvaluateStringOperator(std::to_string(actual), op, value);
        default:
            return false;
    }
}

[[nodiscard]] bool IsNumericField(const QueryField field) noexcept {
    switch (field) {
        case QueryField::Timestamp:
        case QueryField::Category:
        case QueryField::Severity:
        case QueryField::ProcessId:
        case QueryField::ParentProcessId:
        case QueryField::DestPort:
            return true;
        default:
            return false;
    }
}

[[nodiscard]] bool EvaluateCondition(const EventRow& row, const QueryCondition& condition) {
    bool matched = false;
    if (IsNumericField(condition.field)) {
        int64_t actual = 0;
        switch (condition.field) {
            case QueryField::Timestamp: actual = row.timestampNs; break;
            case QueryField::Category: actual = row.category; break;
            case QueryField::Severity: actual = row.severity; break;
            case QueryField::ProcessId: actual = row.processId; break;
            case QueryField::ParentProcessId: actual = row.parentProcessId; break;
            case QueryField::DestPort: {
                const std::string joined = row.payloadJson + '\n' + row.metadataJson;
                const auto parsed = TryParseInt64FromString(joined);
                actual = parsed.value_or(0);
                break;
            }
            default: break;
        }
        matched = EvaluateNumericOperator(actual, condition.op, condition.value, condition.field);
    } else {
        matched = EvaluateStringOperator(GetFieldText(row, condition.field), condition.op, condition.value);
    }

    return condition.negate ? !matched : matched;
}

[[nodiscard]] bool EvaluateQuery(const EventRow& row, const HuntQuery& query) {
    if (query.conditions.empty()) {
        return true;
    }

    if (query.logic == QueryLogic::And) {
        return std::ranges::all_of(query.conditions, [&](const QueryCondition& condition) {
            return EvaluateCondition(row, condition);
        });
    }

    return std::ranges::any_of(query.conditions, [&](const QueryCondition& condition) {
        return EvaluateCondition(row, condition);
    });
}

void AddMatchedField(HuntMatch& match, const EventRow& row, const QueryField field) {
    const auto setIfNotEmpty = [&](std::string key, const std::string& value) {
        if (!value.empty()) {
            match.matchedFields.emplace(std::move(key), value);
        }
    };

    switch (field) {
        case QueryField::Timestamp:
            setIfNotEmpty("timestamp_ns", std::to_string(row.timestampNs));
            break;
        case QueryField::Category:
            setIfNotEmpty("category", CategoryToString(row.category));
            break;
        case QueryField::Severity:
            setIfNotEmpty("severity", SeverityToString(row.severity));
            break;
        case QueryField::ProcessId:
            setIfNotEmpty("process_id", std::to_string(row.processId));
            break;
        case QueryField::ProcessName:
            setIfNotEmpty("process_name", row.processName);
            break;
        case QueryField::ProcessPath:
            setIfNotEmpty("process_path", row.processPath);
            break;
        case QueryField::ParentProcessId:
            setIfNotEmpty("parent_process_id", std::to_string(row.parentProcessId));
            break;
        case QueryField::UserName:
            setIfNotEmpty("user_name", row.userName);
            break;
        case QueryField::MitreAttackId:
            setIfNotEmpty("mitre_attack_id", row.mitreAttackId);
            break;
        case QueryField::SourceIP:
            setIfNotEmpty("source_ip", row.payloadJson);
            break;
        case QueryField::DestIP:
            setIfNotEmpty("dest_ip", row.payloadJson);
            break;
        case QueryField::DestPort:
            setIfNotEmpty("dest_port", row.payloadJson);
            break;
        case QueryField::FilePath:
            setIfNotEmpty("file_path", row.payloadJson);
            break;
        case QueryField::FileHash:
            setIfNotEmpty("file_hash", row.payloadJson);
            break;
        case QueryField::RegistryKey:
            setIfNotEmpty("registry_key", row.payloadJson);
            break;
        case QueryField::RegistryValue:
            setIfNotEmpty("registry_value", row.payloadJson);
            break;
        case QueryField::DomainName:
            setIfNotEmpty("domain_name", row.payloadJson);
            break;
        case QueryField::CommandLine:
            setIfNotEmpty("command_line", row.payloadJson);
            break;
    }
}

[[nodiscard]] HuntMatch MakeHuntMatch(
    const EventRow& row,
    const HuntQuery& query,
    const std::chrono::system_clock::time_point executedAt) {
    HuntMatch match;
    match.eventId = row.eventId;
    match.ruleId = query.name.empty() ? "adhoc-hunt-query" : query.name;
    match.ruleName = query.name.empty() ? "AdHoc Hunt Query" : query.name;
    match.severity = ToRuleSeverity(row.severity);
    match.mitreAttackId = row.mitreAttackId;
    match.description = std::format("Telemetry hunt match in category {}", CategoryToString(row.category));
    match.matchTime = executedAt;
    match.eventTime = FromEpochNanoseconds(row.timestampNs);
    match.processId = row.processId;
    match.processName = StringUtils::ToWide(row.processName);
    match.processPath = StringUtils::ToWide(row.processPath);
    match.userName = StringUtils::ToWide(row.userName);

    for (const auto& condition : query.conditions) {
        if (EvaluateCondition(row, condition)) {
            AddMatchedField(match, row, condition.field);
        }
    }

    if (match.matchedFields.empty()) {
        AddMatchedField(match, row, QueryField::ProcessName);
        AddMatchedField(match, row, QueryField::UserName);
        AddMatchedField(match, row, QueryField::MitreAttackId);
    }

    return match;
}

[[nodiscard]] std::string MakeBaseSelectSql(const std::string& whereClause) {
    return
        "SELECT event_id, timestamp_ns, category, severity, process_id, parent_process_id, thread_id, "
        "process_name, process_path, user_name, session_id, mitre_attack_id, payload_json, metadata_json "
        "FROM telemetry_events" + whereClause + " ORDER BY timestamp_ns DESC";
}

[[nodiscard]] bool IsDirectColumnField(const QueryField field) noexcept {
    switch (field) {
        case QueryField::Timestamp:
        case QueryField::Category:
        case QueryField::Severity:
        case QueryField::ProcessId:
        case QueryField::ProcessName:
        case QueryField::ProcessPath:
        case QueryField::ParentProcessId:
        case QueryField::UserName:
        case QueryField::MitreAttackId:
            return true;
        default:
            return false;
    }
}

[[nodiscard]] std::string DirectColumnName(const QueryField field) {
    switch (field) {
        case QueryField::Timestamp: return "timestamp_ns";
        case QueryField::Category: return "category";
        case QueryField::Severity: return "severity";
        case QueryField::ProcessId: return "process_id";
        case QueryField::ProcessName: return "process_name";
        case QueryField::ProcessPath: return "process_path";
        case QueryField::ParentProcessId: return "parent_process_id";
        case QueryField::UserName: return "user_name";
        case QueryField::MitreAttackId: return "mitre_attack_id";
        default: return {};
    }
}

[[nodiscard]] std::string JsonBlobPredicate(const QueryOperator op) {
    switch (op) {
        case QueryOperator::Exists:
            return "((payload_json IS NOT NULL AND payload_json <> '') OR (metadata_json IS NOT NULL AND metadata_json <> ''))";
        case QueryOperator::Regex:
            return "((payload_json IS NOT NULL AND payload_json <> '') OR (metadata_json IS NOT NULL AND metadata_json <> ''))";
        default:
            return "(payload_json LIKE ? ESCAPE '\\' OR metadata_json LIKE ? ESCAPE '\\')";
    }
}

void AppendWhereFragment(QueryPlan& plan, const std::string& fragment) {
    plan.whereClause += plan.whereClause.empty() ? " WHERE " : " AND ";
    plan.whereClause += fragment;
}

void AppendFieldCondition(QueryPlan& plan, const QueryCondition& condition) {
    const auto appendPredicate = [&](std::string predicate, std::vector<std::string> params) {
        if (condition.negate && condition.op != QueryOperator::NotEquals) {
            predicate = "NOT (" + predicate + ")";
        }
        AppendWhereFragment(plan, predicate);
        for (auto& param : params) {
            plan.params.emplace_back(std::move(param));
        }
    };

    if (condition.op == QueryOperator::Regex) {
        if (IsDirectColumnField(condition.field)) {
            appendPredicate(DirectColumnName(condition.field) + " IS NOT NULL", {});
        } else {
            appendPredicate(JsonBlobPredicate(condition.op), {});
        }
        plan.postFilters.push_back(condition);
        return;
    }

    if (IsDirectColumnField(condition.field)) {
        const std::string column = DirectColumnName(condition.field);
        const bool numeric = IsNumericField(condition.field);
        const auto rawValue = QueryValueToString(condition.value);

        switch (condition.op) {
            case QueryOperator::Equals:
            case QueryOperator::NotEquals: {
                if (numeric) {
                    const auto numericValue = ResolveNumericQueryValue(condition.field, condition.value);
                    if (!numericValue.has_value()) {
                        plan.postFilters.push_back(condition);
                        return;
                    }
                    appendPredicate(column + (condition.op == QueryOperator::Equals ? " = ?" : " <> ?"),
                        { std::to_string(*numericValue) });
                } else {
                    appendPredicate(column + (condition.op == QueryOperator::Equals ? " = ? COLLATE NOCASE" : " <> ? COLLATE NOCASE"),
                        { rawValue });
                }
                return;
            }
            case QueryOperator::Contains:
                appendPredicate((numeric ? "CAST(" + column + " AS TEXT)" : column) + " LIKE ? ESCAPE '\\'",
                    { MakeLikePattern(rawValue, true, true) });
                return;
            case QueryOperator::StartsWith:
                appendPredicate((numeric ? "CAST(" + column + " AS TEXT)" : column) + " LIKE ? ESCAPE '\\'",
                    { MakeLikePattern(rawValue, false, true) });
                return;
            case QueryOperator::EndsWith:
                appendPredicate((numeric ? "CAST(" + column + " AS TEXT)" : column) + " LIKE ? ESCAPE '\\'",
                    { MakeLikePattern(rawValue, true, false) });
                return;
            case QueryOperator::GreaterThan:
            case QueryOperator::LessThan: {
                if (!numeric) {
                    plan.postFilters.push_back(condition);
                    return;
                }
                const auto numericValue = ResolveNumericQueryValue(condition.field, condition.value);
                if (!numericValue.has_value()) {
                    plan.postFilters.push_back(condition);
                    return;
                }
                appendPredicate(column + (condition.op == QueryOperator::GreaterThan ? " > ?" : " < ?"),
                    { std::to_string(*numericValue) });
                return;
            }
            case QueryOperator::In: {
                const auto values = QueryValueToStrings(condition.value);
                if (values.empty()) {
                    return;
                }

                std::string placeholders;
                std::vector<std::string> params;
                params.reserve(values.size());
                for (size_t index = 0; index < values.size(); ++index) {
                    if (!placeholders.empty()) {
                        placeholders += ", ";
                    }
                    placeholders += '?';
                    if (numeric) {
                        const auto numericValue = ResolveNumericQueryValue(condition.field, QueryValue{ values[index] });
                        if (!numericValue.has_value()) {
                            plan.postFilters.push_back(condition);
                            return;
                        }
                        params.push_back(std::to_string(*numericValue));
                    } else {
                        params.push_back(values[index]);
                    }
                }
                appendPredicate(column + " IN (" + placeholders + ")", std::move(params));
                return;
            }
            case QueryOperator::Exists:
                appendPredicate(column + " IS NOT NULL", {});
                return;
            case QueryOperator::Regex:
                break;
        }
    }

    const auto rawValue = QueryValueToString(condition.value);
    switch (condition.op) {
        case QueryOperator::Equals:
        case QueryOperator::Contains:
            appendPredicate(JsonBlobPredicate(QueryOperator::Contains),
                { MakeLikePattern(rawValue, true, true), MakeLikePattern(rawValue, true, true) });
            return;
        case QueryOperator::NotEquals: {
            std::string predicate = JsonBlobPredicate(QueryOperator::Contains);
            appendPredicate("NOT " + predicate,
                { MakeLikePattern(rawValue, true, true), MakeLikePattern(rawValue, true, true) });
            return;
        }
        case QueryOperator::StartsWith:
            appendPredicate(JsonBlobPredicate(QueryOperator::Contains),
                { MakeLikePattern(rawValue, false, true), MakeLikePattern(rawValue, false, true) });
            return;
        case QueryOperator::EndsWith:
            appendPredicate(JsonBlobPredicate(QueryOperator::Contains),
                { MakeLikePattern(rawValue, true, false), MakeLikePattern(rawValue, true, false) });
            return;
        case QueryOperator::In: {
            const auto values = QueryValueToStrings(condition.value);
            if (values.empty()) {
                return;
            }
            std::string predicate;
            std::vector<std::string> params;
            params.reserve(values.size() * 2);
            for (const auto& current : values) {
                if (!predicate.empty()) {
                    predicate += " OR ";
                }
                predicate += JsonBlobPredicate(QueryOperator::Contains);
                params.push_back(MakeLikePattern(current, true, true));
                params.push_back(MakeLikePattern(current, true, true));
            }
            appendPredicate('(' + predicate + ')', std::move(params));
            return;
        }
        case QueryOperator::Exists:
            appendPredicate(JsonBlobPredicate(QueryOperator::Exists), {});
            return;
        case QueryOperator::GreaterThan:
        case QueryOperator::LessThan:
        case QueryOperator::Regex:
            plan.postFilters.push_back(condition);
            return;
    }
}

[[nodiscard]] QueryPlan BuildQueryPlan(const HuntQuery& query) {
    QueryPlan plan;
    for (const auto& condition : query.conditions) {
        AppendFieldCondition(plan, condition);
    }

    if (query.startTime != std::chrono::system_clock::time_point{}) {
        AppendWhereFragment(plan, "timestamp_ns >= ?");
        plan.params.push_back(std::to_string(ToEpochNanoseconds(query.startTime)));
    }

    if (query.endTime != std::chrono::system_clock::time_point{}) {
        AppendWhereFragment(plan, "timestamp_ns <= ?");
        plan.params.push_back(std::to_string(ToEpochNanoseconds(query.endTime)));
    }

    return plan;
}

[[nodiscard]] uint32_t SanitizeMaxResults(const uint32_t requested) noexcept {
    const uint32_t nonZero = requested == 0 ? kDefaultMaxResults : requested;
    return std::min(nonZero, kMaxQueryResults);
}

[[nodiscard]] std::unordered_map<std::string, int> BuildColumnLookup(QueryResult& result) {
    std::unordered_map<std::string, int> columns;
    const int columnCount = result.ColumnCount();
    columns.reserve(static_cast<size_t>(std::max(columnCount, 0)));
    for (int index = 0; index < columnCount; ++index) {
        columns.emplace(ToLowerAscii(StringUtils::ToNarrow(result.ColumnName(index))), index);
    }
    return columns;
}

[[nodiscard]] int ColumnIndexOrDefault(
    const std::unordered_map<std::string, int>& columns,
    std::string_view name,
    const int fallback = -1) {
    const auto it = columns.find(ToLowerAscii(std::string(name)));
    return it == columns.end() ? fallback : it->second;
}

[[nodiscard]] HuntMatch MakeRawSqlMatch(
    QueryResult& result,
    const std::unordered_map<std::string, int>& columns,
    const std::chrono::system_clock::time_point executedAt) {
    HuntMatch match;
    match.ruleId = "raw-sql";
    match.ruleName = "Raw SQL";
    match.matchTime = executedAt;

    const int eventIdIndex = ColumnIndexOrDefault(columns, "event_id");
    const int timestampIndex = ColumnIndexOrDefault(columns, "timestamp_ns", ColumnIndexOrDefault(columns, "timestamp"));
    const int severityIndex = ColumnIndexOrDefault(columns, "severity");
    const int processIdIndex = ColumnIndexOrDefault(columns, "process_id");
    const int processNameIndex = ColumnIndexOrDefault(columns, "process_name");
    const int processPathIndex = ColumnIndexOrDefault(columns, "process_path");
    const int userNameIndex = ColumnIndexOrDefault(columns, "user_name");
    const int mitreIndex = ColumnIndexOrDefault(columns, "mitre_attack_id");

    if (eventIdIndex >= 0 && !result.IsNull(eventIdIndex)) {
        match.eventId = static_cast<uint64_t>(std::max<int64_t>(0, result.GetInt64(eventIdIndex)));
    }
    if (timestampIndex >= 0 && !result.IsNull(timestampIndex)) {
        const int64_t rawTimestamp = result.GetInt64(timestampIndex);
        match.eventTime = FromEpochNanoseconds(rawTimestamp);
    }
    if (severityIndex >= 0 && !result.IsNull(severityIndex)) {
        match.severity = ToRuleSeverity(result.GetInt(severityIndex));
    }
    if (processIdIndex >= 0 && !result.IsNull(processIdIndex)) {
        match.processId = static_cast<uint32_t>(std::max(0, result.GetInt(processIdIndex)));
    }
    if (processNameIndex >= 0 && !result.IsNull(processNameIndex)) {
        match.processName = StringUtils::ToWide(result.GetString(processNameIndex));
    }
    if (processPathIndex >= 0 && !result.IsNull(processPathIndex)) {
        match.processPath = StringUtils::ToWide(result.GetString(processPathIndex));
    }
    if (userNameIndex >= 0 && !result.IsNull(userNameIndex)) {
        match.userName = StringUtils::ToWide(result.GetString(userNameIndex));
    }
    if (mitreIndex >= 0 && !result.IsNull(mitreIndex)) {
        match.mitreAttackId = result.GetString(mitreIndex);
    }

    const int columnCount = result.ColumnCount();
    for (int index = 0; index < columnCount; ++index) {
        const std::string columnName = StringUtils::ToNarrow(result.ColumnName(index));
        if (result.IsNull(index)) {
            continue;
        }

        if (result.GetColumnType(index) == SQLITE_INTEGER) {
            match.matchedFields.emplace(columnName, std::to_string(result.GetInt64(index)));
        } else {
            match.matchedFields.emplace(columnName, result.GetString(index));
        }
    }

    match.description = "Raw telemetry SQL result";
    return match;
}

} // namespace

HuntQueryEngine::HuntQueryEngine()
    : m_impl(std::make_unique<HuntQueryEngineImpl>()) {
}

HuntQueryEngine::~HuntQueryEngine() = default;

HuntQueryEngine& HuntQueryEngine::Instance() {
    static HuntQueryEngine instance;
    return instance;
}

bool HuntQueryEngine::Initialize() {
    std::unique_lock lock(m_impl->mutex);
    if (m_impl->initialized.load(std::memory_order_acquire)) {
        return true;
    }

    m_impl->initialized.store(true, std::memory_order_release);
    Logger::Info("HuntQueryEngine: initialized");
    return true;
}

void HuntQueryEngine::Shutdown() {
    std::unique_lock lock(m_impl->mutex);
    m_impl->initialized.store(false, std::memory_order_release);
    Logger::Info("HuntQueryEngine: shutdown complete");
}

bool HuntQueryEngine::IsInitialized() const noexcept {
    return m_impl->initialized.load(std::memory_order_acquire);
}

HuntResult HuntQueryEngine::ExecuteQuery(const HuntQuery& query) {
    const auto started = std::chrono::steady_clock::now();
    const auto executedAt = std::chrono::system_clock::now();

    HuntResult result;
    result.queryOrRuleId = query.name.empty() ? "adhoc-hunt-query" : query.name;
    result.queryOrRuleName = query.name.empty() ? "AdHoc Hunt Query" : query.name;
    result.executedAt = executedAt;

    std::shared_lock lock(m_impl->mutex);
    if (!m_impl->initialized.load(std::memory_order_acquire)) {
        Logger::Warn("HuntQueryEngine: ExecuteQuery requested before initialization");
        result.executionTime = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - started);
        return result;
    }

    const QueryPlan plan = BuildQueryPlan(query);
    const uint32_t effectiveMax = SanitizeMaxResults(query.maxResults);
    DatabaseError error{};

    if (plan.postFilters.empty()) {
        const auto countSql = std::string("SELECT COUNT(*) FROM telemetry_events") + plan.whereClause + ';';
        auto countResult = DatabaseManager::Instance().QueryWithParamsVector(countSql, plan.params, &error);
        if (error.HasError()) {
            Logger::Error("HuntQueryEngine: count query failed context={} code={} msg={}",
                StringUtils::ToNarrow(error.context), error.sqliteCode, StringUtils::ToNarrow(error.message));
            result.executionTime = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - started);
            return result;
        }

        if (countResult.Next()) {
            result.totalMatches = static_cast<uint64_t>(std::max<int64_t>(0, countResult.GetInt64(0)));
        }

        auto params = plan.params;
        params.push_back(std::to_string(effectiveMax));
        params.push_back(std::to_string(query.offset));
        auto dataResult = DatabaseManager::Instance().QueryWithParamsVector(
            MakeBaseSelectSql(plan.whereClause) + " LIMIT ? OFFSET ?;",
            params,
            &error);

        if (error.HasError()) {
            Logger::Error("HuntQueryEngine: data query failed context={} code={} msg={}",
                StringUtils::ToNarrow(error.context), error.sqliteCode, StringUtils::ToNarrow(error.message));
            result.executionTime = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - started);
            return result;
        }

        result.matches.reserve(static_cast<size_t>(std::min<uint64_t>(result.totalMatches, effectiveMax)));
        while (dataResult.Next()) {
            result.matches.emplace_back(MakeHuntMatch(ReadTelemetryRow(dataResult), query, executedAt));
        }
        result.hasMore = result.totalMatches > static_cast<uint64_t>(query.offset) + result.matches.size();
    } else {
        uint64_t matchedCount = 0;
        uint32_t rawOffset = 0;
        bool exhausted = false;

        while (!exhausted) {
            auto params = plan.params;
            params.push_back(std::to_string(kPostFilterBatchSize));
            params.push_back(std::to_string(rawOffset));
            auto pageResult = DatabaseManager::Instance().QueryWithParamsVector(
                MakeBaseSelectSql(plan.whereClause) + " LIMIT ? OFFSET ?;",
                params,
                &error);

            if (error.HasError()) {
                Logger::Error("HuntQueryEngine: post-filter query failed context={} code={} msg={}",
                    StringUtils::ToNarrow(error.context), error.sqliteCode, StringUtils::ToNarrow(error.message));
                break;
            }

            uint32_t rowsRead = 0;
            while (pageResult.Next()) {
                ++rowsRead;
                const EventRow row = ReadTelemetryRow(pageResult);
                if (!EvaluateQuery(row, query)) {
                    continue;
                }

                if (matchedCount >= query.offset && result.matches.size() < effectiveMax) {
                    result.matches.emplace_back(MakeHuntMatch(row, query, executedAt));
                }
                ++matchedCount;
            }

            if (rowsRead < kPostFilterBatchSize) {
                exhausted = true;
            } else {
                rawOffset += rowsRead;
            }
        }

        result.totalMatches = matchedCount;
        result.hasMore = matchedCount > static_cast<uint64_t>(query.offset) + result.matches.size();
    }

    result.executionTime = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - started);
    Logger::Debug("HuntQueryEngine: ExecuteQuery completed name={} totalMatches={} returned={} durationMs={}",
        result.queryOrRuleName, result.totalMatches, result.matches.size(), result.executionTime.count());
    return result;
}

HuntResult HuntQueryEngine::ExecuteRawSQL(std::string_view sql, const uint32_t maxResults) {
    const auto started = std::chrono::steady_clock::now();
    const auto executedAt = std::chrono::system_clock::now();

    HuntResult result;
    result.queryOrRuleId = "raw-sql";
    result.queryOrRuleName = "Raw SQL";
    result.executedAt = executedAt;

    std::shared_lock lock(m_impl->mutex);
    if (!m_impl->initialized.load(std::memory_order_acquire)) {
        Logger::Warn("HuntQueryEngine: ExecuteRawSQL requested before initialization");
        result.executionTime = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - started);
        return result;
    }

    std::string normalizedSql = StripTrailingSemicolons(TrimCopy(sql));
    const std::string lowered = ToLowerAscii(normalizedSql);
    if (!(lowered.starts_with("select ") || lowered.starts_with("with "))) {
        Logger::Error("HuntQueryEngine: ExecuteRawSQL rejected non-read-only SQL");
        result.executionTime = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - started);
        return result;
    }

    const uint32_t effectiveMax = SanitizeMaxResults(maxResults);
    DatabaseError error{};

    auto countResult = DatabaseManager::Instance().QueryWithParamsVector(
        "SELECT COUNT(*) FROM (" + normalizedSql + ") AS raw_query;",
        {},
        &error);
    if (error.HasError()) {
        Logger::Error("HuntQueryEngine: raw count query failed context={} code={} msg={}",
            StringUtils::ToNarrow(error.context), error.sqliteCode, StringUtils::ToNarrow(error.message));
        result.executionTime = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - started);
        return result;
    }

    if (countResult.Next()) {
        result.totalMatches = static_cast<uint64_t>(std::max<int64_t>(0, countResult.GetInt64(0)));
    }

    auto dataResult = DatabaseManager::Instance().QueryWithParamsVector(
        "SELECT * FROM (" + normalizedSql + ") AS raw_query LIMIT ?;",
        { std::to_string(effectiveMax) },
        &error);
    if (error.HasError()) {
        Logger::Error("HuntQueryEngine: raw data query failed context={} code={} msg={}",
            StringUtils::ToNarrow(error.context), error.sqliteCode, StringUtils::ToNarrow(error.message));
        result.executionTime = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - started);
        return result;
    }

    std::unordered_map<std::string, int> columns;
    while (dataResult.Next()) {
        if (columns.empty()) {
            columns = BuildColumnLookup(dataResult);
        }
        result.matches.emplace_back(MakeRawSqlMatch(dataResult, columns, executedAt));
    }

    result.hasMore = result.totalMatches > result.matches.size();
    result.executionTime = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - started);
    Logger::Debug("HuntQueryEngine: ExecuteRawSQL completed returned={} total={} durationMs={}",
        result.matches.size(), result.totalMatches, result.executionTime.count());
    return result;
}

uint64_t HuntQueryEngine::CountMatches(const HuntQuery& query) {
    std::shared_lock lock(m_impl->mutex);
    if (!m_impl->initialized.load(std::memory_order_acquire)) {
        Logger::Warn("HuntQueryEngine: CountMatches requested before initialization");
        return 0;
    }

    const QueryPlan plan = BuildQueryPlan(query);
    DatabaseError error{};

    if (plan.postFilters.empty()) {
        auto countResult = DatabaseManager::Instance().QueryWithParamsVector(
            std::string("SELECT COUNT(*) FROM telemetry_events") + plan.whereClause + ';',
            plan.params,
            &error);
        if (error.HasError()) {
            Logger::Error("HuntQueryEngine: CountMatches failed context={} code={} msg={}",
                StringUtils::ToNarrow(error.context), error.sqliteCode, StringUtils::ToNarrow(error.message));
            return 0;
        }

        if (countResult.Next()) {
            return static_cast<uint64_t>(std::max<int64_t>(0, countResult.GetInt64(0)));
        }
        return 0;
    }

    uint64_t matchedCount = 0;
    uint32_t rawOffset = 0;
    while (true) {
        auto params = plan.params;
        params.push_back(std::to_string(kPostFilterBatchSize));
        params.push_back(std::to_string(rawOffset));
        auto pageResult = DatabaseManager::Instance().QueryWithParamsVector(
            MakeBaseSelectSql(plan.whereClause) + " LIMIT ? OFFSET ?;",
            params,
            &error);
        if (error.HasError()) {
            Logger::Error("HuntQueryEngine: CountMatches post-filter query failed context={} code={} msg={}",
                StringUtils::ToNarrow(error.context), error.sqliteCode, StringUtils::ToNarrow(error.message));
            return matchedCount;
        }

        uint32_t rowsRead = 0;
        while (pageResult.Next()) {
            ++rowsRead;
            if (EvaluateQuery(ReadTelemetryRow(pageResult), query)) {
                ++matchedCount;
            }
        }

        if (rowsRead < kPostFilterBatchSize) {
            break;
        }
        rawOffset += rowsRead;
    }

    return matchedCount;
}

std::vector<std::string> HuntQueryEngine::GetAvailableFields() {
    return {
        "timestamp",
        "category",
        "severity",
        "process_id",
        "process_name",
        "process_path",
        "parent_process_id",
        "user_name",
        "mitre_attack_id",
        "source_ip",
        "dest_ip",
        "dest_port",
        "file_path",
        "file_hash",
        "registry_key",
        "registry_value",
        "domain_name",
        "command_line"
    };
}

} // namespace ShadowStrike::Products::PhantomEDR::ThreatHunting
