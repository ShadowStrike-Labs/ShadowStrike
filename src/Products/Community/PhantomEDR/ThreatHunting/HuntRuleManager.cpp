#include "pch.h"
#include "Products/Community/PhantomEDR/ThreatHunting/HuntRuleManager.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cctype>
#include <filesystem>
#include <format>
#include <fstream>
#include <functional>
#include <limits>
#include <memory>
#include <optional>
#include <regex>
#include <shared_mutex>
#include <sstream>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#include <nlohmann/json.hpp>

#include "PhantomCore/Database/DatabaseManager.hpp"
#include "PhantomCore/SignatureStore/YaraRuleStore.hpp"
#include "PhantomCore/Utils/FileUtils.hpp"
#include "PhantomCore/Utils/Logger.hpp"
#include "PhantomCore/Utils/StringUtils.hpp"
#include "Products/Community/PhantomEDR/Telemetry/TelemetryTypes.hpp"

namespace ShadowStrike::Products::PhantomEDR::ThreatHunting {

namespace {

using json = nlohmann::json;
using Clock = std::chrono::system_clock;
using ShadowStrike::Database::DatabaseError;
using ShadowStrike::Database::DatabaseManager;
using ShadowStrike::Database::QueryResult;
using ShadowStrike::SignatureStore::StoreError;
using ShadowStrike::SignatureStore::ThreatLevel;
using ShadowStrike::SignatureStore::YaraMatch;
using ShadowStrike::SignatureStore::YaraRuleStore;
namespace FileUtils = ShadowStrike::Utils::FileUtils;
namespace StringUtils = ShadowStrike::Utils::StringUtils;

constexpr std::string_view kLogPrefix = "[HuntRuleManager]";
constexpr size_t kMaxSigmaFileBytes = 2 * 1024 * 1024;
constexpr size_t kMaxYaraFileBytes = 10 * 1024 * 1024;
constexpr uint32_t kMaxImportedRulesPerRun = 10000;
constexpr uint32_t kDefaultQueryCap = 10000;
constexpr std::string_view kHuntRuleNamespacePrefix = "hunt_rule_";

constexpr std::string_view kCreateRulesTableSql = R"(
    CREATE TABLE IF NOT EXISTS hunt_rules (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        description TEXT NOT NULL,
        format INTEGER NOT NULL,
        severity INTEGER NOT NULL,
        status INTEGER NOT NULL,
        author TEXT NOT NULL,
        source TEXT NOT NULL,
        rule_content TEXT NOT NULL,
        mitre_attack_id TEXT NOT NULL,
        tags TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL,
        version INTEGER NOT NULL
    );
)";

constexpr std::string_view kCreateRulesIndexSql = R"(
    CREATE INDEX IF NOT EXISTS idx_hunt_rules_format_status ON hunt_rules(format, status);
    CREATE INDEX IF NOT EXISTS idx_hunt_rules_updated_at ON hunt_rules(updated_at DESC);
    CREATE INDEX IF NOT EXISTS idx_hunt_rules_severity ON hunt_rules(severity);
)";

constexpr std::string_view kUpsertRuleSql = R"(
    INSERT INTO hunt_rules (
        id, name, description, format, severity, status, author, source,
        rule_content, mitre_attack_id, tags, created_at, updated_at, version
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(id) DO UPDATE SET
        name = excluded.name,
        description = excluded.description,
        format = excluded.format,
        severity = excluded.severity,
        status = excluded.status,
        author = excluded.author,
        source = excluded.source,
        rule_content = excluded.rule_content,
        mitre_attack_id = excluded.mitre_attack_id,
        tags = excluded.tags,
        created_at = excluded.created_at,
        updated_at = excluded.updated_at,
        version = excluded.version;
)";

constexpr std::string_view kDeleteRuleSql = R"(
    DELETE FROM hunt_rules WHERE id = ?;
)";

constexpr std::string_view kUpdateRuleStatusSql = R"(
    UPDATE hunt_rules
       SET status = ?,
           updated_at = ?
     WHERE id = ?;
)";

constexpr std::string_view kSelectRuleSql = R"(
    SELECT id, name, description, format, severity, status, author, source,
           rule_content, mitre_attack_id, tags, created_at, updated_at, version
      FROM hunt_rules
     WHERE id = ?;
)";

constexpr std::string_view kCountRulesSql = R"(
    SELECT COUNT(*) FROM hunt_rules;
)";

constexpr std::string_view kSelectActiveRulesSql = R"(
    SELECT id, name, description, format, severity, status, author, source,
           rule_content, mitre_attack_id, tags, created_at, updated_at, version
      FROM hunt_rules
     WHERE status = ?
     ORDER BY updated_at DESC;
)";

constexpr std::string_view kSelectTelemetryBaseSql = R"(
    SELECT event_id, timestamp_ns, category, severity, process_id, parent_process_id,
           process_name, process_path, user_name, mitre_attack_id, payload_json, metadata_json
      FROM telemetry_events
)";

struct TelemetryRow final {
    uint64_t eventId = 0;
    int64_t timestampNs = 0;
    int category = 0;
    int severity = 0;
    uint32_t processId = 0;
    uint32_t parentProcessId = 0;
    std::string processName;
    std::string processPath;
    std::string userName;
    std::string mitreAttackId;
    std::string payloadJson;
    std::string metadataJson;
    json payload;
    json metadata;
};

struct QuerySqlPlan final {
    std::string whereClause;
    std::vector<std::string> params;
};

struct SigmaSelectorTerm final {
    QueryCondition condition;
    std::vector<std::string> values;
    bool requireAllValues = false;
};

struct SigmaRuleDefinition final {
    std::string id;
    std::string title;
    std::string description;
    RuleSeverity severity = RuleSeverity::Medium;
    RuleStatus status = RuleStatus::Active;
    std::string author;
    std::string mitreAttackId;
    std::vector<std::string> tags;
    std::string source;
    std::unordered_map<std::string, std::vector<SigmaSelectorTerm>> selectors;
    std::string condition;
    std::unordered_map<std::string, std::string> logsource;
};

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

[[nodiscard]] bool StartsWithInsensitive(std::string_view value, std::string_view prefix)
{
    if (prefix.size() > value.size()) {
        return false;
    }

    return ToLowerCopy(value.substr(0, prefix.size())) == ToLowerCopy(prefix);
}

[[nodiscard]] bool EndsWithInsensitive(std::string_view value, std::string_view suffix)
{
    if (suffix.size() > value.size()) {
        return false;
    }

    return ToLowerCopy(value.substr(value.size() - suffix.size())) == ToLowerCopy(suffix);
}

[[nodiscard]] std::string Unquote(std::string value)
{
    value = TrimCopy(value);
    if (value.size() >= 2) {
        const char first = value.front();
        const char last = value.back();
        if ((first == '\'' && last == '\'') || (first == '"' && last == '"')) {
            value = value.substr(1, value.size() - 2);
        }
    }

    std::string result;
    result.reserve(value.size());
    bool escaping = false;
    for (const char ch : value) {
        if (escaping) {
            switch (ch) {
            case 'n':
                result.push_back('\n');
                break;
            case 'r':
                result.push_back('\r');
                break;
            case 't':
                result.push_back('\t');
                break;
            default:
                result.push_back(ch);
                break;
            }
            escaping = false;
            continue;
        }

        if (ch == '\\') {
            escaping = true;
            continue;
        }

        result.push_back(ch);
    }

    if (escaping) {
        result.push_back('\\');
    }

    return result;
}

[[nodiscard]] std::vector<std::string> ParseInlineArray(std::string value)
{
    std::vector<std::string> items;
    value = TrimCopy(value);
    if (value.size() < 2 || value.front() != '[' || value.back() != ']') {
        if (!value.empty()) {
            items.push_back(Unquote(value));
        }
        return items;
    }

    value = value.substr(1, value.size() - 2);
    std::string current;
    bool inQuotes = false;
    char quoteChar = '\0';

    for (const char ch : value) {
        if ((ch == '"' || ch == '\'') && (!inQuotes || ch == quoteChar)) {
            if (!inQuotes) {
                inQuotes = true;
                quoteChar = ch;
            } else {
                inQuotes = false;
                quoteChar = '\0';
            }
            current.push_back(ch);
            continue;
        }

        if (ch == ',' && !inQuotes) {
            const std::string item = Unquote(current);
            if (!item.empty()) {
                items.push_back(item);
            }
            current.clear();
            continue;
        }

        current.push_back(ch);
    }

    const std::string finalItem = Unquote(current);
    if (!finalItem.empty()) {
        items.push_back(finalItem);
    }

    return items;
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

[[nodiscard]] std::string MakeStableId(std::string_view prefix, std::string_view seed)
{
    return std::format("{}{:016x}", prefix, Fnv1a64(seed));
}

[[nodiscard]] std::string SerializeTags(const std::vector<std::string>& tags)
{
    return json(tags).dump();
}

[[nodiscard]] std::vector<std::string> DeserializeTags(std::string_view serialized)
{
    std::vector<std::string> tags;
    if (serialized.empty()) {
        return tags;
    }

    try {
        const json parsed = json::parse(serialized, nullptr, true, true);
        if (!parsed.is_array()) {
            return tags;
        }

        tags.reserve(parsed.size());
        for (const auto& item : parsed) {
            if (item.is_string()) {
                tags.push_back(item.get<std::string>());
            }
        }
    }
    catch (const std::exception& ex) {
        ShadowStrike::Utils::Logger::Warn("{} Failed to deserialize tags: {}", kLogPrefix, ex.what());
    }

    return tags;
}

[[nodiscard]] RuleSeverity ParseRuleSeverity(std::string_view severityText)
{
    const std::string lowered = ToLowerCopy(TrimCopy(severityText));
    if (lowered == "critical") {
        return RuleSeverity::Critical;
    }
    if (lowered == "high") {
        return RuleSeverity::High;
    }
    if (lowered == "medium" || lowered == "med") {
        return RuleSeverity::Medium;
    }
    if (lowered == "low") {
        return RuleSeverity::Low;
    }
    return RuleSeverity::Informational;
}

[[nodiscard]] RuleStatus ParseRuleStatus(std::string_view statusText)
{
    const std::string lowered = ToLowerCopy(TrimCopy(statusText));
    if (lowered == "disabled") {
        return RuleStatus::Disabled;
    }
    if (lowered == "deprecated" || lowered == "expired") {
        return RuleStatus::Expired;
    }
    if (lowered == "draft" || lowered == "experimental" || lowered == "test") {
        return RuleStatus::Draft;
    }
    return RuleStatus::Active;
}

[[nodiscard]] RuleSeverity ConvertThreatLevel(ThreatLevel level) noexcept
{
    switch (level) {
    case ThreatLevel::Critical:
        return RuleSeverity::Critical;
    case ThreatLevel::High:
        return RuleSeverity::High;
    case ThreatLevel::Medium:
        return RuleSeverity::Medium;
    case ThreatLevel::Low:
        return RuleSeverity::Low;
    case ThreatLevel::Info:
    default:
        return RuleSeverity::Informational;
    }
}

[[nodiscard]] std::optional<int64_t> ParseInteger(std::string_view value)
{
    const std::string trimmed = TrimCopy(value);
    if (trimmed.empty()) {
        return std::nullopt;
    }

    try {
        size_t processed = 0;
        const long long result = std::stoll(trimmed, &processed, 10);
        if (processed != trimmed.size()) {
            return std::nullopt;
        }
        return static_cast<int64_t>(result);
    }
    catch (...) {
        return std::nullopt;
    }
}

[[nodiscard]] std::optional<double> ParseDouble(std::string_view value)
{
    const std::string trimmed = TrimCopy(value);
    if (trimmed.empty()) {
        return std::nullopt;
    }

    try {
        size_t processed = 0;
        const double result = std::stod(trimmed, &processed);
        if (processed != trimmed.size()) {
            return std::nullopt;
        }
        return result;
    }
    catch (...) {
        return std::nullopt;
    }
}

[[nodiscard]] QueryField ParseQueryField(std::string_view fieldText)
{
    const std::string field = ToLowerCopy(fieldText);
    if (field == "timestamp") {
        return QueryField::Timestamp;
    }
    if (field == "category" || field == "eventcategory") {
        return QueryField::Category;
    }
    if (field == "severity") {
        return QueryField::Severity;
    }
    if (field == "processid" || field == "process_id" || field == "pid") {
        return QueryField::ProcessId;
    }
    if (field == "processname" || field == "image" || field == "imagename" || field == "parentimage") {
        return QueryField::ProcessName;
    }
    if (field == "processpath" || field == "imagepath") {
        return QueryField::ProcessPath;
    }
    if (field == "parentprocessid" || field == "parent_process_id" || field == "ppid") {
        return QueryField::ParentProcessId;
    }
    if (field == "username" || field == "user" || field == "user_name") {
        return QueryField::UserName;
    }
    if (field == "mitreattackid" || field == "mitre_attack_id") {
        return QueryField::MitreAttackId;
    }
    if (field == "sourceip" || field == "srcip" || field == "localaddr" || field == "source_ip") {
        return QueryField::SourceIP;
    }
    if (field == "destip" || field == "dstip" || field == "remoteaddr" || field == "dest_ip") {
        return QueryField::DestIP;
    }
    if (field == "destport" || field == "remoteport" || field == "dest_port") {
        return QueryField::DestPort;
    }
    if (field == "filepath" || field == "filename" || field == "targetfilename" || field == "file_path") {
        return QueryField::FilePath;
    }
    if (field == "filehash" || field == "hash" || field == "sha256" || field == "imagehash") {
        return QueryField::FileHash;
    }
    if (field == "registrykey" || field == "keypath" || field == "targetobject" || field == "registry_key") {
        return QueryField::RegistryKey;
    }
    if (field == "registryvalue" || field == "valuename" || field == "value_name") {
        return QueryField::RegistryValue;
    }
    if (field == "domain" || field == "domainname" || field == "dnsquery" || field == "queryname") {
        return QueryField::DomainName;
    }
    return QueryField::CommandLine;
}

[[nodiscard]] QueryOperator ParseQueryOperator(std::string_view opText)
{
    const std::string op = ToLowerCopy(opText);
    if (op == "notequals" || op == "not_equals") {
        return QueryOperator::NotEquals;
    }
    if (op == "contains") {
        return QueryOperator::Contains;
    }
    if (op == "startswith") {
        return QueryOperator::StartsWith;
    }
    if (op == "endswith") {
        return QueryOperator::EndsWith;
    }
    if (op == "greaterthan" || op == "gt") {
        return QueryOperator::GreaterThan;
    }
    if (op == "lessthan" || op == "lt") {
        return QueryOperator::LessThan;
    }
    if (op == "in") {
        return QueryOperator::In;
    }
    if (op == "regex" || op == "re") {
        return QueryOperator::Regex;
    }
    if (op == "exists") {
        return QueryOperator::Exists;
    }
    return QueryOperator::Equals;
}

[[nodiscard]] std::string GetQueryFieldName(QueryField field)
{
    switch (field) {
    case QueryField::Timestamp:
        return "timestamp";
    case QueryField::Category:
        return "category";
    case QueryField::Severity:
        return "severity";
    case QueryField::ProcessId:
        return "process_id";
    case QueryField::ProcessName:
        return "process_name";
    case QueryField::ProcessPath:
        return "process_path";
    case QueryField::ParentProcessId:
        return "parent_process_id";
    case QueryField::UserName:
        return "user_name";
    case QueryField::MitreAttackId:
        return "mitre_attack_id";
    case QueryField::SourceIP:
        return "source_ip";
    case QueryField::DestIP:
        return "dest_ip";
    case QueryField::DestPort:
        return "dest_port";
    case QueryField::FilePath:
        return "file_path";
    case QueryField::FileHash:
        return "file_hash";
    case QueryField::RegistryKey:
        return "registry_key";
    case QueryField::RegistryValue:
        return "registry_value";
    case QueryField::DomainName:
        return "domain_name";
    case QueryField::CommandLine:
    default:
        return "command_line";
    }
}

[[nodiscard]] std::string GetOperatorName(QueryOperator op)
{
    switch (op) {
    case QueryOperator::Equals:
        return "equals";
    case QueryOperator::NotEquals:
        return "not_equals";
    case QueryOperator::Contains:
        return "contains";
    case QueryOperator::StartsWith:
        return "startswith";
    case QueryOperator::EndsWith:
        return "endswith";
    case QueryOperator::GreaterThan:
        return "greater_than";
    case QueryOperator::LessThan:
        return "less_than";
    case QueryOperator::In:
        return "in";
    case QueryOperator::Regex:
        return "regex";
    case QueryOperator::Exists:
    default:
        return "exists";
    }
}

[[nodiscard]] QueryValue ParseQueryValue(const json& value)
{
    if (value.is_array()) {
        std::vector<std::string> values;
        values.reserve(value.size());
        for (const auto& item : value) {
            if (item.is_string()) {
                values.push_back(item.get<std::string>());
            } else if (item.is_number_integer()) {
                values.push_back(std::to_string(item.get<int64_t>()));
            } else if (item.is_number_unsigned()) {
                values.push_back(std::to_string(item.get<uint64_t>()));
            } else if (item.is_number_float()) {
                values.push_back(std::format("{}", item.get<double>()));
            }
        }
        return values;
    }

    if (value.is_string()) {
        return value.get<std::string>();
    }
    if (value.is_number_unsigned()) {
        return value.get<uint64_t>();
    }
    if (value.is_number_integer()) {
        return value.get<int64_t>();
    }
    if (value.is_number_float()) {
        return value.get<double>();
    }

    return std::string{};
}

[[nodiscard]] std::string QueryValueToString(const QueryValue& value)
{
    return std::visit(
        [](const auto& actual) -> std::string {
            using T = std::decay_t<decltype(actual)>;
            if constexpr (std::is_same_v<T, std::string>) {
                return actual;
            } else if constexpr (std::is_same_v<T, std::wstring>) {
                return StringUtils::ToNarrow(actual);
            } else if constexpr (std::is_same_v<T, int64_t>) {
                return std::to_string(actual);
            } else if constexpr (std::is_same_v<T, uint64_t>) {
                return std::to_string(actual);
            } else if constexpr (std::is_same_v<T, double>) {
                return std::format("{}", actual);
            } else if constexpr (std::is_same_v<T, std::vector<std::string>>) {
                return actual.empty() ? std::string{} : actual.front();
            } else {
                return std::string{};
            }
        },
        value);
}

[[nodiscard]] std::vector<std::string> QueryValueToStringVector(const QueryValue& value)
{
    return std::visit(
        [](const auto& actual) -> std::vector<std::string> {
            using T = std::decay_t<decltype(actual)>;
            if constexpr (std::is_same_v<T, std::vector<std::string>>) {
                return actual;
            } else {
                return {QueryValueToString(QueryValue{actual})};
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
                return ParseInteger(actual);
            } else if constexpr (std::is_same_v<T, std::wstring>) {
                return ParseInteger(StringUtils::ToNarrow(actual));
            } else if constexpr (std::is_same_v<T, std::vector<std::string>>) {
                if (actual.empty()) {
                    return std::nullopt;
                }
                return ParseInteger(actual.front());
            } else {
                return std::nullopt;
            }
        },
        value);
}

[[nodiscard]] std::vector<std::string> ExtractStringValues(const TelemetryRow& row, QueryField field)
{
    std::vector<std::string> values;
    switch (field) {
    case QueryField::Category:
        values.push_back(std::to_string(row.category));
        values.push_back(ToLowerCopy(std::string(ToString(static_cast<ShadowStrike::Products::PhantomEDR::Telemetry::EventCategory>(row.category)))));
        break;
    case QueryField::Severity:
        values.push_back(std::to_string(row.severity));
        break;
    case QueryField::ProcessName:
        if (!row.processName.empty()) {
            values.push_back(row.processName);
        }
        if (row.payload.contains("targetProcessName") && row.payload["targetProcessName"].is_string()) {
            values.push_back(row.payload["targetProcessName"].get<std::string>());
        }
        break;
    case QueryField::ProcessPath:
        if (!row.processPath.empty()) {
            values.push_back(row.processPath);
        }
        break;
    case QueryField::UserName:
        if (!row.userName.empty()) {
            values.push_back(row.userName);
        }
        break;
    case QueryField::MitreAttackId:
        if (!row.mitreAttackId.empty()) {
            values.push_back(row.mitreAttackId);
        }
        break;
    case QueryField::SourceIP:
        if (row.payload.contains("localAddr") && row.payload["localAddr"].is_string()) {
            values.push_back(row.payload["localAddr"].get<std::string>());
        }
        if (row.metadata.contains("sourceIp") && row.metadata["sourceIp"].is_string()) {
            values.push_back(row.metadata["sourceIp"].get<std::string>());
        }
        break;
    case QueryField::DestIP:
        if (row.payload.contains("remoteAddr") && row.payload["remoteAddr"].is_string()) {
            values.push_back(row.payload["remoteAddr"].get<std::string>());
        }
        if (row.metadata.contains("destIp") && row.metadata["destIp"].is_string()) {
            values.push_back(row.metadata["destIp"].get<std::string>());
        }
        break;
    case QueryField::FilePath:
        if (row.payload.contains("filePath") && row.payload["filePath"].is_string()) {
            values.push_back(row.payload["filePath"].get<std::string>());
        }
        if (row.payload.contains("oldFilePath") && row.payload["oldFilePath"].is_string()) {
            values.push_back(row.payload["oldFilePath"].get<std::string>());
        }
        if (!row.processPath.empty()) {
            values.push_back(row.processPath);
        }
        break;
    case QueryField::FileHash:
        if (row.payload.contains("fileHash") && row.payload["fileHash"].is_string()) {
            values.push_back(row.payload["fileHash"].get<std::string>());
        }
        if (row.payload.contains("imageHash") && row.payload["imageHash"].is_string()) {
            values.push_back(row.payload["imageHash"].get<std::string>());
        }
        if (row.payload.contains("parentImageHash") && row.payload["parentImageHash"].is_string()) {
            values.push_back(row.payload["parentImageHash"].get<std::string>());
        }
        break;
    case QueryField::RegistryKey:
        if (row.payload.contains("keyPath") && row.payload["keyPath"].is_string()) {
            values.push_back(row.payload["keyPath"].get<std::string>());
        }
        break;
    case QueryField::RegistryValue:
        if (row.payload.contains("valueName") && row.payload["valueName"].is_string()) {
            values.push_back(row.payload["valueName"].get<std::string>());
        }
        if (row.payload.contains("valueData") && row.payload["valueData"].is_string()) {
            values.push_back(row.payload["valueData"].get<std::string>());
        }
        break;
    case QueryField::DomainName:
        if (row.payload.contains("dnsQuery") && row.payload["dnsQuery"].is_string()) {
            values.push_back(row.payload["dnsQuery"].get<std::string>());
        }
        if (row.payload.contains("dnsResponse") && row.payload["dnsResponse"].is_array()) {
            for (const auto& item : row.payload["dnsResponse"]) {
                if (item.is_string()) {
                    values.push_back(item.get<std::string>());
                }
            }
        }
        break;
    case QueryField::CommandLine:
        if (row.payload.contains("commandLine") && row.payload["commandLine"].is_string()) {
            values.push_back(row.payload["commandLine"].get<std::string>());
        }
        if (row.metadata.contains("commandLine") && row.metadata["commandLine"].is_string()) {
            values.push_back(row.metadata["commandLine"].get<std::string>());
        }
        break;
    default:
        break;
    }

    values.erase(std::remove_if(values.begin(), values.end(), [](const std::string& value) { return value.empty(); }), values.end());
    return values;
}

[[nodiscard]] std::optional<int64_t> ExtractNumericValue(const TelemetryRow& row, QueryField field)
{
    switch (field) {
    case QueryField::Timestamp:
        return row.timestampNs;
    case QueryField::Severity:
        return row.severity;
    case QueryField::ProcessId:
        return static_cast<int64_t>(row.processId);
    case QueryField::ParentProcessId:
        return static_cast<int64_t>(row.parentProcessId);
    case QueryField::DestPort:
        if (row.payload.contains("remotePort") && row.payload["remotePort"].is_number_unsigned()) {
            return static_cast<int64_t>(row.payload["remotePort"].get<uint64_t>());
        }
        if (row.payload.contains("remotePort") && row.payload["remotePort"].is_number_integer()) {
            return row.payload["remotePort"].get<int64_t>();
        }
        return std::nullopt;
    default:
        return std::nullopt;
    }
}

[[nodiscard]] bool MatchesStringOperator(
    QueryOperator op,
    std::string_view actual,
    const std::vector<std::string>& expectedValues,
    bool requireAllValues)
{
    if (op == QueryOperator::Exists) {
        return !actual.empty();
    }

    const std::string loweredActual = ToLowerCopy(actual);
    const auto predicate = [&](const std::string& expected) -> bool {
        const std::string loweredExpected = ToLowerCopy(expected);
        switch (op) {
        case QueryOperator::Equals:
            return loweredActual == loweredExpected;
        case QueryOperator::NotEquals:
            return loweredActual != loweredExpected;
        case QueryOperator::Contains:
            return loweredActual.find(loweredExpected) != std::string::npos;
        case QueryOperator::StartsWith:
            return StartsWithInsensitive(actual, expected);
        case QueryOperator::EndsWith:
            return EndsWithInsensitive(actual, expected);
        case QueryOperator::Regex:
            try {
                return std::regex_search(
                    std::string(actual),
                    std::regex(expected, std::regex::ECMAScript | std::regex::icase));
            }
            catch (const std::exception&) {
                return false;
            }
        case QueryOperator::In:
            return loweredActual == loweredExpected;
        default:
            return false;
        }
    };

    if (expectedValues.empty()) {
        return false;
    }

    if (requireAllValues) {
        return std::all_of(expectedValues.begin(), expectedValues.end(), predicate);
    }

    return std::any_of(expectedValues.begin(), expectedValues.end(), predicate);
}

[[nodiscard]] bool MatchesNumericOperator(QueryOperator op, int64_t actual, const QueryValue& expected)
{
    if (op == QueryOperator::Exists) {
        return true;
    }

    const auto expectedNumeric = QueryValueToInt64(expected);
    if (!expectedNumeric.has_value()) {
        return false;
    }

    switch (op) {
    case QueryOperator::Equals:
        return actual == *expectedNumeric;
    case QueryOperator::NotEquals:
        return actual != *expectedNumeric;
    case QueryOperator::GreaterThan:
        return actual > *expectedNumeric;
    case QueryOperator::LessThan:
        return actual < *expectedNumeric;
    case QueryOperator::In: {
        const auto values = QueryValueToStringVector(expected);
        return std::any_of(values.begin(), values.end(), [&](const std::string& value) {
            const auto parsed = ParseInteger(value);
            return parsed.has_value() && *parsed == actual;
        });
    }
    default:
        return false;
    }
}

[[nodiscard]] bool MatchesCondition(const TelemetryRow& row, const QueryCondition& condition)
{
    bool matched = false;

    if (const auto numericValue = ExtractNumericValue(row, condition.field); numericValue.has_value()) {
        matched = MatchesNumericOperator(condition.op, *numericValue, condition.value);
    } else {
        const std::vector<std::string> actualValues = ExtractStringValues(row, condition.field);
        if (condition.op == QueryOperator::Exists) {
            matched = !actualValues.empty();
        } else {
            const std::vector<std::string> expectedValues = QueryValueToStringVector(condition.value);
            matched = std::any_of(actualValues.begin(), actualValues.end(), [&](const std::string& actual) {
                return MatchesStringOperator(condition.op, actual, expectedValues, false);
            });
        }
    }

    return condition.negate ? !matched : matched;
}

[[nodiscard]] TelemetryRow RowToTelemetryRow(QueryResult& result)
{
    TelemetryRow row;
    row.eventId = static_cast<uint64_t>(result.GetInt64(0));
    row.timestampNs = result.GetInt64(1);
    row.category = result.GetInt(2);
    row.severity = result.GetInt(3);
    row.processId = static_cast<uint32_t>(result.GetInt(4));
    row.parentProcessId = static_cast<uint32_t>(result.GetInt(5));
    row.processName = result.GetString(6);
    row.processPath = result.GetString(7);
    row.userName = result.GetString(8);
    row.mitreAttackId = result.GetString(9);
    row.payloadJson = result.GetString(10);
    row.metadataJson = result.GetString(11);

    try {
        if (!row.payloadJson.empty()) {
            row.payload = json::parse(row.payloadJson, nullptr, true, true);
        }
    }
    catch (const std::exception& ex) {
        ShadowStrike::Utils::Logger::Warn("{} Invalid telemetry payload JSON for event {}: {}", kLogPrefix, row.eventId, ex.what());
    }

    try {
        if (!row.metadataJson.empty()) {
            row.metadata = json::parse(row.metadataJson, nullptr, true, true);
        }
    }
    catch (const std::exception& ex) {
        ShadowStrike::Utils::Logger::Warn("{} Invalid telemetry metadata JSON for event {}: {}", kLogPrefix, row.eventId, ex.what());
    }

    return row;
}

[[nodiscard]] HuntMatch BuildMatchFromTelemetry(
    const TelemetryRow& row,
    const HuntRule& rule,
    const std::unordered_map<std::string, std::string>& matchedFields)
{
    HuntMatch match;
    match.eventId = row.eventId;
    match.ruleId = rule.id;
    match.ruleName = rule.name;
    match.severity = rule.severity;
    match.mitreAttackId = !rule.mitreAttackId.empty() ? rule.mitreAttackId : row.mitreAttackId;
    match.description = rule.description;
    match.matchTime = Clock::now();
    match.eventTime = Clock::time_point(std::chrono::duration_cast<Clock::duration>(std::chrono::nanoseconds(row.timestampNs)));
    match.processId = row.processId;
    match.processName = StringUtils::ToWide(row.processName);
    match.processPath = StringUtils::ToWide(row.processPath);
    match.userName = StringUtils::ToWide(row.userName);
    match.matchedFields = matchedFields;
    return match;
}

[[nodiscard]] HuntRule RowToHuntRule(QueryResult& result)
{
    HuntRule rule;
    rule.id = result.GetString(0);
    rule.name = result.GetString(1);
    rule.description = result.GetString(2);
    rule.format = static_cast<RuleFormat>(result.GetInt(3));
    rule.severity = static_cast<RuleSeverity>(result.GetInt(4));
    rule.status = static_cast<RuleStatus>(result.GetInt(5));
    rule.author = result.GetString(6);
    rule.source = result.GetString(7);
    rule.ruleContent = result.GetString(8);
    rule.mitreAttackId = result.GetString(9);
    rule.tags = DeserializeTags(result.GetString(10));
    rule.createdAt = FromUnixSeconds(result.GetInt64(11));
    rule.updatedAt = FromUnixSeconds(result.GetInt64(12));
    rule.version = static_cast<uint32_t>(result.GetInt(13));
    return rule;
}

[[nodiscard]] std::optional<std::pair<std::string, std::string>> SplitKeyValue(std::string_view line)
{
    const size_t separator = line.find(':');
    if (separator == std::string_view::npos) {
        return std::nullopt;
    }

    std::string key = TrimCopy(line.substr(0, separator));
    std::string value = TrimCopy(line.substr(separator + 1));
    if (key.empty()) {
        return std::nullopt;
    }

    return std::make_pair(std::move(key), std::move(value));
}

[[nodiscard]] QueryCondition BuildQueryCondition(
    QueryField field,
    QueryOperator op,
    const std::vector<std::string>& values,
    bool negate)
{
    QueryCondition condition;
    condition.field = field;
    condition.op = values.size() > 1 && op == QueryOperator::Equals ? QueryOperator::In : op;
    condition.negate = negate;

    if (values.empty()) {
        condition.value = std::string{};
        return condition;
    }

    if (values.size() == 1) {
        if (const auto intValue = ParseInteger(values.front()); intValue.has_value()) {
            condition.value = *intValue;
        } else if (const auto doubleValue = ParseDouble(values.front()); doubleValue.has_value()) {
            condition.value = *doubleValue;
        } else {
            condition.value = values.front();
        }
    } else {
        condition.value = values;
    }

    return condition;
}

[[nodiscard]] SigmaSelectorTerm BuildSigmaSelectorTerm(
    std::string_view fieldExpression,
    const std::vector<std::string>& values)
{
    std::vector<std::string> parts;
    std::string current;
    for (const char ch : fieldExpression) {
        if (ch == '|') {
            if (!current.empty()) {
                parts.push_back(ToLowerCopy(current));
                current.clear();
            }
            continue;
        }
        current.push_back(ch);
    }
    if (!current.empty()) {
        parts.push_back(ToLowerCopy(current));
    }

    const QueryField field = ParseQueryField(parts.empty() ? std::string_view{} : std::string_view(parts.front()));

    QueryOperator op = QueryOperator::Equals;
    bool requireAllValues = false;
    bool negate = false;

    for (size_t i = 1; i < parts.size(); ++i) {
        const std::string& modifier = parts[i];
        if (modifier == "contains") {
            op = QueryOperator::Contains;
        } else if (modifier == "startswith") {
            op = QueryOperator::StartsWith;
        } else if (modifier == "endswith") {
            op = QueryOperator::EndsWith;
        } else if (modifier == "re" || modifier == "regex") {
            op = QueryOperator::Regex;
        } else if (modifier == "all") {
            requireAllValues = true;
        } else if (modifier == "not") {
            negate = true;
        } else if (modifier == "exists") {
            op = QueryOperator::Exists;
        }
    }

    SigmaSelectorTerm term;
    term.values = values;
    term.requireAllValues = requireAllValues;
    term.condition = BuildQueryCondition(field, op, values, negate);
    return term;
}

[[nodiscard]] std::optional<SigmaRuleDefinition> ParseSigmaDefinition(
    const std::string& content,
    std::string_view sourcePath)
{
    SigmaRuleDefinition definition;
    definition.source = std::string(sourcePath);

    std::istringstream stream(content);
    std::string line;
    std::string currentTopLevel;
    std::string currentSelector;
    std::string pendingDetectionField;
    size_t importedListItems = 0;

    while (std::getline(stream, line)) {
        if (!line.empty() && line.back() == '\r') {
            line.pop_back();
        }

        const size_t commentPos = line.find('#');
        if (commentPos != std::string::npos && TrimCopy(line.substr(0, commentPos)).empty()) {
            continue;
        }

        size_t indent = 0;
        while (indent < line.size() && line[indent] == ' ') {
            ++indent;
        }

        const std::string trimmed = TrimCopy(line.substr(indent));
        if (trimmed.empty()) {
            continue;
        }

        if (currentTopLevel == "tags" && indent >= 2 && StartsWithInsensitive(trimmed, "- ")) {
            definition.tags.push_back(Unquote(trimmed.substr(2)));
            continue;
        }

        if (currentTopLevel == "detection" &&
            !currentSelector.empty() &&
            !pendingDetectionField.empty() &&
            indent >= 6 &&
            StartsWithInsensitive(trimmed, "- "))
        {
            auto& terms = definition.selectors[currentSelector];
            if (!terms.empty()) {
                terms.back().values.push_back(Unquote(trimmed.substr(2)));
                terms.back().condition = BuildQueryCondition(
                    terms.back().condition.field,
                    terms.back().condition.op,
                    terms.back().values,
                    terms.back().condition.negate);
            }
            continue;
        }

        if (indent == 0) {
            pendingDetectionField.clear();
            currentSelector.clear();

            const auto kv = SplitKeyValue(trimmed);
            if (!kv.has_value()) {
                continue;
            }

            const std::string key = ToLowerCopy(kv->first);
            const std::string value = kv->second;
            currentTopLevel = key;

            if (key == "title") {
                definition.title = Unquote(value);
            } else if (key == "id") {
                definition.id = Unquote(value);
            } else if (key == "description") {
                definition.description = Unquote(value);
            } else if (key == "author") {
                definition.author = Unquote(value);
            } else if (key == "status") {
                definition.status = ParseRuleStatus(value);
            } else if (key == "level") {
                definition.severity = ParseRuleSeverity(value);
            } else if (key == "tags") {
                const auto parsedTags = ParseInlineArray(value);
                definition.tags.insert(definition.tags.end(), parsedTags.begin(), parsedTags.end());
            } else if (key == "detection") {
                currentTopLevel = "detection";
            } else if (key == "logsource") {
                currentTopLevel = "logsource";
            } else if (key == "falsepositives" || key == "references") {
                currentTopLevel = key;
            }

            continue;
        }

        if (currentTopLevel == "logsource") {
            const auto kv = SplitKeyValue(trimmed);
            if (!kv.has_value()) {
                continue;
            }
            definition.logsource[ToLowerCopy(kv->first)] = Unquote(kv->second);
            continue;
        }

        if (currentTopLevel == "detection") {
            if (indent == 2) {
                const auto kv = SplitKeyValue(trimmed);
                if (!kv.has_value()) {
                    continue;
                }

                const std::string key = ToLowerCopy(kv->first);
                if (key == "condition") {
                    definition.condition = TrimCopy(Unquote(kv->second));
                    currentSelector.clear();
                    pendingDetectionField.clear();
                    continue;
                }

                currentSelector = kv->first;
                pendingDetectionField.clear();
                continue;
            }

            if (indent >= 4 && !currentSelector.empty()) {
                const auto kv = SplitKeyValue(trimmed);
                if (!kv.has_value()) {
                    continue;
                }

                pendingDetectionField = kv->first;
                auto parsedValues = ParseInlineArray(kv->second);
                if (parsedValues.empty() && !kv->second.empty()) {
                    parsedValues.push_back(Unquote(kv->second));
                }

                definition.selectors[currentSelector].push_back(
                    BuildSigmaSelectorTerm(kv->first, parsedValues));
                ++importedListItems;
            }
        }
    }

    if (definition.title.empty()) {
        ShadowStrike::Utils::Logger::Warn("{} Sigma rule missing title: {}", kLogPrefix, sourcePath);
        return std::nullopt;
    }

    if (definition.id.empty()) {
        definition.id = MakeStableId(
            "sigma-",
            std::format("{}|{}|{}", definition.title, definition.source, importedListItems));
    }

    for (const std::string& tag : definition.tags) {
        const std::string lowered = ToLowerCopy(tag);
        if ((lowered.size() > 2 && lowered[0] == 't' && std::isdigit(static_cast<unsigned char>(lowered[1])) != 0) ||
            StartsWithInsensitive(lowered, "attack.t"))
        {
            definition.mitreAttackId = tag;
            break;
        }
    }

    if (definition.condition.empty() && !definition.selectors.empty()) {
        definition.condition = definition.selectors.begin()->first;
    }

    return definition;
}

[[nodiscard]] HuntRule SigmaDefinitionToRule(const SigmaRuleDefinition& definition, const std::string& content)
{
    HuntRule rule;
    rule.id = definition.id;
    rule.name = definition.title;
    rule.description = definition.description;
    rule.format = RuleFormat::Sigma;
    rule.severity = definition.severity;
    rule.status = definition.status;
    rule.author = definition.author;
    rule.source = definition.source;
    rule.ruleContent = content;
    rule.mitreAttackId = definition.mitreAttackId;
    rule.tags = definition.tags;
    rule.createdAt = Clock::now();
    rule.updatedAt = rule.createdAt;
    rule.version = 1;
    return rule;
}

[[nodiscard]] std::optional<std::filesystem::path> ExtractTelemetryScanPath(const TelemetryRow& row)
{
    if (row.payload.contains("filePath") && row.payload["filePath"].is_string()) {
        const std::string candidate = row.payload["filePath"].get<std::string>();
        if (!candidate.empty()) {
            return std::filesystem::path(StringUtils::ToWide(candidate));
        }
    }

    if (!row.processPath.empty()) {
        return std::filesystem::path(StringUtils::ToWide(row.processPath));
    }

    return std::nullopt;
}

[[nodiscard]] std::string BuildYaraNamespace(std::string_view ruleId)
{
    return std::format("{}{}", kHuntRuleNamespacePrefix, ruleId);
}

[[nodiscard]] std::string SerializeQueryCondition(const QueryCondition& condition)
{
    json valueJson;
    std::visit(
        [&](const auto& actual) {
            using T = std::decay_t<decltype(actual)>;
            if constexpr (std::is_same_v<T, std::wstring>) {
                valueJson = StringUtils::ToNarrow(actual);
            } else {
                valueJson = actual;
            }
        },
        condition.value);

    json node;
    node["field"] = GetQueryFieldName(condition.field);
    node["op"] = GetOperatorName(condition.op);
    node["negate"] = condition.negate;
    node["value"] = valueJson;
    return node.dump();
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
        query.maxResults = parsed.value("maxResults", kDefaultQueryCap);
        query.offset = parsed.value("offset", 0u);

        const auto parseTimeField = [&](std::string_view key) -> Clock::time_point {
            if (!parsed.contains(std::string(key))) {
                return {};
            }
            const json& node = parsed.at(std::string(key));
            if (node.is_number_integer()) {
                return FromUnixSeconds(node.get<int64_t>());
            }
            if (node.is_number_unsigned()) {
                return FromUnixSeconds(static_cast<int64_t>(node.get<uint64_t>()));
            }
            if (node.is_string()) {
                const auto numeric = ParseInteger(node.get<std::string>());
                if (numeric.has_value()) {
                    return FromUnixSeconds(*numeric);
                }
            }
            return {};
        };

        query.startTime = parseTimeField("startTime");
        query.endTime = parseTimeField("endTime");

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
        ShadowStrike::Utils::Logger::Warn("{} Failed to parse custom HuntQuery JSON: {}", kLogPrefix, ex.what());
        return std::nullopt;
    }
}

[[nodiscard]] std::optional<QuerySqlPlan> BuildSqlPlanForQuery(const HuntQuery& query)
{
    QuerySqlPlan plan;
    std::vector<std::string> clauses;

    if (!IsDefaultTime(query.startTime)) {
        clauses.push_back("timestamp_ns >= ?");
        plan.params.push_back(std::to_string(
            std::chrono::duration_cast<std::chrono::nanoseconds>(query.startTime.time_since_epoch()).count()));
    }

    if (!IsDefaultTime(query.endTime)) {
        clauses.push_back("timestamp_ns <= ?");
        plan.params.push_back(std::to_string(
            std::chrono::duration_cast<std::chrono::nanoseconds>(query.endTime.time_since_epoch()).count()));
    }

    const auto appendClause = [&](std::string clause, std::vector<std::string> params, bool negate) {
        if (clause.empty()) {
            return;
        }

        if (negate) {
            clause = std::format("NOT ({})", clause);
        }

        clauses.push_back(std::move(clause));
        plan.params.insert(plan.params.end(), params.begin(), params.end());
    };

    for (const auto& condition : query.conditions) {
        std::string clause;
        std::vector<std::string> params;
        const auto values = QueryValueToStringVector(condition.value);
        const auto numericValue = QueryValueToInt64(condition.value);

        auto appendStringClause = [&](std::string_view column) {
            switch (condition.op) {
            case QueryOperator::Equals:
                clause = std::format("LOWER({}) = LOWER(?)", column);
                params.push_back(QueryValueToString(condition.value));
                break;
            case QueryOperator::NotEquals:
                clause = std::format("LOWER({}) <> LOWER(?)", column);
                params.push_back(QueryValueToString(condition.value));
                break;
            case QueryOperator::Contains:
                clause = std::format("LOWER({}) LIKE ?", column);
                params.push_back(std::format("%{}%", ToLowerCopy(QueryValueToString(condition.value))));
                break;
            case QueryOperator::StartsWith:
                clause = std::format("LOWER({}) LIKE ?", column);
                params.push_back(std::format("{}%", ToLowerCopy(QueryValueToString(condition.value))));
                break;
            case QueryOperator::EndsWith:
                clause = std::format("LOWER({}) LIKE ?", column);
                params.push_back(std::format("%{}", ToLowerCopy(QueryValueToString(condition.value))));
                break;
            case QueryOperator::In: {
                if (values.empty()) {
                    return;
                }
                std::ostringstream builder;
                builder << "LOWER(" << column << ") IN (";
                for (size_t i = 0; i < values.size(); ++i) {
                    if (i != 0) {
                        builder << ", ";
                    }
                    builder << "LOWER(?)";
                    params.push_back(values[i]);
                }
                builder << ")";
                clause = builder.str();
                break;
            }
            case QueryOperator::Exists:
                clause = std::format("{} IS NOT NULL AND {} <> ''", column, column);
                break;
            default:
                clause = std::format("LOWER({}) LIKE ?", column);
                params.push_back(std::format("%{}%", ToLowerCopy(QueryValueToString(condition.value))));
                break;
            }
        };

        auto appendNumericClause = [&](std::string_view column) {
            if (!numericValue.has_value()) {
                return;
            }

            switch (condition.op) {
            case QueryOperator::Equals:
                clause = std::format("{} = ?", column);
                params.push_back(std::to_string(*numericValue));
                break;
            case QueryOperator::NotEquals:
                clause = std::format("{} <> ?", column);
                params.push_back(std::to_string(*numericValue));
                break;
            case QueryOperator::GreaterThan:
                clause = std::format("{} > ?", column);
                params.push_back(std::to_string(*numericValue));
                break;
            case QueryOperator::LessThan:
                clause = std::format("{} < ?", column);
                params.push_back(std::to_string(*numericValue));
                break;
            case QueryOperator::Exists:
                clause = std::format("{} IS NOT NULL", column);
                break;
            case QueryOperator::In:
                if (values.empty()) {
                    return;
                }
                clause.clear();
                clause += std::format("{} IN (", column);
                for (size_t i = 0; i < values.size(); ++i) {
                    if (i != 0) {
                        clause += ", ";
                    }
                    clause += "?";
                    params.push_back(values[i]);
                }
                clause += ")";
                break;
            default:
                break;
            }
        };

        switch (condition.field) {
        case QueryField::Timestamp:
            appendNumericClause("timestamp_ns");
            break;
        case QueryField::Category:
            appendNumericClause("category");
            break;
        case QueryField::Severity:
            appendNumericClause("severity");
            break;
        case QueryField::ProcessId:
            appendNumericClause("process_id");
            break;
        case QueryField::ParentProcessId:
            appendNumericClause("parent_process_id");
            break;
        case QueryField::ProcessName:
            appendStringClause("process_name");
            break;
        case QueryField::ProcessPath:
            appendStringClause("process_path");
            break;
        case QueryField::UserName:
            appendStringClause("user_name");
            break;
        case QueryField::MitreAttackId:
            appendStringClause("mitre_attack_id");
            break;
        case QueryField::SourceIP:
        case QueryField::DestIP:
        case QueryField::FilePath:
        case QueryField::FileHash:
        case QueryField::RegistryKey:
        case QueryField::RegistryValue:
        case QueryField::DomainName:
        case QueryField::CommandLine:
            clause = "LOWER(payload_json) LIKE ?";
            params.push_back(std::format("%{}%", ToLowerCopy(QueryValueToString(condition.value))));
            break;
        case QueryField::DestPort:
            clause = "LOWER(payload_json) LIKE ?";
            params.push_back(std::format("%{}%", ToLowerCopy(QueryValueToString(condition.value))));
            break;
        }

        appendClause(std::move(clause), std::move(params), condition.negate);
    }

    if (!clauses.empty()) {
        const std::string separator = query.logic == QueryLogic::Or ? " OR " : " AND ";
        std::ostringstream builder;
        builder << " WHERE ";
        for (size_t i = 0; i < clauses.size(); ++i) {
            if (i != 0) {
                builder << separator;
            }
            builder << "(" << clauses[i] << ")";
        }
        plan.whereClause = builder.str();
    }

    return plan;
}

[[nodiscard]] HuntResult ExecuteHuntQuery(
    const HuntQuery& query,
    const HuntRule* ruleContext,
    std::string_view resultId,
    std::string_view resultName)
{
    HuntResult result;
    result.queryOrRuleId = std::string(resultId);
    result.queryOrRuleName = std::string(resultName);
    result.executedAt = Clock::now();

    const auto started = std::chrono::steady_clock::now();
    DatabaseError dbError;

    const auto plan = BuildSqlPlanForQuery(query);
    std::string sql = std::string(kSelectTelemetryBaseSql);
    if (plan.has_value()) {
        sql += plan->whereClause;
    }
    sql += " ORDER BY timestamp_ns DESC;";

    QueryResult queryResult = plan.has_value()
        ? DatabaseManager::Instance().QueryWithParamsVector(sql, plan->params, &dbError)
        : DatabaseManager::Instance().Query(sql, &dbError);

    if (dbError.HasError()) {
        ShadowStrike::Utils::Logger::Error(
            "{} Telemetry query failed for {}: {}",
            kLogPrefix,
            resultId,
            StringUtils::ToNarrow(dbError.message));
        result.executionTime = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - started);
        return result;
    }

    std::vector<HuntMatch> allMatches;
    while (queryResult.Next()) {
        const TelemetryRow row = RowToTelemetryRow(queryResult);
        const bool matched = query.conditions.empty()
            ? true
            : (query.logic == QueryLogic::And
                ? std::all_of(query.conditions.begin(), query.conditions.end(), [&](const QueryCondition& condition) {
                    return MatchesCondition(row, condition);
                })
                : std::any_of(query.conditions.begin(), query.conditions.end(), [&](const QueryCondition& condition) {
                    return MatchesCondition(row, condition);
                }));

        if (!matched) {
            continue;
        }

        std::unordered_map<std::string, std::string> matchedFields;
        for (const auto& condition : query.conditions) {
            const auto values = ExtractStringValues(row, condition.field);
            if (!values.empty()) {
                matchedFields.emplace(GetQueryFieldName(condition.field), values.front());
            } else if (const auto numeric = ExtractNumericValue(row, condition.field); numeric.has_value()) {
                matchedFields.emplace(GetQueryFieldName(condition.field), std::to_string(*numeric));
            }
        }

        HuntRule syntheticRule;
        if (ruleContext != nullptr) {
            syntheticRule = *ruleContext;
        } else {
            syntheticRule.id = std::string(resultId);
            syntheticRule.name = std::string(resultName);
            syntheticRule.description = query.description;
            syntheticRule.severity = RuleSeverity::Medium;
        }

        allMatches.push_back(BuildMatchFromTelemetry(row, syntheticRule, matchedFields));
    }

    result.totalMatches = allMatches.size();
    const size_t offset = std::min<size_t>(query.offset, allMatches.size());
    const size_t maxResults = std::max<uint32_t>(1u, query.maxResults == 0 ? kDefaultQueryCap : query.maxResults);
    const size_t count = std::min<size_t>(maxResults, allMatches.size() - offset);
    result.hasMore = (offset + count) < allMatches.size();
    result.matches.assign(allMatches.begin() + static_cast<std::ptrdiff_t>(offset),
        allMatches.begin() + static_cast<std::ptrdiff_t>(offset + count));
    result.executionTime = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - started);
    return result;
}

[[nodiscard]] std::vector<std::string> TokenizeCondition(std::string_view condition)
{
    std::vector<std::string> tokens;
    std::string current;

    const auto flush = [&]() {
        const std::string trimmed = TrimCopy(current);
        if (!trimmed.empty()) {
            tokens.push_back(trimmed);
        }
        current.clear();
    };

    for (const char ch : condition) {
        if (std::isspace(static_cast<unsigned char>(ch)) != 0) {
            flush();
            continue;
        }
        if (ch == '(' || ch == ')') {
            flush();
            tokens.emplace_back(1, ch);
            continue;
        }
        current.push_back(ch);
    }
    flush();
    return tokens;
}

[[nodiscard]] std::string ExpandSigmaCondition(
    const std::string& rawCondition,
    const std::unordered_map<std::string, std::vector<SigmaSelectorTerm>>& selectors)
{
    std::string expanded = ToLowerCopy(rawCondition);
    if (expanded.empty()) {
        return expanded;
    }

    const auto selectorNames = [&]() {
        std::vector<std::string> names;
        names.reserve(selectors.size());
        for (const auto& [name, _] : selectors) {
            names.push_back(ToLowerCopy(name));
        }
        std::sort(names.begin(), names.end());
        return names;
    }();

    const auto replacePattern = [&](const std::string& keyword, bool requireAll) {
        std::regex pattern(std::format(R"(({}|any|1)\s+of\s+([a-z0-9_\-*]+|them))", keyword), std::regex::icase);
        std::smatch match;
        std::string current = expanded;
        while (std::regex_search(current, match, pattern)) {
            std::vector<std::string> matchedSelectors;
            const std::string subject = ToLowerCopy(match[2].str());
            if (subject == "them") {
                matchedSelectors = selectorNames;
            } else if (!subject.empty() && subject.back() == '*') {
                const std::string prefix = subject.substr(0, subject.size() - 1);
                for (const auto& selector : selectorNames) {
                    if (StartsWithInsensitive(selector, prefix)) {
                        matchedSelectors.push_back(selector);
                    }
                }
            } else {
                matchedSelectors.push_back(subject);
            }

            std::string replacement;
            if (matchedSelectors.empty()) {
                replacement = "false";
            } else if (matchedSelectors.size() == 1) {
                replacement = matchedSelectors.front();
            } else {
                std::ostringstream builder;
                builder << "(";
                for (size_t i = 0; i < matchedSelectors.size(); ++i) {
                    if (i != 0) {
                        builder << (requireAll ? " and " : " or ");
                    }
                    builder << matchedSelectors[i];
                }
                builder << ")";
                replacement = builder.str();
            }

            current = match.prefix().str() + replacement + match.suffix().str();
        }
        expanded = current;
    };

    replacePattern("all", true);
    replacePattern("1", false);
    replacePattern("any", false);
    return expanded;
}

class SigmaConditionParser final {
public:
    SigmaConditionParser(std::vector<std::string> tokens, const std::unordered_map<std::string, bool>& selectorMatches)
        : m_tokens(std::move(tokens)), m_selectorMatches(selectorMatches)
    {
    }

    [[nodiscard]] bool Parse()
    {
        m_index = 0;
        return ParseOr();
    }

private:
    [[nodiscard]] bool ParseOr()
    {
        bool value = ParseAnd();
        while (Peek("or")) {
            (void)Consume();
            value = value || ParseAnd();
        }
        return value;
    }

    [[nodiscard]] bool ParseAnd()
    {
        bool value = ParseNot();
        while (Peek("and")) {
            (void)Consume();
            value = value && ParseNot();
        }
        return value;
    }

    [[nodiscard]] bool ParseNot()
    {
        if (Peek("not")) {
            (void)Consume();
            return !ParseNot();
        }
        return ParsePrimary();
    }

    [[nodiscard]] bool ParsePrimary()
    {
        if (Peek("(")) {
            (void)Consume();
            const bool value = ParseOr();
            if (Peek(")")) {
                (void)Consume();
            }
            return value;
        }

        if (m_index >= m_tokens.size()) {
            return false;
        }

        const std::string token = Consume();
        if (token == "true") {
            return true;
        }
        if (token == "false") {
            return false;
        }

        const auto it = m_selectorMatches.find(ToLowerCopy(token));
        return it != m_selectorMatches.end() ? it->second : false;
    }

    [[nodiscard]] bool Peek(std::string_view expected) const
    {
        return m_index < m_tokens.size() && ToLowerCopy(m_tokens[m_index]) == ToLowerCopy(expected);
    }

    [[nodiscard]] std::string Consume()
    {
        return m_tokens.at(m_index++);
    }

    std::vector<std::string> m_tokens;
    const std::unordered_map<std::string, bool>& m_selectorMatches;
    size_t m_index = 0;
};

[[nodiscard]] bool MatchesSigmaSelector(const TelemetryRow& row, const std::vector<SigmaSelectorTerm>& terms)
{
    return std::all_of(terms.begin(), terms.end(), [&](const SigmaSelectorTerm& term) {
        if (const auto numeric = ExtractNumericValue(row, term.condition.field); numeric.has_value()) {
            const bool matched = MatchesNumericOperator(term.condition.op, *numeric, term.condition.value);
            return term.condition.negate ? !matched : matched;
        }

        const auto actualValues = ExtractStringValues(row, term.condition.field);
        if (term.condition.op == QueryOperator::Exists) {
            const bool matched = !actualValues.empty();
            return term.condition.negate ? !matched : matched;
        }

        bool matched = false;
        for (const auto& actual : actualValues) {
            if (MatchesStringOperator(term.condition.op, actual, term.values, term.requireAllValues)) {
                matched = true;
                break;
            }
        }

        return term.condition.negate ? !matched : matched;
    });
}

[[nodiscard]] HuntResult EvaluateSigmaRule(const HuntRule& rule)
{
    HuntResult result;
    result.queryOrRuleId = rule.id;
    result.queryOrRuleName = rule.name;
    result.executedAt = Clock::now();

    const auto started = std::chrono::steady_clock::now();
    const auto parsedSigma = ParseSigmaDefinition(rule.ruleContent, rule.source);
    if (!parsedSigma.has_value()) {
        ShadowStrike::Utils::Logger::Warn("{} Unable to evaluate invalid Sigma rule {}", kLogPrefix, rule.id);
        result.executionTime = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - started);
        return result;
    }

    HuntQuery candidateQuery;
    candidateQuery.logic = QueryLogic::Or;
    candidateQuery.maxResults = std::numeric_limits<uint32_t>::max();
    candidateQuery.offset = 0;
    candidateQuery.description = rule.description;
    for (const auto& [selectorName, selectorTerms] : parsedSigma->selectors) {
        for (const auto& term : selectorTerms) {
            candidateQuery.conditions.push_back(term.condition);
        }
        if (!selectorTerms.empty()) {
            const auto& firstTerm = selectorTerms.front();
            ShadowStrike::Utils::Logger::Debug(
                "{} Sigma selector {} mapped to {} {}",
                kLogPrefix,
                selectorName,
                GetQueryFieldName(firstTerm.condition.field),
                GetOperatorName(firstTerm.condition.op));
        }
    }

    HuntResult candidateResult = ExecuteHuntQuery(candidateQuery, &rule, rule.id, rule.name);
    const std::string expandedCondition = ExpandSigmaCondition(parsedSigma->condition, parsedSigma->selectors);
    const auto conditionTokens = TokenizeCondition(expandedCondition);

    std::vector<HuntMatch> finalMatches;
    finalMatches.reserve(candidateResult.matches.size());

    for (const HuntMatch& candidateMatch : candidateResult.matches) {
        DatabaseError dbError;
        QueryResult rowResult = DatabaseManager::Instance().QueryWithParams(
            std::string(kSelectTelemetryBaseSql) + " WHERE event_id = ?;",
            &dbError,
            static_cast<int64_t>(candidateMatch.eventId));

        if (dbError.HasError() || !rowResult.Next()) {
            continue;
        }

        const TelemetryRow row = RowToTelemetryRow(rowResult);
        std::unordered_map<std::string, bool> selectorMatches;
        std::unordered_map<std::string, std::string> matchedFields;

        for (const auto& [name, terms] : parsedSigma->selectors) {
            const bool selectorMatched = MatchesSigmaSelector(row, terms);
            selectorMatches.emplace(ToLowerCopy(name), selectorMatched);
            if (selectorMatched) {
                for (const auto& term : terms) {
                    const auto values = ExtractStringValues(row, term.condition.field);
                    if (!values.empty()) {
                        matchedFields.emplace(GetQueryFieldName(term.condition.field), values.front());
                    }
                }
            }
        }

        const bool matchesRule = conditionTokens.empty()
            ? std::any_of(selectorMatches.begin(), selectorMatches.end(), [](const auto& entry) { return entry.second; })
            : SigmaConditionParser(conditionTokens, selectorMatches).Parse();

        if (matchesRule) {
            finalMatches.push_back(BuildMatchFromTelemetry(row, rule, matchedFields));
        }
    }

    result.matches = std::move(finalMatches);
    result.totalMatches = result.matches.size();
    result.hasMore = false;
    result.executionTime = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - started);
    return result;
}

[[nodiscard]] HuntResult EvaluateCustomRule(const HuntRule& rule)
{
    const auto query = ParseHuntQueryJson(rule.ruleContent);
    if (!query.has_value()) {
        HuntResult result;
        result.queryOrRuleId = rule.id;
        result.queryOrRuleName = rule.name;
        result.executedAt = Clock::now();
        return result;
    }

    return ExecuteHuntQuery(*query, &rule, rule.id, rule.name);
}

[[nodiscard]] bool IsYamlFile(const std::filesystem::path& path)
{
    const std::string extension = ToLowerCopy(StringUtils::ToNarrow(path.extension().wstring()));
    return extension == ".yml" || extension == ".yaml";
}

[[nodiscard]] bool IsYaraFile(const std::filesystem::path& path)
{
    const std::string extension = ToLowerCopy(StringUtils::ToNarrow(path.extension().wstring()));
    return extension == ".yar" || extension == ".yara";
}

} // namespace

class HuntRuleManagerImpl final {
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

        DatabaseError dbError;
        if (!DatabaseManager::Instance().Execute(std::string(kCreateRulesTableSql), &dbError) ||
            !DatabaseManager::Instance().Execute(std::string(kCreateRulesIndexSql), &dbError))
        {
            ShadowStrike::Utils::Logger::Error(
                "{} Failed to create hunt_rules schema: {}",
                kLogPrefix,
                StringUtils::ToNarrow(dbError.message));
            return false;
        }

        auto yaraStore = std::make_unique<YaraRuleStore>();
        const StoreError yaraInit = YaraRuleStore::InitializeYara();
        if (!yaraInit.IsSuccess()) {
            ShadowStrike::Utils::Logger::Warn(
                "{} YARA engine initialisation failed: {}",
                kLogPrefix,
                yaraInit.message);
        }

        const std::filesystem::path databasePath(DatabaseManager::Instance().GetConfig().databasePath);
        const std::filesystem::path yaraDatabasePath =
            databasePath.has_parent_path()
            ? databasePath.parent_path() / L"threathunting_yara_rules.db"
            : std::filesystem::path(L"threathunting_yara_rules.db");

        StoreError storeInit = yaraStore->Initialize(yaraDatabasePath.wstring(), false);
        if (!storeInit.IsSuccess()) {
            storeInit = yaraStore->CreateNew(yaraDatabasePath.wstring());
        }

        if (!storeInit.IsSuccess()) {
            ShadowStrike::Utils::Logger::Warn(
                "{} Unable to open YARA rule store '{}': {}",
                kLogPrefix,
                StringUtils::ToNarrow(yaraDatabasePath.wstring()),
                storeInit.message);
        } else {
            DatabaseError readError;
            QueryResult existingRules = DatabaseManager::Instance().Query(
                "SELECT id, rule_content FROM hunt_rules WHERE format = 1;",
                &readError);
            while (existingRules.Next()) {
                const std::string ruleId = existingRules.GetString(0);
                const std::string ruleContent = existingRules.GetString(1);
                const StoreError addError = yaraStore->AddRulesFromSource(ruleContent, BuildYaraNamespace(ruleId));
                if (!addError.IsSuccess()) {
                    ShadowStrike::Utils::Logger::Warn(
                        "{} Failed to warm YARA rule {} into the runtime store: {}",
                        kLogPrefix,
                        ruleId,
                        addError.message);
                }
            }
        }

        m_yaraRuleStore = std::move(yaraStore);
        m_initialized = true;
        ShadowStrike::Utils::Logger::Info("{} Initialized", kLogPrefix);
        return true;
    }

    void Shutdown()
    {
        std::unique_lock lock(m_mutex);
        if (!m_initialized) {
            return;
        }

        if (m_yaraRuleStore != nullptr) {
            m_yaraRuleStore->Close();
            m_yaraRuleStore.reset();
        }

        YaraRuleStore::FinalizeYara();
        m_initialized = false;
        ShadowStrike::Utils::Logger::Info("{} Shutdown complete", kLogPrefix);
    }

    [[nodiscard]] bool IsInitialized() const noexcept
    {
        std::shared_lock lock(m_mutex);
        return m_initialized;
    }

    [[nodiscard]] bool AddRule(HuntRule&& rule)
    {
        std::unique_lock lock(m_mutex);
        if (!m_initialized) {
            ShadowStrike::Utils::Logger::Error("{} AddRule called before Initialize", kLogPrefix);
            return false;
        }

        if (rule.name.empty()) {
            ShadowStrike::Utils::Logger::Error("{} Refusing to add rule with empty name", kLogPrefix);
            return false;
        }

        if (rule.id.empty()) {
            rule.id = MakeStableId("hunt-", std::format("{}|{}|{}", rule.name, rule.source, rule.ruleContent));
        }

        const auto now = Clock::now();
        if (IsDefaultTime(rule.createdAt)) {
            rule.createdAt = now;
        }
        rule.updatedAt = now;
        if (rule.version == 0) {
            rule.version = 1;
        }

        if (rule.format == RuleFormat::YARA && m_yaraRuleStore != nullptr) {
            (void)m_yaraRuleStore->RemoveNamespace(BuildYaraNamespace(rule.id));
            const StoreError storeError = m_yaraRuleStore->AddRulesFromSource(rule.ruleContent, BuildYaraNamespace(rule.id));
            if (!storeError.IsSuccess()) {
                ShadowStrike::Utils::Logger::Error(
                    "{} Failed to compile YARA rule {}: {}",
                    kLogPrefix,
                    rule.id,
                    storeError.message);
                return false;
            }
        }

        DatabaseError dbError;
        const bool success = DatabaseManager::Instance().ExecuteWithParams(
            kUpsertRuleSql,
            &dbError,
            rule.id,
            rule.name,
            rule.description,
            static_cast<int>(rule.format),
            static_cast<int>(rule.severity),
            static_cast<int>(rule.status),
            rule.author,
            rule.source,
            rule.ruleContent,
            rule.mitreAttackId,
            SerializeTags(rule.tags),
            ToUnixSeconds(rule.createdAt),
            ToUnixSeconds(rule.updatedAt),
            static_cast<int>(rule.version));

        if (!success) {
            ShadowStrike::Utils::Logger::Error(
                "{} Failed to persist rule {}: {}",
                kLogPrefix,
                rule.id,
                StringUtils::ToNarrow(dbError.message));
            return false;
        }

        ShadowStrike::Utils::Logger::Info(
            "{} Added/updated hunt rule {} ({})",
            kLogPrefix,
            rule.id,
            rule.name);
        return true;
    }

    [[nodiscard]] bool RemoveRule(const std::string& ruleId)
    {
        std::unique_lock lock(m_mutex);
        if (!m_initialized || ruleId.empty()) {
            return false;
        }

        if (m_yaraRuleStore != nullptr) {
            (void)m_yaraRuleStore->RemoveNamespace(BuildYaraNamespace(ruleId));
        }

        DatabaseError dbError;
        const bool success = DatabaseManager::Instance().ExecuteWithParams(kDeleteRuleSql, &dbError, ruleId);
        if (!success) {
            ShadowStrike::Utils::Logger::Error(
                "{} Failed to remove rule {}: {}",
                kLogPrefix,
                ruleId,
                StringUtils::ToNarrow(dbError.message));
        }
        return success;
    }

    [[nodiscard]] bool UpdateRuleStatus(const std::string& ruleId, RuleStatus status)
    {
        std::unique_lock lock(m_mutex);
        if (!m_initialized || ruleId.empty()) {
            return false;
        }

        DatabaseError dbError;
        const bool success = DatabaseManager::Instance().ExecuteWithParams(
            kUpdateRuleStatusSql,
            &dbError,
            static_cast<int>(status),
            ToUnixSeconds(Clock::now()),
            ruleId);

        if (!success) {
            ShadowStrike::Utils::Logger::Error(
                "{} Failed to update rule status for {}: {}",
                kLogPrefix,
                ruleId,
                StringUtils::ToNarrow(dbError.message));
        }
        return success;
    }

    [[nodiscard]] std::optional<HuntRule> GetRule(const std::string& ruleId)
    {
        std::shared_lock lock(m_mutex);
        if (!m_initialized || ruleId.empty()) {
            return std::nullopt;
        }

        DatabaseError dbError;
        QueryResult result = DatabaseManager::Instance().QueryWithParams(kSelectRuleSql, &dbError, ruleId);
        if (dbError.HasError()) {
            ShadowStrike::Utils::Logger::Error(
                "{} Failed to fetch rule {}: {}",
                kLogPrefix,
                ruleId,
                StringUtils::ToNarrow(dbError.message));
            return std::nullopt;
        }

        if (!result.Next()) {
            return std::nullopt;
        }

        return RowToHuntRule(result);
    }

    [[nodiscard]] std::vector<HuntRule> QueryRules(const RuleQueryParams& params)
    {
        std::shared_lock lock(m_mutex);
        std::vector<HuntRule> rules;
        if (!m_initialized) {
            return rules;
        }

        std::string sql =
            "SELECT id, name, description, format, severity, status, author, source, "
            "rule_content, mitre_attack_id, tags, created_at, updated_at, version "
            "FROM hunt_rules WHERE 1 = 1";

        std::vector<std::string> values;
        if (params.format.has_value()) {
            sql += " AND format = ?";
            values.push_back(std::to_string(static_cast<int>(*params.format)));
        }
        if (params.status.has_value()) {
            sql += " AND status = ?";
            values.push_back(std::to_string(static_cast<int>(*params.status)));
        }
        if (params.minSeverity.has_value()) {
            sql += " AND severity >= ?";
            values.push_back(std::to_string(static_cast<int>(*params.minSeverity)));
        }
        if (params.namePattern.has_value() && !params.namePattern->empty()) {
            sql += " AND LOWER(name) LIKE ?";
            values.push_back(std::format("%{}%", ToLowerCopy(*params.namePattern)));
        }
        if (params.tagContains.has_value() && !params.tagContains->empty()) {
            sql += " AND LOWER(tags) LIKE ?";
            values.push_back(std::format("%{}%", ToLowerCopy(*params.tagContains)));
        }

        sql += " ORDER BY updated_at DESC LIMIT ? OFFSET ?;";
        values.push_back(std::to_string(std::max<uint32_t>(1u, params.maxResults)));
        values.push_back(std::to_string(params.offset));

        DatabaseError dbError;
        QueryResult result = DatabaseManager::Instance().QueryWithParamsVector(sql, values, &dbError);
        if (dbError.HasError()) {
            ShadowStrike::Utils::Logger::Error(
                "{} QueryRules failed: {}",
                kLogPrefix,
                StringUtils::ToNarrow(dbError.message));
            return rules;
        }

        while (result.Next()) {
            rules.push_back(RowToHuntRule(result));
        }

        return rules;
    }

    [[nodiscard]] uint64_t GetRuleCount()
    {
        std::shared_lock lock(m_mutex);
        if (!m_initialized) {
            return 0;
        }

        DatabaseError dbError;
        QueryResult result = DatabaseManager::Instance().Query(kCountRulesSql, &dbError);
        if (dbError.HasError() || !result.Next()) {
            return 0;
        }

        return static_cast<uint64_t>(result.GetInt64(0));
    }

    [[nodiscard]] bool ImportSigmaRules(const std::filesystem::path& dirOrFile)
    {
        std::unique_lock lock(m_mutex);
        if (!m_initialized) {
            return false;
        }

        std::error_code ec;
        if (!std::filesystem::exists(dirOrFile, ec)) {
            ShadowStrike::Utils::Logger::Warn("{} Sigma import path does not exist: {}", kLogPrefix, StringUtils::ToNarrow(dirOrFile.wstring()));
            return false;
        }

        std::vector<std::filesystem::path> candidates;
        if (std::filesystem::is_regular_file(dirOrFile, ec)) {
            if (IsYamlFile(dirOrFile)) {
                candidates.push_back(dirOrFile);
            }
        } else {
            for (auto it = std::filesystem::recursive_directory_iterator(dirOrFile, ec);
                 !ec && it != std::filesystem::recursive_directory_iterator() && candidates.size() < kMaxImportedRulesPerRun;
                 it.increment(ec))
            {
                if (it->is_regular_file(ec) && IsYamlFile(it->path())) {
                    candidates.push_back(it->path());
                }
            }
        }

        uint32_t importedCount = 0;
        for (const auto& path : candidates) {
            FileUtils::FileStat stat{};
            if (!FileUtils::Stat(path.wstring(), stat) || stat.size > kMaxSigmaFileBytes) {
                ShadowStrike::Utils::Logger::Warn("{} Skipping oversized Sigma file {}", kLogPrefix, StringUtils::ToNarrow(path.wstring()));
                continue;
            }

            std::string content;
            if (!FileUtils::ReadAllTextUtf8(path.wstring(), content)) {
                ShadowStrike::Utils::Logger::Warn("{} Unable to read Sigma file {}", kLogPrefix, StringUtils::ToNarrow(path.wstring()));
                continue;
            }

            const auto parsed = ParseSigmaDefinition(content, StringUtils::ToNarrow(path.wstring()));
            if (!parsed.has_value()) {
                continue;
            }

            HuntRule rule = SigmaDefinitionToRule(*parsed, content);
            if (AddRule(std::move(rule))) {
                ++importedCount;
            }
        }

        ShadowStrike::Utils::Logger::Info("{} Imported {} Sigma rules from {}", kLogPrefix, importedCount, StringUtils::ToNarrow(dirOrFile.wstring()));
        return importedCount > 0;
    }

    [[nodiscard]] bool ImportYaraRules(const std::filesystem::path& dirOrFile)
    {
        std::unique_lock lock(m_mutex);
        if (!m_initialized) {
            return false;
        }

        std::error_code ec;
        if (!std::filesystem::exists(dirOrFile, ec)) {
            ShadowStrike::Utils::Logger::Warn("{} YARA import path does not exist: {}", kLogPrefix, StringUtils::ToNarrow(dirOrFile.wstring()));
            return false;
        }

        std::vector<std::filesystem::path> candidates;
        if (std::filesystem::is_regular_file(dirOrFile, ec)) {
            if (IsYaraFile(dirOrFile)) {
                candidates.push_back(dirOrFile);
            }
        } else {
            for (auto it = std::filesystem::recursive_directory_iterator(dirOrFile, ec);
                 !ec && it != std::filesystem::recursive_directory_iterator() && candidates.size() < kMaxImportedRulesPerRun;
                 it.increment(ec))
            {
                if (it->is_regular_file(ec) && IsYaraFile(it->path())) {
                    candidates.push_back(it->path());
                }
            }
        }

        uint32_t importedCount = 0;
        for (const auto& path : candidates) {
            FileUtils::FileStat stat{};
            if (!FileUtils::Stat(path.wstring(), stat) || stat.size > kMaxYaraFileBytes) {
                ShadowStrike::Utils::Logger::Warn("{} Skipping oversized YARA file {}", kLogPrefix, StringUtils::ToNarrow(path.wstring()));
                continue;
            }

            std::string content;
            if (!FileUtils::ReadAllTextUtf8(path.wstring(), content)) {
                ShadowStrike::Utils::Logger::Warn("{} Unable to read YARA file {}", kLogPrefix, StringUtils::ToNarrow(path.wstring()));
                continue;
            }

            HuntRule rule;
            rule.id = MakeStableId("yara-", std::format("{}|{}", StringUtils::ToNarrow(path.wstring()), content));
            rule.name = path.stem().string();
            rule.description = std::format("Imported YARA rule from {}", StringUtils::ToNarrow(path.wstring()));
            rule.format = RuleFormat::YARA;
            rule.severity = RuleSeverity::High;
            rule.status = RuleStatus::Active;
            rule.author = "Imported";
            rule.source = StringUtils::ToNarrow(path.wstring());
            rule.ruleContent = content;
            rule.createdAt = Clock::now();
            rule.updatedAt = rule.createdAt;
            rule.version = 1;

            if (AddRule(std::move(rule))) {
                ++importedCount;
            }
        }

        ShadowStrike::Utils::Logger::Info("{} Imported {} YARA rules from {}", kLogPrefix, importedCount, StringUtils::ToNarrow(dirOrFile.wstring()));
        return importedCount > 0;
    }

    [[nodiscard]] HuntResult EvaluateRule(const std::string& ruleId)
    {
        std::shared_lock lock(m_mutex);
        HuntResult result;
        result.queryOrRuleId = ruleId;
        result.executedAt = Clock::now();

        if (!m_initialized || ruleId.empty()) {
            return result;
        }

        const auto rule = GetRule(ruleId);
        if (!rule.has_value()) {
            ShadowStrike::Utils::Logger::Warn("{} Rule not found: {}", kLogPrefix, ruleId);
            return result;
        }

        result.queryOrRuleName = rule->name;
        switch (rule->format) {
        case RuleFormat::Sigma:
            return EvaluateSigmaRule(*rule);
        case RuleFormat::YARA: {
            const auto started = std::chrono::steady_clock::now();
            result.matches.clear();
            result.queryOrRuleName = rule->name;

            if (m_yaraRuleStore == nullptr || !m_yaraRuleStore->IsInitialized()) {
                ShadowStrike::Utils::Logger::Warn("{} YARA runtime is not available for {}", kLogPrefix, ruleId);
                result.executionTime = std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::steady_clock::now() - started);
                return result;
            }

            DatabaseError dbError;
            QueryResult events = DatabaseManager::Instance().Query(
                std::string(kSelectTelemetryBaseSql) + " ORDER BY timestamp_ns DESC;",
                &dbError);

            if (dbError.HasError()) {
                ShadowStrike::Utils::Logger::Error(
                    "{} Unable to query telemetry for YARA evaluation {}: {}",
                    kLogPrefix,
                    ruleId,
                    StringUtils::ToNarrow(dbError.message));
                result.executionTime = std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::steady_clock::now() - started);
                return result;
            }

            ShadowStrike::SignatureStore::YaraScanOptions scanOptions;
            scanOptions.namespaceFilter = {BuildYaraNamespace(rule->id)};
            scanOptions.fastMode = false;
            scanOptions.captureMatchData = false;

            while (events.Next()) {
                const TelemetryRow row = RowToTelemetryRow(events);
                const auto scanPath = ExtractTelemetryScanPath(row);
                if (!scanPath.has_value()) {
                    continue;
                }

                std::error_code fileEc;
                if (!std::filesystem::exists(*scanPath, fileEc) || std::filesystem::is_directory(*scanPath, fileEc)) {
                    continue;
                }

                const std::vector<YaraMatch> matches = m_yaraRuleStore->ScanFile(scanPath->wstring(), scanOptions);
                for (const auto& yaraMatch : matches) {
                    std::unordered_map<std::string, std::string> matchedFields;
                    matchedFields.emplace("path", StringUtils::ToNarrow(scanPath->wstring()));
                    matchedFields.emplace("yara_rule", yaraMatch.ruleName);
                    if (!yaraMatch.tags.empty()) {
                        matchedFields.emplace("tag", yaraMatch.tags.front());
                    }

                    HuntRule enrichedRule = *rule;
                    enrichedRule.severity = std::max(rule->severity, ConvertThreatLevel(yaraMatch.threatLevel));
                    result.matches.push_back(BuildMatchFromTelemetry(row, enrichedRule, matchedFields));
                }
            }

            result.totalMatches = result.matches.size();
            result.hasMore = false;
            result.executionTime = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - started);
            return result;
        }
        case RuleFormat::Custom:
        default:
            return EvaluateCustomRule(*rule);
        }
    }

    [[nodiscard]] std::vector<HuntResult> EvaluateAllActive()
    {
        std::shared_lock lock(m_mutex);
        std::vector<HuntResult> results;
        if (!m_initialized) {
            return results;
        }

        DatabaseError dbError;
        QueryResult resultSet = DatabaseManager::Instance().QueryWithParams(
            kSelectActiveRulesSql,
            &dbError,
            static_cast<int>(RuleStatus::Active));

        if (dbError.HasError()) {
            ShadowStrike::Utils::Logger::Error(
                "{} Failed to enumerate active rules: {}",
                kLogPrefix,
                StringUtils::ToNarrow(dbError.message));
            return results;
        }

        while (resultSet.Next()) {
            HuntRule rule = RowToHuntRule(resultSet);
            results.push_back(EvaluateRule(rule.id));
        }

        return results;
    }

private:
    mutable std::shared_mutex m_mutex;
    bool m_initialized = false;
    std::unique_ptr<YaraRuleStore> m_yaraRuleStore;
};

HuntRuleManager::HuntRuleManager()
    : m_impl(std::make_unique<HuntRuleManagerImpl>())
{
}

HuntRuleManager::~HuntRuleManager()
{
    if (m_impl != nullptr && m_impl->IsInitialized()) {
        Shutdown();
    }
}

HuntRuleManager& HuntRuleManager::Instance()
{
    static HuntRuleManager instance;
    return instance;
}

bool HuntRuleManager::Initialize()
{
    return m_impl->Initialize();
}

void HuntRuleManager::Shutdown()
{
    m_impl->Shutdown();
}

bool HuntRuleManager::IsInitialized() const noexcept
{
    return m_impl->IsInitialized();
}

bool HuntRuleManager::AddRule(HuntRule&& rule)
{
    return m_impl->AddRule(std::move(rule));
}

bool HuntRuleManager::RemoveRule(const std::string& ruleId)
{
    return m_impl->RemoveRule(ruleId);
}

bool HuntRuleManager::UpdateRuleStatus(const std::string& ruleId, RuleStatus status)
{
    return m_impl->UpdateRuleStatus(ruleId, status);
}

std::optional<HuntRule> HuntRuleManager::GetRule(const std::string& ruleId)
{
    return m_impl->GetRule(ruleId);
}

std::vector<HuntRule> HuntRuleManager::QueryRules(const RuleQueryParams& params)
{
    return m_impl->QueryRules(params);
}

uint64_t HuntRuleManager::GetRuleCount()
{
    return m_impl->GetRuleCount();
}

bool HuntRuleManager::ImportSigmaRules(const std::filesystem::path& dirOrFile)
{
    return m_impl->ImportSigmaRules(dirOrFile);
}

bool HuntRuleManager::ImportYaraRules(const std::filesystem::path& dirOrFile)
{
    return m_impl->ImportYaraRules(dirOrFile);
}

HuntResult HuntRuleManager::EvaluateRule(const std::string& ruleId)
{
    return m_impl->EvaluateRule(ruleId);
}

std::vector<HuntResult> HuntRuleManager::EvaluateAllActive()
{
    return m_impl->EvaluateAllActive();
}

} // namespace ShadowStrike::Products::PhantomEDR::ThreatHunting
