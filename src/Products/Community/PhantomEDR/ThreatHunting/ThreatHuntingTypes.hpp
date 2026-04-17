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

#include <chrono>
#include <cstdint>
#include <string>
#include <unordered_map>
#include <variant>
#include <vector>

namespace ShadowStrike::Products::PhantomEDR::ThreatHunting {

// ============================================================================
// IOC CLASSIFICATION
// ============================================================================

enum class IOCCategory : uint8_t {
    FileHash    = 0,
    IPv4        = 1,
    IPv6        = 2,
    Domain      = 3,
    URL         = 4,
    MutexName   = 5,
    RegistryKey = 6,
    NamedPipe   = 7,
    ProcessName = 8,
    Email       = 9,
    JA3         = 10,
    UserAgent   = 11
};

inline constexpr size_t kIOCCategoryCount = 12;

[[nodiscard]] constexpr const char* ToString(IOCCategory cat) noexcept {
    switch (cat) {
        case IOCCategory::FileHash:    return "FileHash";
        case IOCCategory::IPv4:        return "IPv4";
        case IOCCategory::IPv6:        return "IPv6";
        case IOCCategory::Domain:      return "Domain";
        case IOCCategory::URL:         return "URL";
        case IOCCategory::MutexName:   return "MutexName";
        case IOCCategory::RegistryKey: return "RegistryKey";
        case IOCCategory::NamedPipe:   return "NamedPipe";
        case IOCCategory::ProcessName: return "ProcessName";
        case IOCCategory::Email:       return "Email";
        case IOCCategory::JA3:         return "JA3";
        case IOCCategory::UserAgent:   return "UserAgent";
    }
    return "Unknown";
}

// ============================================================================
// HUNT RULE TYPES
// ============================================================================

enum class RuleFormat : uint8_t {
    Sigma  = 0,
    YARA   = 1,
    Custom = 2
};

[[nodiscard]] constexpr const char* ToString(RuleFormat fmt) noexcept {
    switch (fmt) {
        case RuleFormat::Sigma:  return "Sigma";
        case RuleFormat::YARA:   return "YARA";
        case RuleFormat::Custom: return "Custom";
    }
    return "Unknown";
}

enum class RuleSeverity : uint8_t {
    Informational = 0,
    Low           = 1,
    Medium        = 2,
    High          = 3,
    Critical      = 4
};

[[nodiscard]] constexpr const char* ToString(RuleSeverity sev) noexcept {
    switch (sev) {
        case RuleSeverity::Informational: return "Informational";
        case RuleSeverity::Low:           return "Low";
        case RuleSeverity::Medium:        return "Medium";
        case RuleSeverity::High:          return "High";
        case RuleSeverity::Critical:      return "Critical";
    }
    return "Unknown";
}

enum class RuleStatus : uint8_t {
    Draft    = 0,
    Active   = 1,
    Disabled = 2,
    Expired  = 3
};

[[nodiscard]] constexpr const char* ToString(RuleStatus st) noexcept {
    switch (st) {
        case RuleStatus::Draft:    return "Draft";
        case RuleStatus::Active:   return "Active";
        case RuleStatus::Disabled: return "Disabled";
        case RuleStatus::Expired:  return "Expired";
    }
    return "Unknown";
}

struct HuntRule {
    std::string id;
    std::string name;
    std::string description;
    RuleFormat  format   = RuleFormat::Sigma;
    RuleSeverity severity = RuleSeverity::Medium;
    RuleStatus  status    = RuleStatus::Active;
    std::string author;
    std::string source;
    std::string ruleContent;
    std::string mitreAttackId;
    std::vector<std::string> tags;
    std::chrono::system_clock::time_point createdAt{};
    std::chrono::system_clock::time_point updatedAt{};
    uint32_t version = 1;
};

// ============================================================================
// HUNT QUERY TYPES
// ============================================================================

enum class QueryField : uint8_t {
    Timestamp       = 0,
    Category        = 1,
    Severity        = 2,
    ProcessId       = 3,
    ProcessName     = 4,
    ProcessPath     = 5,
    ParentProcessId = 6,
    UserName        = 7,
    MitreAttackId   = 8,
    SourceIP        = 9,
    DestIP          = 10,
    DestPort        = 11,
    FilePath        = 12,
    FileHash        = 13,
    RegistryKey     = 14,
    RegistryValue   = 15,
    DomainName      = 16,
    CommandLine     = 17
};

enum class QueryOperator : uint8_t {
    Equals      = 0,
    NotEquals   = 1,
    Contains    = 2,
    StartsWith  = 3,
    EndsWith    = 4,
    GreaterThan = 5,
    LessThan    = 6,
    In          = 7,
    Regex       = 8,
    Exists      = 9
};

using QueryValue = std::variant<
    std::string,
    std::wstring,
    int64_t,
    uint64_t,
    double,
    std::vector<std::string>
>;

struct QueryCondition {
    QueryField    field    = QueryField::ProcessName;
    QueryOperator op       = QueryOperator::Equals;
    QueryValue    value;
    bool          negate   = false;
};

enum class QueryLogic : uint8_t {
    And = 0,
    Or  = 1
};

struct HuntQuery {
    std::string                  name;
    std::string                  description;
    std::vector<QueryCondition>  conditions;
    QueryLogic                   logic     = QueryLogic::And;
    uint32_t                     maxResults = 10000;
    uint32_t                     offset     = 0;
    std::chrono::system_clock::time_point startTime{};
    std::chrono::system_clock::time_point endTime{};
};

// ============================================================================
// HUNT RESULTS
// ============================================================================

struct HuntMatch {
    uint64_t    eventId     = 0;
    std::string ruleId;
    std::string ruleName;
    RuleSeverity severity    = RuleSeverity::Medium;
    std::string mitreAttackId;
    std::string description;
    std::chrono::system_clock::time_point matchTime{};
    std::chrono::system_clock::time_point eventTime{};
    uint32_t    processId   = 0;
    std::wstring processName;
    std::wstring processPath;
    std::wstring userName;
    std::unordered_map<std::string, std::string> matchedFields;
};

struct HuntResult {
    std::string                queryOrRuleId;
    std::string                queryOrRuleName;
    std::vector<HuntMatch>     matches;
    uint64_t                   totalMatches = 0;
    bool                       hasMore      = false;
    std::chrono::milliseconds  executionTime{};
    std::chrono::system_clock::time_point executedAt{};
};

// ============================================================================
// IOC SCAN TYPES
// ============================================================================

struct IOCEntry {
    std::string  value;
    IOCCategory  category  = IOCCategory::FileHash;
    std::string  source;
    std::string  description;
    RuleSeverity severity   = RuleSeverity::High;
    std::chrono::system_clock::time_point addedAt{};
    std::chrono::system_clock::time_point expiresAt{};
};

struct IOCScanResult {
    IOCEntry    ioc;
    uint64_t    eventId     = 0;
    std::chrono::system_clock::time_point eventTime{};
    uint32_t    processId   = 0;
    std::wstring processName;
    std::wstring userName;
    std::string  matchContext;
};

struct IOCScanSummary {
    std::vector<IOCScanResult>  hits;
    uint64_t totalIOCsScanned   = 0;
    uint64_t totalEventsScanned = 0;
    uint64_t totalHits          = 0;
    std::chrono::milliseconds   executionTime{};
    std::chrono::system_clock::time_point startedAt{};
    std::chrono::system_clock::time_point completedAt{};
};

// ============================================================================
// HUNT SCHEDULER TYPES
// ============================================================================

enum class ScheduleFrequency : uint8_t {
    Once       = 0,
    Hourly     = 1,
    Daily      = 2,
    Weekly     = 3,
    Custom     = 4
};

[[nodiscard]] constexpr const char* ToString(ScheduleFrequency freq) noexcept {
    switch (freq) {
        case ScheduleFrequency::Once:    return "Once";
        case ScheduleFrequency::Hourly:  return "Hourly";
        case ScheduleFrequency::Daily:   return "Daily";
        case ScheduleFrequency::Weekly:  return "Weekly";
        case ScheduleFrequency::Custom:  return "Custom";
    }
    return "Unknown";
}

enum class HuntJobStatus : uint8_t {
    Pending   = 0,
    Running   = 1,
    Completed = 2,
    Failed    = 3,
    Cancelled = 4,
    Paused    = 5
};

[[nodiscard]] constexpr const char* ToString(HuntJobStatus st) noexcept {
    switch (st) {
        case HuntJobStatus::Pending:   return "Pending";
        case HuntJobStatus::Running:   return "Running";
        case HuntJobStatus::Completed: return "Completed";
        case HuntJobStatus::Failed:    return "Failed";
        case HuntJobStatus::Cancelled: return "Cancelled";
        case HuntJobStatus::Paused:    return "Paused";
    }
    return "Unknown";
}

struct ScheduledHunt {
    std::string         id;
    std::string         name;
    std::string         description;
    std::string         queryOrRuleId;
    ScheduleFrequency   frequency      = ScheduleFrequency::Daily;
    std::chrono::seconds customInterval{3600};
    HuntJobStatus       lastStatus     = HuntJobStatus::Pending;
    std::chrono::system_clock::time_point nextRunTime{};
    std::chrono::system_clock::time_point lastRunTime{};
    std::chrono::system_clock::time_point createdAt{};
    bool                enabled        = true;
    uint32_t            maxResultsCached = 10000;
    uint32_t            consecutiveFailures = 0;
};

struct HuntJobRecord {
    std::string         jobId;
    std::string         scheduleId;
    HuntJobStatus       status = HuntJobStatus::Pending;
    HuntResult          result;
    std::string         errorMessage;
    std::chrono::system_clock::time_point startedAt{};
    std::chrono::system_clock::time_point completedAt{};
};

// ============================================================================
// RULE QUERY PARAMS (for HuntRuleManager)
// ============================================================================

struct RuleQueryParams {
    std::optional<RuleFormat>   format;
    std::optional<RuleStatus>   status;
    std::optional<RuleSeverity> minSeverity;
    std::optional<std::string>  tagContains;
    std::optional<std::string>  namePattern;
    uint32_t maxResults = 100;
    uint32_t offset     = 0;
};

} // namespace ShadowStrike::Products::PhantomEDR::ThreatHunting
