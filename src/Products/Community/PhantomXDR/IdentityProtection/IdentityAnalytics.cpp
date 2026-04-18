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
#include "Products/Community/PhantomXDR/IdentityProtection/IdentityAnalytics.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <filesystem>
#include <format>
#include <map>
#include <numbers>
#include <optional>
#include <set>
#include <shared_mutex>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#include "PhantomCore/Database/DatabaseManager.hpp"
#include "PhantomCore/Utils/FileUtils.hpp"
#include "PhantomCore/Utils/Logger.hpp"
#include "PhantomCore/Utils/StringUtils.hpp"

namespace ShadowStrike::Products::PhantomXDR::IdentityProtection {

namespace {

using ShadowStrike::Database::DatabaseConfig;
using ShadowStrike::Database::DatabaseError;
using ShadowStrike::Database::DatabaseManager;
using ShadowStrike::Database::QueryResult;
using ShadowStrike::Utils::Logger;
namespace FileUtils = ShadowStrike::Utils::FileUtils;
namespace SU = ShadowStrike::Utils::StringUtils;

constexpr std::string_view kLogPrefix = "[IdentityProtection::IdentityAnalytics]";
constexpr uint32_t kDefaultBaselineDays = 7;
constexpr size_t kDefaultLimit = 100;
constexpr size_t kMaxLimit = 500;
constexpr double kHighRiskThreshold = 70.0;
constexpr double kImpossibleTravelVelocityKmh = 900.0;
constexpr double kImpossibleTravelMinimumDistanceKm = 300.0;

constexpr std::string_view kCreateProfilesTableSql = R"SQL(
    CREATE TABLE IF NOT EXISTS identity_behavior_profiles (
        user_name TEXT PRIMARY KEY,
        normal_logon_times TEXT NOT NULL,
        normal_workstations TEXT NOT NULL,
        normal_source_ips TEXT NOT NULL,
        typical_resources TEXT NOT NULL,
        risk_score REAL NOT NULL,
        baseline_event_count INTEGER NOT NULL,
        last_updated INTEGER NOT NULL
    );
)SQL";

constexpr std::string_view kCreateAnomaliesTableSql = R"SQL(
    CREATE TABLE IF NOT EXISTS identity_analytics_alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp INTEGER NOT NULL,
        threat_type INTEGER NOT NULL,
        severity INTEGER NOT NULL,
        evidence TEXT NOT NULL,
        affected_user TEXT,
        source_ip TEXT,
        mitre_technique TEXT NOT NULL,
        risk_score REAL NOT NULL,
        module_name TEXT NOT NULL
    );
)SQL";

constexpr std::string_view kCreateIndexesSql = R"SQL(
    CREATE INDEX IF NOT EXISTS idx_identity_behavior_profiles_risk ON identity_behavior_profiles(risk_score DESC);
    CREATE INDEX IF NOT EXISTS idx_identity_analytics_alerts_time ON identity_analytics_alerts(timestamp DESC, threat_type);
)SQL";

constexpr std::string_view kUpsertProfileSql = R"SQL(
    INSERT INTO identity_behavior_profiles(
        user_name, normal_logon_times, normal_workstations, normal_source_ips,
        typical_resources, risk_score, baseline_event_count, last_updated
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(user_name) DO UPDATE SET
        normal_logon_times = excluded.normal_logon_times,
        normal_workstations = excluded.normal_workstations,
        normal_source_ips = excluded.normal_source_ips,
        typical_resources = excluded.typical_resources,
        risk_score = excluded.risk_score,
        baseline_event_count = excluded.baseline_event_count,
        last_updated = excluded.last_updated;
)SQL";

constexpr std::string_view kInsertAlertSql = R"SQL(
    INSERT INTO identity_analytics_alerts(
        timestamp, threat_type, severity, evidence, affected_user, source_ip, mitre_technique, risk_score, module_name
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'IdentityAnalytics');
)SQL";

[[nodiscard]] int64_t ToUnixSeconds(const IdentityTimestamp value) noexcept {
    return std::chrono::duration_cast<std::chrono::seconds>(value.time_since_epoch()).count();
}

[[nodiscard]] IdentityTimestamp FromUnixSeconds(const int64_t value) noexcept {
    return IdentityTimestamp{std::chrono::seconds{value}};
}

[[nodiscard]] size_t ClampLimit(const size_t limit) {
    return std::clamp(limit == 0 ? kDefaultLimit : limit, static_cast<size_t>(1), kMaxLimit);
}

[[nodiscard]] std::wstring GetProgramDataRoot() {
    const DWORD length = ::GetEnvironmentVariableW(L"ProgramData", nullptr, 0);
    if (length == 0U) {
        return L"C:\\ProgramData";
    }

    std::wstring buffer(static_cast<size_t>(length), L'\0');
    const DWORD written = ::GetEnvironmentVariableW(L"ProgramData", buffer.data(), length);
    if (written == 0U) {
        return L"C:\\ProgramData";
    }

    if (!buffer.empty() && buffer.back() == L'\0') {
        buffer.pop_back();
    }

    return buffer;
}

[[nodiscard]] std::wstring GetDefaultDatabasePath() {
    return GetProgramDataRoot() + L"\\ShadowStrike\\PhantomXDR\\identity_protection.db";
}

[[nodiscard]] bool EnsureDatabaseReady(const std::wstring& databasePath, DatabaseError* dbErr) {
    auto& db = DatabaseManager::Instance();
    if (db.IsInitialized()) {
        return true;
    }

    FileUtils::Error fileErr;
    const std::filesystem::path dbPath{databasePath};
    if (!FileUtils::CreateDirectories(dbPath.parent_path().wstring(), &fileErr)) {
        Logger::Error("{} unable to create database directory: {}", kLogPrefix, fileErr.message);
        return false;
    }

    DatabaseConfig config{};
    config.databasePath = databasePath;
    config.enableWAL = true;
    config.minConnections = 1;
    config.maxConnections = 6;
    config.autoBackup = false;
    config.enableMemoryMappedIO = true;
    config.cacheSizeKB = 8192;
    return db.Initialize(config, dbErr);
}

void LogDatabaseError(std::string_view context, const DatabaseError& error) {
    Logger::Error(
        "{} {} sqliteCode={} context={} message={}",
        kLogPrefix,
        context,
        error.sqliteCode,
        SU::ToNarrow(error.context),
        SU::ToNarrow(error.message));
}

[[nodiscard]] std::wstring Lower(std::wstring value) {
    SU::ToLower(value);
    return value;
}

[[nodiscard]] std::wstring Trimmed(std::wstring value) {
    SU::Trim(value);
    return value;
}

[[nodiscard]] std::string SerializeWideList(const std::vector<std::wstring>& values) {
    return SU::ToNarrow(SU::Join(values, L";"));
}

[[nodiscard]] std::vector<std::wstring> DeserializeWideList(std::wstring_view serialized) {
    if (serialized.empty()) {
        return {};
    }

    auto values = SU::Split(serialized, L";");
    for (auto& value : values) {
        SU::Trim(value);
    }

    values.erase(std::remove_if(values.begin(), values.end(), [](const std::wstring& item) {
        return item.empty();
    }), values.end());
    return values;
}

[[nodiscard]] std::string SerializeHours(const std::vector<uint8_t>& hours) {
    std::vector<std::wstring> values;
    values.reserve(hours.size());
    for (const auto hour : hours) {
        values.push_back(std::to_wstring(hour));
    }
    return SU::ToNarrow(SU::Join(values, L","));
}

[[nodiscard]] std::vector<uint8_t> DeserializeHours(std::wstring_view serialized) {
    std::vector<uint8_t> hours;
    if (serialized.empty()) {
        return hours;
    }

    auto tokens = SU::Split(serialized, L",");
    for (const auto& token : tokens) {
        if (token.empty()) {
            continue;
        }
        const unsigned long parsed = std::wcstoul(token.c_str(), nullptr, 10);
        if (parsed <= 23UL) {
            hours.push_back(static_cast<uint8_t>(parsed));
        }
    }

    std::sort(hours.begin(), hours.end());
    hours.erase(std::unique(hours.begin(), hours.end()), hours.end());
    return hours;
}

[[nodiscard]] std::wstring NullSafeWString(const QueryResult& result, const char* columnName) {
    return result.IsNull(columnName) ? std::wstring{} : result.GetWString(columnName);
}

[[nodiscard]] int ExtractHour(const IdentityTimestamp timestamp) {
    const std::time_t rawTime = std::chrono::system_clock::to_time_t(timestamp);
    std::tm utc{};
#if defined(_WIN32)
    gmtime_s(&utc, &rawTime);
#else
    gmtime_r(&rawTime, &utc);
#endif
    return utc.tm_hour;
}

struct GeoLocation {
    std::wstring region;
    double latitude{0.0};
    double longitude{0.0};
    bool known{false};
};

[[nodiscard]] GeoLocation ApproximateLocationFromIp(std::wstring ipAddress) {
    ipAddress = Trimmed(std::move(ipAddress));
    if (ipAddress.empty() || ipAddress == L"-" || ipAddress == L"127.0.0.1" || ipAddress == L"::1") {
        return {};
    }

    const auto octets = SU::Split(ipAddress, L".");
    if (octets.size() < 2) {
        return {};
    }

    const int first = static_cast<int>(std::wcstol(octets[0].c_str(), nullptr, 10));
    const int second = static_cast<int>(std::wcstol(octets[1].c_str(), nullptr, 10));

    if (first == 10 || first == 192 || first == 172) {
        return GeoLocation{
            std::format(L"internal-{}", second),
            35.0 + (second % 25),
            -120.0 + (second % 40),
            true
        };
    }

    if (first < 64) {
        return {L"na-east", 40.7128, -74.0060, true};
    }
    if (first < 96) {
        return {L"na-west", 37.7749, -122.4194, true};
    }
    if (first < 128) {
        return {L"emea", 51.5074, -0.1278, true};
    }
    if (first < 160) {
        return {L"apac", 1.3521, 103.8198, true};
    }
    if (first < 192) {
        return {L"latam", -23.5505, -46.6333, true};
    }

    return {L"global-other", 48.8566, 2.3522, true};
}

[[nodiscard]] double DegreesToRadians(const double degrees) {
    return degrees * std::numbers::pi_v<double> / 180.0;
}

[[nodiscard]] double HaversineKilometers(const GeoLocation& left, const GeoLocation& right) {
    const double deltaLat = DegreesToRadians(right.latitude - left.latitude);
    const double deltaLon = DegreesToRadians(right.longitude - left.longitude);
    const double lat1 = DegreesToRadians(left.latitude);
    const double lat2 = DegreesToRadians(right.latitude);

    const double sinLat = std::sin(deltaLat / 2.0);
    const double sinLon = std::sin(deltaLon / 2.0);
    const double a = sinLat * sinLat + std::cos(lat1) * std::cos(lat2) * sinLon * sinLon;
    const double c = 2.0 * std::atan2(std::sqrt(a), std::sqrt(1.0 - a));
    return 6371.0 * c;
}

[[nodiscard]] bool ContainsInsensitive(std::wstring_view haystack, std::wstring_view needle) {
    return SU::IContains(haystack, needle);
}

[[nodiscard]] bool IsPrivilegedGroup(std::wstring value) {
    value = Lower(Trimmed(std::move(value)));
    return value == L"domain admins" ||
           value == L"enterprise admins" ||
           value == L"schema admins" ||
           value == L"administrators";
}

[[nodiscard]] uint32_t SeverityForThreat(const IdentityThreat threat, const double riskScore) {
    const uint32_t base = static_cast<uint32_t>(std::clamp(riskScore, 0.0, 100.0));
    switch (threat) {
    case IdentityThreat::ImpossibleTravel:
        return std::max<uint32_t>(80, base);
    case IdentityThreat::PrivilegeEscalation:
        return std::max<uint32_t>(90, base);
    case IdentityThreat::AnomalousAccess:
        return std::max<uint32_t>(65, base);
    default:
        return std::max<uint32_t>(60, base);
    }
}

[[nodiscard]] std::wstring MitreTechniqueForThreat(const IdentityThreat threat) {
    switch (threat) {
    case IdentityThreat::ImpossibleTravel:
        return L"T1078";
    case IdentityThreat::AnomalousAccess:
        return L"T1078.004";
    case IdentityThreat::PrivilegeEscalation:
        return L"T1098";
    default:
        return L"T1078";
    }
}

[[nodiscard]] UserBehaviorProfile BuildProfileFromEvents(
    const std::wstring& userName,
    const std::vector<LogonEvent>& events) {
    UserBehaviorProfile profile{};
    profile.userName = userName;

    std::set<uint8_t> hours;
    std::unordered_set<std::wstring> workstations;
    std::unordered_set<std::wstring> sourceIps;
    std::unordered_set<std::wstring> resources;

    for (const auto& event : events) {
        if (!event.success) {
            continue;
        }

        hours.insert(static_cast<uint8_t>(ExtractHour(event.timestamp)));
        if (!event.workstation.empty()) {
            workstations.insert(Lower(event.workstation));
            resources.insert(Lower(event.workstation));
        }
        if (!event.sourceIP.empty()) {
            sourceIps.insert(Lower(event.sourceIP));
        }
        if (!event.sourceHost.empty()) {
            resources.insert(Lower(event.sourceHost));
        }
    }

    profile.normalLogonTimes.assign(hours.begin(), hours.end());
    profile.normalWorkstations.assign(workstations.begin(), workstations.end());
    profile.normalSourceIPs.assign(sourceIps.begin(), sourceIps.end());
    profile.typicalAccessedResources.assign(resources.begin(), resources.end());
    std::sort(profile.normalWorkstations.begin(), profile.normalWorkstations.end());
    std::sort(profile.normalSourceIPs.begin(), profile.normalSourceIPs.end());
    std::sort(profile.typicalAccessedResources.begin(), profile.typicalAccessedResources.end());
    profile.riskScore = 0.0;
    return profile;
}

[[nodiscard]] IdentityThreat ThreatFromInt(const int value) {
    if (value < 0 || value > static_cast<int>(IdentityThreat::PrivilegeEscalation)) {
        return IdentityThreat::None;
    }
    return static_cast<IdentityThreat>(value);
}

} // namespace

class IdentityAnalyticsImpl final {
public:
    [[nodiscard]] bool Initialize(const std::wstring& requestedDatabasePath, const uint32_t baselineLearningDays) {
        std::unique_lock lock(m_mutex);
        if (m_initialized.load(std::memory_order_acquire)) {
            return true;
        }

        DatabaseError dbError{};
        m_databasePath = requestedDatabasePath.empty() ? GetDefaultDatabasePath() : requestedDatabasePath;
        if (!EnsureDatabaseReady(m_databasePath, &dbError)) {
            if (dbError.HasError()) {
                LogDatabaseError("Initialize", dbError);
            }
            return false;
        }

        const std::array<std::string_view, 2> statements{
            kCreateProfilesTableSql,
            kCreateAnomaliesTableSql
        };

        auto& db = DatabaseManager::Instance();
        for (const auto statement : statements) {
            if (!db.Execute(statement, &dbError)) {
                LogDatabaseError("InitializeSchema", dbError);
                return false;
            }
        }

        if (!db.Execute(kCreateIndexesSql, &dbError)) {
            LogDatabaseError("InitializeIndexes", dbError);
            return false;
        }

        m_statistics.baselineLearningDays = baselineLearningDays == 0 ? kDefaultBaselineDays : baselineLearningDays;
        m_initialized.store(true, std::memory_order_release);
        lock.unlock();

        if (!UpdateProfile(L"")) {
            Logger::Warn("{} initial baseline build completed with gaps", kLogPrefix);
        }

        Logger::Info(
            "{} initialized baselineDays={} databasePath={}",
            kLogPrefix,
            m_statistics.baselineLearningDays,
            SU::ToNarrow(m_databasePath));
        return true;
    }

    void Shutdown() {
        std::unique_lock lock(m_mutex);
        m_profiles.clear();
        m_lastAnomalyFingerprint.clear();
        m_initialized.store(false, std::memory_order_release);
        m_databasePath.clear();
    }

    [[nodiscard]] bool IsInitialized() const noexcept {
        return m_initialized.load(std::memory_order_acquire);
    }

    [[nodiscard]] bool UpdateProfile(std::wstring_view userName) {
        if (!m_initialized.load(std::memory_order_acquire)) {
            Logger::Warn("{} UpdateProfile called before Initialize", kLogPrefix);
            return false;
        }

        DatabaseError dbError{};
        const auto baselineStart = std::chrono::system_clock::now() - std::chrono::hours{24 * m_statistics.baselineLearningDays};
        auto& db = DatabaseManager::Instance();

        std::string sql =
            "SELECT timestamp, user_name, domain, logon_type, source_ip, source_host, workstation, success, event_id, logon_id "
            "FROM identity_logons WHERE timestamp >= ? AND success = 1";
        if (!userName.empty()) {
            sql += " AND user_name = ?";
        }
        sql += " ORDER BY user_name ASC, timestamp DESC";

        QueryResult result = userName.empty()
            ? db.QueryWithParams(sql, &dbError, ToUnixSeconds(baselineStart))
            : db.QueryWithParams(sql, &dbError, ToUnixSeconds(baselineStart), SU::ToNarrow(userName));
        if (dbError.HasError()) {
            LogDatabaseError("UpdateProfile", dbError);
            return false;
        }

        std::unordered_map<std::wstring, std::vector<LogonEvent>> eventsByUser;
        while (result.Next()) {
            LogonEvent event{};
            event.timestamp = FromUnixSeconds(result.GetInt64("timestamp"));
            event.userName = NullSafeWString(result, "user_name");
            event.domain = NullSafeWString(result, "domain");
            event.logonType = static_cast<LogonType>(result.GetInt("logon_type"));
            event.sourceIP = NullSafeWString(result, "source_ip");
            event.sourceHost = NullSafeWString(result, "source_host");
            event.workstation = NullSafeWString(result, "workstation");
            event.success = result.GetInt("success") != 0;
            event.eventId = static_cast<uint32_t>(result.GetInt("event_id"));
            event.logonId = NullSafeWString(result, "logon_id");
            eventsByUser[event.userName].push_back(std::move(event));
        }

        bool success = true;
        for (auto& [account, events] : eventsByUser) {
            auto profile = BuildProfileFromEvents(account, events);
            profile.riskScore = GetPersistedRiskScore(account);
            success &= PersistProfile(profile, events.size());

            std::unique_lock lock(m_mutex);
            m_profiles[Lower(account)] = std::move(profile);
            ++m_statistics.profilesBuilt;
        }

        if (userName.empty()) {
            ScanPrivilegeEscalationsUnlocked();
        }

        return success;
    }

    [[nodiscard]] std::vector<IdentityAlert> AnalyzeLogon(const LogonEvent& logon) {
        std::vector<IdentityAlert> alerts;
        if (!m_initialized.load(std::memory_order_acquire)) {
            Logger::Warn("{} AnalyzeLogon called before Initialize", kLogPrefix);
            return alerts;
        }

        const std::wstring normalizedUser = Lower(logon.userName);
        UserBehaviorProfile profile = GetOrBuildProfileUnlocked(normalizedUser);
        if (profile.userName.empty()) {
            return alerts;
        }

        double riskScore = profile.riskScore;
        std::wstring evidenceParts;

        const int eventHour = ExtractHour(logon.timestamp);
        if (!profile.normalLogonTimes.empty() &&
            std::find(profile.normalLogonTimes.begin(), profile.normalLogonTimes.end(), static_cast<uint8_t>(eventHour)) == profile.normalLogonTimes.end()) {
            riskScore += 20.0;
            evidenceParts += std::format(L"hour {} is outside baseline; ", eventHour);
        }

        if (!logon.workstation.empty()) {
            const std::wstring workstation = Lower(logon.workstation);
            if (!profile.normalWorkstations.empty() &&
                std::find(profile.normalWorkstations.begin(), profile.normalWorkstations.end(), workstation) == profile.normalWorkstations.end()) {
                riskScore += 22.0;
                evidenceParts += std::format(L"workstation '{}' not present in profile; ", logon.workstation);
            }
        }

        if (!logon.sourceIP.empty()) {
            const std::wstring sourceIp = Lower(logon.sourceIP);
            if (!profile.normalSourceIPs.empty() &&
                std::find(profile.normalSourceIPs.begin(), profile.normalSourceIPs.end(), sourceIp) == profile.normalSourceIPs.end()) {
                riskScore += 26.0;
                evidenceParts += std::format(L"source IP '{}' not present in profile; ", logon.sourceIP);
            }
        }

        if (!logon.sourceHost.empty()) {
            const std::wstring resource = Lower(logon.sourceHost);
            if (!profile.typicalAccessedResources.empty() &&
                std::find(profile.typicalAccessedResources.begin(), profile.typicalAccessedResources.end(), resource) == profile.typicalAccessedResources.end()) {
                riskScore += 12.0;
                evidenceParts += std::format(L"resource '{}' not present in profile; ", logon.sourceHost);
            }
        }

        if (const auto travelAlert = BuildImpossibleTravelAlert(profile.userName, logon, riskScore)) {
            alerts.push_back(*travelAlert);
            riskScore = std::max(riskScore, static_cast<double>(travelAlert->severity));
        }

        riskScore = std::clamp(riskScore, 0.0, 100.0);
        if (riskScore >= 45.0 && !evidenceParts.empty()) {
            IdentityAlert alert{};
            alert.timestamp = logon.timestamp;
            alert.threatType = IdentityThreat::AnomalousAccess;
            alert.severity = SeverityForThreat(IdentityThreat::AnomalousAccess, riskScore);
            alert.evidence = evidenceParts;
            alert.affectedUser = logon.userName;
            alert.sourceIP = logon.sourceIP;
            alert.mitreTechnique = MitreTechniqueForThreat(IdentityThreat::AnomalousAccess);
            alerts.push_back(std::move(alert));
        }

        for (const auto& alert : alerts) {
            PersistAlert(alert, riskScore);
            std::unique_lock lock(m_mutex);
            ++m_statistics.anomaliesRaised;
            if (alert.threatType == IdentityThreat::ImpossibleTravel) {
                ++m_statistics.impossibleTravelDetections;
            } else if (alert.threatType == IdentityThreat::AnomalousAccess) {
                ++m_statistics.anomalousAccessDetections;
            } else if (alert.threatType == IdentityThreat::PrivilegeEscalation) {
                ++m_statistics.privilegeEscalationDetections;
            }
        }

        {
            std::unique_lock lock(m_mutex);
            ++m_statistics.logonsAnalyzed;
            auto& mutableProfile = m_profiles[normalizedUser];
            mutableProfile = profile;
            mutableProfile.riskScore = riskScore;
        }

        (void)PersistProfile(profile, 0U, riskScore);
        UpdateHighRiskCount();
        return alerts;
    }

    [[nodiscard]] std::optional<UserBehaviorProfile> GetUserProfile(std::wstring_view userName) const {
        if (!m_initialized.load(std::memory_order_acquire) || userName.empty()) {
            return std::nullopt;
        }

        const std::wstring normalized = Lower(std::wstring{userName});
        {
            std::shared_lock lock(m_mutex);
            const auto it = m_profiles.find(normalized);
            if (it != m_profiles.end()) {
                return it->second;
            }
        }

        DatabaseError dbError{};
        auto result = DatabaseManager::Instance().QueryWithParams(
            "SELECT user_name, normal_logon_times, normal_workstations, normal_source_ips, typical_resources, risk_score "
            "FROM identity_behavior_profiles WHERE user_name = ? LIMIT 1",
            &dbError,
            SU::ToNarrow(userName));
        if (dbError.HasError()) {
            LogDatabaseError("GetUserProfile", dbError);
            return std::nullopt;
        }

        if (!result.Next()) {
            return std::nullopt;
        }

        UserBehaviorProfile profile{};
        profile.userName = NullSafeWString(result, "user_name");
        profile.normalLogonTimes = DeserializeHours(NullSafeWString(result, "normal_logon_times"));
        profile.normalWorkstations = DeserializeWideList(NullSafeWString(result, "normal_workstations"));
        profile.normalSourceIPs = DeserializeWideList(NullSafeWString(result, "normal_source_ips"));
        profile.typicalAccessedResources = DeserializeWideList(NullSafeWString(result, "typical_resources"));
        profile.riskScore = result.IsNull("risk_score") ? 0.0 : result.GetDouble("risk_score");
        return profile;
    }

    [[nodiscard]] std::vector<UserBehaviorProfile> GetHighRiskUsers(const double minimumRiskScore, const size_t limit) const {
        std::vector<UserBehaviorProfile> profiles;
        if (!m_initialized.load(std::memory_order_acquire)) {
            return profiles;
        }

        DatabaseError dbError{};
        const std::string sql =
            "SELECT user_name, normal_logon_times, normal_workstations, normal_source_ips, typical_resources, risk_score "
            "FROM identity_behavior_profiles WHERE risk_score >= ? "
            "ORDER BY risk_score DESC LIMIT " + std::to_string(ClampLimit(limit));
        auto result = DatabaseManager::Instance().QueryWithParams(sql, &dbError, minimumRiskScore);
        if (dbError.HasError()) {
            LogDatabaseError("GetHighRiskUsers", dbError);
            return profiles;
        }

        while (result.Next()) {
            UserBehaviorProfile profile{};
            profile.userName = NullSafeWString(result, "user_name");
            profile.normalLogonTimes = DeserializeHours(NullSafeWString(result, "normal_logon_times"));
            profile.normalWorkstations = DeserializeWideList(NullSafeWString(result, "normal_workstations"));
            profile.normalSourceIPs = DeserializeWideList(NullSafeWString(result, "normal_source_ips"));
            profile.typicalAccessedResources = DeserializeWideList(NullSafeWString(result, "typical_resources"));
            profile.riskScore = result.IsNull("risk_score") ? 0.0 : result.GetDouble("risk_score");
            profiles.push_back(std::move(profile));
        }

        return profiles;
    }

    [[nodiscard]] std::vector<IdentityAlert> GetAnomalies(const size_t limit) const {
        std::vector<IdentityAlert> alerts;
        if (!m_initialized.load(std::memory_order_acquire)) {
            return alerts;
        }

        const_cast<IdentityAnalyticsImpl*>(this)->ScanPrivilegeEscalationsUnlocked();

        DatabaseError dbError{};
        const std::string sql =
            "SELECT timestamp, threat_type, severity, evidence, affected_user, source_ip, mitre_technique "
            "FROM identity_analytics_alerts WHERE module_name = 'IdentityAnalytics' "
            "ORDER BY timestamp DESC LIMIT " + std::to_string(ClampLimit(limit));
        auto result = DatabaseManager::Instance().Query(sql, &dbError);
        if (dbError.HasError()) {
            LogDatabaseError("GetAnomalies", dbError);
            return alerts;
        }

        while (result.Next()) {
            IdentityAlert alert{};
            alert.timestamp = FromUnixSeconds(result.GetInt64("timestamp"));
            alert.threatType = ThreatFromInt(result.GetInt("threat_type"));
            alert.severity = static_cast<uint32_t>(result.GetInt("severity"));
            alert.evidence = NullSafeWString(result, "evidence");
            alert.affectedUser = NullSafeWString(result, "affected_user");
            alert.sourceIP = NullSafeWString(result, "source_ip");
            alert.mitreTechnique = NullSafeWString(result, "mitre_technique");
            alerts.push_back(std::move(alert));
        }

        return alerts;
    }

    [[nodiscard]] IdentityAnalyticsStatistics GetStatistics() const {
        std::shared_lock lock(m_mutex);
        return m_statistics;
    }

private:
    [[nodiscard]] UserBehaviorProfile GetOrBuildProfileUnlocked(const std::wstring& normalizedUser) {
        {
            std::shared_lock lock(m_mutex);
            const auto it = m_profiles.find(normalizedUser);
            if (it != m_profiles.end()) {
                return it->second;
            }
        }

        (void)UpdateProfile(normalizedUser);

        std::shared_lock lock(m_mutex);
        const auto it = m_profiles.find(normalizedUser);
        return it != m_profiles.end() ? it->second : UserBehaviorProfile{};
    }

    [[nodiscard]] double GetPersistedRiskScore(std::wstring_view userName) const {
        DatabaseError dbError{};
        auto result = DatabaseManager::Instance().QueryWithParams(
            "SELECT risk_score FROM identity_behavior_profiles WHERE user_name = ? LIMIT 1",
            &dbError,
            SU::ToNarrow(userName));
        if (dbError.HasError()) {
            LogDatabaseError("GetPersistedRiskScore", dbError);
            return 0.0;
        }

        return result.Next() ? result.GetDouble("risk_score") : 0.0;
    }

    [[nodiscard]] bool PersistProfile(const UserBehaviorProfile& profile, const size_t baselineEventCount, std::optional<double> riskOverride = std::nullopt) const {
        DatabaseError dbError{};
        const double risk = riskOverride.has_value() ? *riskOverride : profile.riskScore;
        const bool success = DatabaseManager::Instance().ExecuteWithParams(
            kUpsertProfileSql,
            &dbError,
            SU::ToNarrow(profile.userName),
            SerializeHours(profile.normalLogonTimes),
            SerializeWideList(profile.normalWorkstations),
            SerializeWideList(profile.normalSourceIPs),
            SerializeWideList(profile.typicalAccessedResources),
            risk,
            static_cast<int64_t>(baselineEventCount),
            ToUnixSeconds(std::chrono::system_clock::now()));
        if (!success) {
            LogDatabaseError("PersistProfile", dbError);
        }
        return success;
    }

    [[nodiscard]] std::optional<IdentityAlert> BuildImpossibleTravelAlert(
        std::wstring_view userName,
        const LogonEvent& currentLogon,
        const double currentRisk) const {
        if (currentLogon.sourceIP.empty()) {
            return std::nullopt;
        }

        DatabaseError dbError{};
        auto result = DatabaseManager::Instance().QueryWithParams(
            "SELECT timestamp, source_ip FROM identity_logons "
            "WHERE user_name = ? AND success = 1 AND source_ip IS NOT NULL AND source_ip <> '' "
            "AND timestamp < ? ORDER BY timestamp DESC LIMIT 1",
            &dbError,
            SU::ToNarrow(userName),
            ToUnixSeconds(currentLogon.timestamp));
        if (dbError.HasError()) {
            LogDatabaseError("BuildImpossibleTravelAlert", dbError);
            return std::nullopt;
        }

        if (!result.Next()) {
            return std::nullopt;
        }

        const auto previousTimestamp = FromUnixSeconds(result.GetInt64("timestamp"));
        const std::wstring previousIp = NullSafeWString(result, "source_ip");
        if (previousIp.empty() || SU::IEquals(previousIp, currentLogon.sourceIP)) {
            return std::nullopt;
        }

        const GeoLocation previousLocation = ApproximateLocationFromIp(previousIp);
        const GeoLocation currentLocation = ApproximateLocationFromIp(currentLogon.sourceIP);
        if (!previousLocation.known || !currentLocation.known) {
            return std::nullopt;
        }

        const double distanceKm = HaversineKilometers(previousLocation, currentLocation);
        if (distanceKm < kImpossibleTravelMinimumDistanceKm) {
            return std::nullopt;
        }

        const auto elapsedSeconds = std::chrono::duration_cast<std::chrono::seconds>(currentLogon.timestamp - previousTimestamp).count();
        if (elapsedSeconds <= 0) {
            return std::nullopt;
        }

        const double velocityKmh = distanceKm / (static_cast<double>(elapsedSeconds) / 3600.0);
        if (velocityKmh < kImpossibleTravelVelocityKmh) {
            return std::nullopt;
        }

        IdentityAlert alert{};
        alert.timestamp = currentLogon.timestamp;
        alert.threatType = IdentityThreat::ImpossibleTravel;
        alert.severity = SeverityForThreat(IdentityThreat::ImpossibleTravel, std::max(currentRisk, 85.0));
        alert.evidence = std::format(
            L"user '{}' authenticated from '{}' after '{}' within {} seconds (estimated {:.0f} km at {:.0f} km/h)",
            currentLogon.userName,
            currentLogon.sourceIP,
            previousIp,
            elapsedSeconds,
            distanceKm,
            velocityKmh);
        alert.affectedUser = currentLogon.userName;
        alert.sourceIP = currentLogon.sourceIP;
        alert.mitreTechnique = MitreTechniqueForThreat(IdentityThreat::ImpossibleTravel);
        return alert;
    }

    void PersistAlert(const IdentityAlert& alert, const double riskScore) {
        const std::wstring fingerprint = std::format(
            L"{}:{}:{}:{}",
            static_cast<int>(alert.threatType),
            Lower(alert.affectedUser),
            Lower(alert.sourceIP),
            Lower(alert.evidence.substr(0, std::min<size_t>(alert.evidence.size(), 64))));

        {
            std::unique_lock lock(m_mutex);
            const auto existing = m_lastAnomalyFingerprint.find(fingerprint);
            if (existing != m_lastAnomalyFingerprint.end() &&
                (alert.timestamp - existing->second) < std::chrono::minutes{30}) {
                return;
            }
            m_lastAnomalyFingerprint[fingerprint] = alert.timestamp;
        }

        DatabaseError dbError{};
        if (!DatabaseManager::Instance().ExecuteWithParams(
                kInsertAlertSql,
                &dbError,
                ToUnixSeconds(alert.timestamp),
                static_cast<int>(alert.threatType),
                static_cast<int>(alert.severity),
                SU::ToNarrow(alert.evidence),
                SU::ToNarrow(alert.affectedUser),
                SU::ToNarrow(alert.sourceIP),
                SU::ToNarrow(alert.mitreTechnique),
                riskScore)) {
            LogDatabaseError("PersistAlert", dbError);
        }

        Logger::Warn(
            "{} threat={} user={} source={} evidence={}",
            kLogPrefix,
            static_cast<int>(alert.threatType),
            SU::ToNarrow(alert.affectedUser),
            SU::ToNarrow(alert.sourceIP),
            SU::ToNarrow(alert.evidence));
    }

    void ScanPrivilegeEscalationsUnlocked() {
        if (!m_initialized.load(std::memory_order_acquire)) {
            return;
        }

        DatabaseError dbError{};
        const auto baselineStart = std::chrono::system_clock::now() - std::chrono::hours{24 * m_statistics.baselineLearningDays};
        auto result = DatabaseManager::Instance().QueryWithParams(
            "SELECT timestamp, actor, target_user, group_name, change_type, domain "
            "FROM identity_group_changes WHERE timestamp >= ? ORDER BY timestamp DESC LIMIT 500",
            &dbError,
            ToUnixSeconds(baselineStart));
        if (dbError.HasError()) {
            LogDatabaseError("ScanPrivilegeEscalationsUnlocked", dbError);
            return;
        }

        while (result.Next()) {
            const std::wstring group = NullSafeWString(result, "group_name");
            if (!IsPrivilegedGroup(group) || !SU::IEquals(NullSafeWString(result, "change_type"), L"add")) {
                continue;
            }

            const IdentityAlert alert{
                IdentityThreat::PrivilegeEscalation,
                SeverityForThreat(IdentityThreat::PrivilegeEscalation, 95.0),
                std::format(L"user '{}' was added to privileged group '{}' by '{}'",
                    NullSafeWString(result, "target_user"),
                    group,
                    NullSafeWString(result, "actor")),
                NullSafeWString(result, "target_user"),
                L"",
                MitreTechniqueForThreat(IdentityThreat::PrivilegeEscalation),
                FromUnixSeconds(result.GetInt64("timestamp"))
            };

            PersistAlert(alert, 95.0);
            std::unique_lock lock(m_mutex);
            ++m_statistics.privilegeEscalationDetections;
            ++m_statistics.anomaliesRaised;
        }
    }

    void UpdateHighRiskCount() {
        std::unique_lock lock(m_mutex);
        m_statistics.highRiskUsers = std::count_if(
            m_profiles.begin(),
            m_profiles.end(),
            [](const auto& entry) {
                return entry.second.riskScore >= kHighRiskThreshold;
            });
    }

    mutable std::shared_mutex m_mutex;
    std::atomic<bool> m_initialized{false};
    std::wstring m_databasePath;
    std::unordered_map<std::wstring, UserBehaviorProfile> m_profiles;
    std::unordered_map<std::wstring, IdentityTimestamp> m_lastAnomalyFingerprint;
    IdentityAnalyticsStatistics m_statistics{};
};

IdentityAnalytics& IdentityAnalytics::Instance() {
    static IdentityAnalytics instance;
    return instance;
}

IdentityAnalytics::IdentityAnalytics()
    : m_impl(std::make_unique<IdentityAnalyticsImpl>()) {
}

IdentityAnalytics::~IdentityAnalytics() = default;

bool IdentityAnalytics::Initialize(const std::wstring& databasePath, const uint32_t baselineLearningDays) {
    return m_impl->Initialize(databasePath, baselineLearningDays);
}

void IdentityAnalytics::Shutdown() {
    m_impl->Shutdown();
}

bool IdentityAnalytics::IsInitialized() const noexcept {
    return m_impl->IsInitialized();
}

bool IdentityAnalytics::UpdateProfile(std::wstring_view userName) {
    return m_impl->UpdateProfile(userName);
}

std::vector<IdentityAlert> IdentityAnalytics::AnalyzeLogon(const LogonEvent& logon) {
    return m_impl->AnalyzeLogon(logon);
}

std::optional<UserBehaviorProfile> IdentityAnalytics::GetUserProfile(std::wstring_view userName) const {
    return m_impl->GetUserProfile(userName);
}

std::vector<UserBehaviorProfile> IdentityAnalytics::GetHighRiskUsers(const double minimumRiskScore, const size_t limit) const {
    return m_impl->GetHighRiskUsers(minimumRiskScore, limit);
}

std::vector<IdentityAlert> IdentityAnalytics::GetAnomalies(const size_t limit) const {
    return m_impl->GetAnomalies(limit);
}

IdentityAnalyticsStatistics IdentityAnalytics::GetStatistics() const {
    return m_impl->GetStatistics();
}

} // namespace ShadowStrike::Products::PhantomXDR::IdentityProtection
