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
#include "Products/Community/PhantomXDR/IdentityProtection/ADMonitor.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cmath>
#include <filesystem>
#include <format>
#include <limits>
#include <optional>
#include <shared_mutex>
#include <string>
#include <string_view>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <winevt.h>

#include "PhantomCore/Database/DatabaseManager.hpp"
#include "PhantomCore/Utils/FileUtils.hpp"
#include "PhantomCore/Utils/Logger.hpp"
#include "PhantomCore/Utils/StringUtils.hpp"

#pragma comment(lib, "wevtapi.lib")

namespace ShadowStrike::Products::PhantomXDR::IdentityProtection {

class ADMonitorImpl;

DWORD WINAPI EventSubscriptionCallback(
    const EVT_SUBSCRIBE_NOTIFY_ACTION action,
    const PVOID userContext,
    const EVT_HANDLE eventHandle);

namespace {

using ShadowStrike::Database::DatabaseConfig;
using ShadowStrike::Database::DatabaseError;
using ShadowStrike::Database::DatabaseManager;
using ShadowStrike::Database::QueryResult;
using ShadowStrike::Utils::Logger;
namespace FileUtils = ShadowStrike::Utils::FileUtils;
namespace SU = ShadowStrike::Utils::StringUtils;

constexpr std::string_view kLogPrefix = "[IdentityProtection::ADMonitor]";
constexpr size_t kDefaultQueryLimit = 100;
constexpr size_t kMaxQueryLimit = 1000;
constexpr size_t kMaxBurstEntries = 256;
constexpr std::chrono::minutes kBruteForceWindow{5};
constexpr std::chrono::minutes kPasswordSprayWindow{10};
constexpr std::chrono::minutes kDuplicateAlertWindow{15};

constexpr std::string_view kCreateRawEventsTableSql = R"SQL(
    CREATE TABLE IF NOT EXISTS identity_raw_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp INTEGER NOT NULL,
        event_id INTEGER NOT NULL,
        provider TEXT NOT NULL,
        computer TEXT,
        event_xml TEXT NOT NULL,
        inserted_at INTEGER NOT NULL
    );
)SQL";

constexpr std::string_view kCreateLogonsTableSql = R"SQL(
    CREATE TABLE IF NOT EXISTS identity_logons (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp INTEGER NOT NULL,
        user_name TEXT NOT NULL,
        domain TEXT,
        logon_type INTEGER NOT NULL,
        source_ip TEXT,
        source_host TEXT,
        workstation TEXT,
        success INTEGER NOT NULL,
        event_id INTEGER NOT NULL,
        logon_id TEXT,
        authentication_package TEXT
    );
)SQL";

constexpr std::string_view kCreateGroupChangesTableSql = R"SQL(
    CREATE TABLE IF NOT EXISTS identity_group_changes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp INTEGER NOT NULL,
        actor TEXT NOT NULL,
        target_user TEXT,
        group_name TEXT NOT NULL,
        change_type TEXT NOT NULL,
        domain TEXT
    );
)SQL";

constexpr std::string_view kCreateAlertsTableSql = R"SQL(
    CREATE TABLE IF NOT EXISTS identity_alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp INTEGER NOT NULL,
        threat_type INTEGER NOT NULL,
        severity INTEGER NOT NULL,
        evidence TEXT NOT NULL,
        affected_user TEXT,
        source_ip TEXT,
        mitre_technique TEXT NOT NULL,
        module_name TEXT NOT NULL
    );
)SQL";

constexpr std::string_view kCreateKerberosTableSql = R"SQL(
    CREATE TABLE IF NOT EXISTS identity_kerberos_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp INTEGER NOT NULL,
        event_id INTEGER NOT NULL,
        user_name TEXT,
        service_name TEXT,
        source_ip TEXT,
        source_host TEXT,
        ticket_encryption_type TEXT,
        ticket_options TEXT,
        failure_code TEXT,
        preauth_type TEXT
    );
)SQL";

constexpr std::string_view kCreateIndexesSql = R"SQL(
    CREATE INDEX IF NOT EXISTS idx_identity_raw_events_time ON identity_raw_events(timestamp DESC, event_id);
    CREATE INDEX IF NOT EXISTS idx_identity_logons_user_time ON identity_logons(user_name, timestamp DESC);
    CREATE INDEX IF NOT EXISTS idx_identity_logons_source_time ON identity_logons(source_ip, timestamp DESC);
    CREATE INDEX IF NOT EXISTS idx_identity_logons_failed_time ON identity_logons(success, timestamp DESC);
    CREATE INDEX IF NOT EXISTS idx_identity_group_changes_time ON identity_group_changes(timestamp DESC, group_name);
    CREATE INDEX IF NOT EXISTS idx_identity_alerts_time ON identity_alerts(timestamp DESC, threat_type);
    CREATE INDEX IF NOT EXISTS idx_identity_kerberos_time ON identity_kerberos_events(timestamp DESC, event_id);
)SQL";

constexpr std::string_view kInsertRawEventSql = R"SQL(
    INSERT INTO identity_raw_events(timestamp, event_id, provider, computer, event_xml, inserted_at)
    VALUES (?, ?, ?, ?, ?, ?);
)SQL";

constexpr std::string_view kInsertLogonSql = R"SQL(
    INSERT INTO identity_logons(
        timestamp, user_name, domain, logon_type, source_ip, source_host,
        workstation, success, event_id, logon_id, authentication_package
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
)SQL";

constexpr std::string_view kInsertGroupChangeSql = R"SQL(
    INSERT INTO identity_group_changes(timestamp, actor, target_user, group_name, change_type, domain)
    VALUES (?, ?, ?, ?, ?, ?);
)SQL";

constexpr std::string_view kInsertAlertSql = R"SQL(
    INSERT INTO identity_alerts(timestamp, threat_type, severity, evidence, affected_user, source_ip, mitre_technique, module_name)
    VALUES (?, ?, ?, ?, ?, ?, ?, 'ADMonitor');
)SQL";

constexpr std::string_view kInsertKerberosSql = R"SQL(
    INSERT INTO identity_kerberos_events(
        timestamp, event_id, user_name, service_name, source_ip, source_host,
        ticket_encryption_type, ticket_options, failure_code, preauth_type
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
)SQL";

[[nodiscard]] int64_t ToUnixSeconds(const IdentityTimestamp value) noexcept {
    return std::chrono::duration_cast<std::chrono::seconds>(value.time_since_epoch()).count();
}

[[nodiscard]] IdentityTimestamp FromUnixSeconds(const int64_t value) noexcept {
    return IdentityTimestamp{std::chrono::seconds{value}};
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

[[nodiscard]] std::wstring Trimmed(std::wstring value) {
    SU::Trim(value);
    return value;
}

[[nodiscard]] std::wstring Lower(std::wstring value) {
    SU::ToLower(value);
    return value;
}

[[nodiscard]] bool IsPlaceholderValue(std::wstring_view value) {
    return value.empty() || value == L"-" || value == L"::1" || value == L"127.0.0.1";
}

[[nodiscard]] std::wstring ExtractXmlElement(std::wstring_view xml, std::wstring_view elementName) {
    const std::wstring openTag = std::format(L"<{}>", elementName);
    const std::wstring closeTag = std::format(L"</{}>", elementName);
    const size_t start = xml.find(openTag);
    if (start == std::wstring_view::npos) {
        return {};
    }

    const size_t contentStart = start + openTag.size();
    const size_t end = xml.find(closeTag, contentStart);
    if (end == std::wstring_view::npos || end <= contentStart) {
        return {};
    }

    return Trimmed(std::wstring{xml.substr(contentStart, end - contentStart)});
}

[[nodiscard]] std::wstring ExtractEventData(std::wstring_view xml, std::wstring_view name) {
    const std::array<std::wstring, 2> prefixes{
        std::format(L"<Data Name='{}'>", name),
        std::format(L"<Data Name=\"{}\">", name)
    };

    for (const auto& prefix : prefixes) {
        const size_t start = xml.find(prefix);
        if (start == std::wstring_view::npos) {
            continue;
        }

        const size_t valueStart = start + prefix.size();
        const size_t end = xml.find(L"</Data>", valueStart);
        if (end == std::wstring_view::npos || end <= valueStart) {
            continue;
        }

        return Trimmed(std::wstring{xml.substr(valueStart, end - valueStart)});
    }

    return {};
}

[[nodiscard]] uint32_t ExtractEventId(std::wstring_view xml) {
    const size_t start = xml.find(L"<EventID");
    if (start == std::wstring_view::npos) {
        return 0;
    }

    const size_t openEnd = xml.find(L'>', start);
    if (openEnd == std::wstring_view::npos) {
        return 0;
    }

    const size_t close = xml.find(L"</EventID>", openEnd + 1);
    if (close == std::wstring_view::npos || close <= openEnd + 1) {
        return 0;
    }

    const std::wstring value = Trimmed(std::wstring{xml.substr(openEnd + 1, close - openEnd - 1)});
    return value.empty() ? 0U : static_cast<uint32_t>(std::wcstoul(value.c_str(), nullptr, 10));
}

[[nodiscard]] IdentityTimestamp ParseSystemTime(std::wstring_view xml) {
    constexpr std::array<std::wstring_view, 2> markers{
        L"SystemTime='",
        L"SystemTime=\""
    };

    for (const auto marker : markers) {
        const size_t start = xml.find(marker);
        if (start == std::wstring_view::npos) {
            continue;
        }

        const size_t valueStart = start + marker.size();
        const wchar_t terminator = marker.back();
        const size_t end = xml.find(terminator, valueStart);
        if (end == std::wstring_view::npos || end <= valueStart) {
            continue;
        }

        const std::wstring value{xml.substr(valueStart, end - valueStart)};
        std::tm utc{};
        int year = 0;
        int month = 0;
        int day = 0;
        int hour = 0;
        int minute = 0;
        int second = 0;
        if (swscanf_s(
                value.c_str(),
                L"%d-%d-%dT%d:%d:%d",
                &year,
                &month,
                &day,
                &hour,
                &minute,
                &second) == 6) {
            utc.tm_year = year - 1900;
            utc.tm_mon = month - 1;
            utc.tm_mday = day;
            utc.tm_hour = hour;
            utc.tm_min = minute;
            utc.tm_sec = second;
#if defined(_WIN32)
            const time_t asTime = _mkgmtime(&utc);
#else
            const time_t asTime = timegm(&utc);
#endif
            if (asTime >= 0) {
                return IdentityTimestamp{std::chrono::seconds{asTime}};
            }
        }
    }

    return std::chrono::system_clock::now();
}

[[nodiscard]] std::wstring RenderEventXml(const EVT_HANDLE eventHandle) {
    DWORD bufferUsed = 0;
    DWORD propertyCount = 0;
    if (::EvtRender(nullptr, eventHandle, EvtRenderEventXml, 0, nullptr, &bufferUsed, &propertyCount) != FALSE) {
        return {};
    }

    const DWORD error = ::GetLastError();
    if (error != ERROR_INSUFFICIENT_BUFFER || bufferUsed == 0U) {
        return {};
    }

    std::wstring buffer(bufferUsed / sizeof(wchar_t), L'\0');
    if (::EvtRender(
            nullptr,
            eventHandle,
            EvtRenderEventXml,
            bufferUsed,
            buffer.data(),
            &bufferUsed,
            &propertyCount) == FALSE) {
        return {};
    }

    if (!buffer.empty() && buffer.back() == L'\0') {
        buffer.pop_back();
    }

    return buffer;
}

[[nodiscard]] LogonType ParseLogonType(const std::wstring_view value) {
    const int numeric = value.empty() ? 2 : std::stoi(std::wstring{value});
    switch (numeric) {
    case 3:
        return LogonType::Network;
    case 4:
        return LogonType::Batch;
    case 5:
        return LogonType::Service;
    case 7:
        return LogonType::Unlock;
    case 8:
        return LogonType::NetworkCleartext;
    case 9:
        return LogonType::NewCredentials;
    case 10:
        return LogonType::RemoteInteractive;
    case 11:
        return LogonType::CachedInteractive;
    default:
        return LogonType::Interactive;
    }
}

[[nodiscard]] std::wstring NormalizePrincipal(std::wstring value) {
    value = Trimmed(std::move(value));
    if (value.empty()) {
        return {};
    }

    if (value == L"-" || value == L"ANONYMOUS LOGON" || value == L"LOCAL SERVICE") {
        return {};
    }

    return Lower(std::move(value));
}

[[nodiscard]] std::wstring ExtractTargetUser(std::wstring_view xml) {
    std::wstring user = ExtractEventData(xml, L"TargetUserName");
    if (user.empty()) {
        user = ExtractEventData(xml, L"SubjectUserName");
    }
    if (user.empty()) {
        user = ExtractEventData(xml, L"AccountName");
    }
    return Trimmed(std::move(user));
}

[[nodiscard]] bool EndsWithInsensitive(std::wstring_view value, std::wstring_view suffix) {
    return SU::IEquals(value.size() >= suffix.size() ? value.substr(value.size() - suffix.size()) : std::wstring_view{}, suffix);
}

[[nodiscard]] bool ContainsInsensitive(std::wstring_view value, std::wstring_view needle) {
    return SU::IContains(value, needle);
}

[[nodiscard]] bool IsPrivilegedMachineAccount(std::wstring_view account) {
    return !account.empty() && account.back() == L'$';
}

[[nodiscard]] bool IsLikelyDomainControllerHost(std::wstring host) {
    host = Lower(Trimmed(std::move(host)));
    return ContainsInsensitive(host, L"domaincontroller") ||
           ContainsInsensitive(host, L"\\dc") ||
           SU::StartsWith(host, L"dc") ||
           ContainsInsensitive(host, L"-dc");
}

[[nodiscard]] uint32_t SeverityForThreat(const IdentityThreat threat) {
    switch (threat) {
    case IdentityThreat::DCSync:
    case IdentityThreat::CredentialDumping:
        return 95;
    case IdentityThreat::Kerberoasting:
    case IdentityThreat::PassTheHash:
        return 85;
    case IdentityThreat::BruteForce:
    case IdentityThreat::PasswordSpray:
        return 75;
    default:
        return 60;
    }
}

[[nodiscard]] std::wstring MitreTechniqueForThreat(const IdentityThreat threat) {
    switch (threat) {
    case IdentityThreat::BruteForce:
        return L"T1110";
    case IdentityThreat::PasswordSpray:
        return L"T1110.003";
    case IdentityThreat::Kerberoasting:
        return L"T1558.003";
    case IdentityThreat::DCSync:
        return L"T1003.006";
    case IdentityThreat::PassTheHash:
        return L"T1550.002";
    case IdentityThreat::CredentialDumping:
        return L"T1003";
    default:
        return L"T1078";
    }
}

[[nodiscard]] IdentityAlert MakeAlert(
    const IdentityThreat threat,
    const uint32_t severity,
    std::wstring evidence,
    std::wstring affectedUser,
    std::wstring sourceIp,
    const IdentityTimestamp timestamp) {
    IdentityAlert alert{};
    alert.threatType = threat;
    alert.severity = severity;
    alert.evidence = Trimmed(std::move(evidence));
    alert.affectedUser = Trimmed(std::move(affectedUser));
    alert.sourceIP = Trimmed(std::move(sourceIp));
    alert.mitreTechnique = MitreTechniqueForThreat(threat);
    alert.timestamp = timestamp;
    return alert;
}

[[nodiscard]] size_t ClampLimit(const size_t limit) {
    return std::clamp(limit == 0 ? kDefaultQueryLimit : limit, static_cast<size_t>(1), kMaxQueryLimit);
}

[[nodiscard]] std::wstring ExtractMemberName(std::wstring value) {
    value = Trimmed(std::move(value));
    if (value.empty()) {
        return {};
    }

    const size_t equals = value.find(L"CN=");
    if (equals != std::wstring::npos) {
        const size_t start = equals + 3;
        const size_t end = value.find(L',', start);
        return end == std::wstring::npos ? value.substr(start) : value.substr(start, end - start);
    }

    return value;
}

[[nodiscard]] std::wstring NullSafeWString(const QueryResult& result, const int columnIndex) {
    return result.IsNull(columnIndex) ? std::wstring{} : result.GetWString(columnIndex);
}

[[nodiscard]] std::wstring NullSafeWString(const QueryResult& result, std::string_view columnName) {
    return result.IsNull(columnName) ? std::wstring{} : result.GetWString(columnName);
}

[[nodiscard]] IdentityThreat ThreatFromInt(const int value) {
    if (value < 0 || value > static_cast<int>(IdentityThreat::PrivilegeEscalation)) {
        return IdentityThreat::None;
    }
    return static_cast<IdentityThreat>(value);
}

} // namespace

class ADMonitorImpl final {
public:
    [[nodiscard]] bool Initialize(const std::wstring& requestedDatabasePath) {
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

        auto& db = DatabaseManager::Instance();
        const std::array<std::string_view, 5> schemaStatements{
            kCreateRawEventsTableSql,
            kCreateLogonsTableSql,
            kCreateGroupChangesTableSql,
            kCreateAlertsTableSql,
            kCreateKerberosTableSql
        };

        for (const auto statement : schemaStatements) {
            if (!db.Execute(statement, &dbError)) {
                LogDatabaseError("InitializeSchema", dbError);
                return false;
            }
        }

        if (!db.Execute(kCreateIndexesSql, &dbError)) {
            LogDatabaseError("InitializeIndexes", dbError);
            return false;
        }

        m_initialized.store(true, std::memory_order_release);
        m_statistics.monitoringActive = false;
        Logger::Info("{} initialized databasePath={}", kLogPrefix, SU::ToNarrow(m_databasePath));
        return true;
    }

    void Shutdown() {
        StopMonitoring();
        std::unique_lock lock(m_mutex);
        m_recentFailedByAccount.clear();
        m_recentFailedBySource.clear();
        m_lastAlertByFingerprint.clear();
        m_initialized.store(false, std::memory_order_release);
        m_databasePath.clear();
    }

    [[nodiscard]] bool StartMonitoring() {
        if (!m_initialized.load(std::memory_order_acquire)) {
            Logger::Warn("{} StartMonitoring called before Initialize", kLogPrefix);
            return false;
        }

        std::unique_lock lock(m_mutex);
        if (m_monitoring.load(std::memory_order_acquire)) {
            return true;
        }

        m_monitoring.store(true, std::memory_order_release);
        m_statistics.monitoringActive = true;
        m_worker = std::jthread([this](std::stop_token stopToken) { SubscriptionWorker(stopToken); });
        Logger::Info("{} security event subscription started", kLogPrefix);
        return true;
    }

    void StopMonitoring() {
        std::jthread workerToJoin;
        EVT_HANDLE subscriptionToClose = nullptr;

        {
            std::unique_lock lock(m_mutex);
            if (!m_monitoring.load(std::memory_order_acquire) && m_worker.get_id() == std::jthread::id{}) {
                return;
            }

            m_monitoring.store(false, std::memory_order_release);
            m_statistics.monitoringActive = false;
            workerToJoin = std::move(m_worker);
            subscriptionToClose = m_subscriptionHandle;
            m_subscriptionHandle = nullptr;
        }

        if (workerToJoin.joinable()) {
            workerToJoin.request_stop();
        }

        if (subscriptionToClose != nullptr) {
            ::EvtClose(subscriptionToClose);
        }
    }

    [[nodiscard]] bool IsInitialized() const noexcept {
        return m_initialized.load(std::memory_order_acquire);
    }

    [[nodiscard]] bool IsMonitoring() const noexcept {
        return m_monitoring.load(std::memory_order_acquire);
    }

    [[nodiscard]] DWORD HandleSubscriptionCallback(
        const EVT_SUBSCRIBE_NOTIFY_ACTION action,
        const EVT_HANDLE eventHandle) {
        if (action == EvtSubscribeActionError) {
            const auto status = static_cast<DWORD>(reinterpret_cast<ULONG_PTR>(eventHandle));
            Logger::Warn("{} event subscription reported error={}", kLogPrefix, status);
            return ERROR_SUCCESS;
        }

        if (action != EvtSubscribeActionDeliver || eventHandle == nullptr) {
            return ERROR_SUCCESS;
        }

        ProcessSecurityEvent(eventHandle);
        return ERROR_SUCCESS;
    }

    [[nodiscard]] std::vector<LogonEvent> GetRecentLogons(const size_t limit, const bool successfulOnly) const {
        std::vector<LogonEvent> events;
        if (!m_initialized.load(std::memory_order_acquire)) {
            return events;
        }

        DatabaseError dbError{};
        auto& db = DatabaseManager::Instance();
        std::string sql =
            "SELECT timestamp, user_name, domain, logon_type, source_ip, source_host, workstation, success, event_id, logon_id "
            "FROM identity_logons";
        if (successfulOnly) {
            sql += " WHERE success = 1";
        }
        sql += " ORDER BY timestamp DESC LIMIT " + std::to_string(ClampLimit(limit));

        auto result = db.Query(sql, &dbError);
        if (dbError.HasError()) {
            LogDatabaseError("GetRecentLogons", dbError);
            return events;
        }

        while (result.Next()) {
            events.push_back(ReadLogonRow(result));
        }

        return events;
    }

    [[nodiscard]] std::vector<LogonEvent> GetFailedLogons(const size_t limit, std::wstring_view sourceIP) const {
        std::vector<LogonEvent> events;
        if (!m_initialized.load(std::memory_order_acquire)) {
            return events;
        }

        DatabaseError dbError{};
        auto& db = DatabaseManager::Instance();
        std::string sql =
            "SELECT timestamp, user_name, domain, logon_type, source_ip, source_host, workstation, success, event_id, logon_id "
            "FROM identity_logons WHERE success = 0";
        if (!sourceIP.empty()) {
            sql += " AND source_ip = ?";
        }
        sql += " ORDER BY timestamp DESC LIMIT " + std::to_string(ClampLimit(limit));

        QueryResult result = sourceIP.empty()
            ? db.Query(sql, &dbError)
            : db.QueryWithParams(sql, &dbError, SU::ToNarrow(sourceIP));
        if (dbError.HasError()) {
            LogDatabaseError("GetFailedLogons", dbError);
            return events;
        }

        while (result.Next()) {
            events.push_back(ReadLogonRow(result));
        }

        return events;
    }

    [[nodiscard]] std::vector<GroupChangeEvent> GetGroupChanges(const size_t limit, std::wstring_view targetUser) const {
        std::vector<GroupChangeEvent> events;
        if (!m_initialized.load(std::memory_order_acquire)) {
            return events;
        }

        DatabaseError dbError{};
        auto& db = DatabaseManager::Instance();
        std::string sql =
            "SELECT timestamp, actor, target_user, group_name, change_type, domain "
            "FROM identity_group_changes";
        if (!targetUser.empty()) {
            sql += " WHERE target_user = ?";
        }
        sql += " ORDER BY timestamp DESC LIMIT " + std::to_string(ClampLimit(limit));

        QueryResult result = targetUser.empty()
            ? db.Query(sql, &dbError)
            : db.QueryWithParams(sql, &dbError, SU::ToNarrow(targetUser));
        if (dbError.HasError()) {
            LogDatabaseError("GetGroupChanges", dbError);
            return events;
        }

        while (result.Next()) {
            GroupChangeEvent event{};
            event.timestamp = FromUnixSeconds(result.GetInt64("timestamp"));
            event.actor = NullSafeWString(result, "actor");
            event.targetUser = NullSafeWString(result, "target_user");
            event.groupName = NullSafeWString(result, "group_name");
            event.changeType = NullSafeWString(result, "change_type");
            event.domain = NullSafeWString(result, "domain");
            events.push_back(std::move(event));
        }

        return events;
    }

    [[nodiscard]] std::vector<IdentityAlert> GetAlerts(const size_t limit, const std::optional<IdentityThreat> threat) const {
        std::vector<IdentityAlert> alerts;
        if (!m_initialized.load(std::memory_order_acquire)) {
            return alerts;
        }

        DatabaseError dbError{};
        auto& db = DatabaseManager::Instance();
        std::string sql =
            "SELECT timestamp, threat_type, severity, evidence, affected_user, source_ip, mitre_technique "
            "FROM identity_alerts WHERE module_name = 'ADMonitor'";
        if (threat.has_value()) {
            sql += " AND threat_type = ?";
        }
        sql += " ORDER BY timestamp DESC LIMIT " + std::to_string(ClampLimit(limit));

        QueryResult result = threat.has_value()
            ? db.QueryWithParams(sql, &dbError, static_cast<int>(*threat))
            : db.Query(sql, &dbError);
        if (dbError.HasError()) {
            LogDatabaseError("GetAlerts", dbError);
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

    [[nodiscard]] ADMonitorStatistics GetStatistics() const {
        std::shared_lock lock(m_mutex);
        return m_statistics;
    }

private:
    [[nodiscard]] LogonEvent ReadLogonRow(QueryResult& result) const {
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
        return event;
    }

    void SubscriptionWorker(std::stop_token stopToken) {
        constexpr std::wstring_view query = LR"(
            *[
                System[
                    Provider[@Name='Microsoft-Windows-Security-Auditing'] and
                    (
                        EventID=4624 or EventID=4625 or EventID=4648 or
                        EventID=4720 or EventID=4722 or EventID=4726 or
                        EventID=4728 or EventID=4729 or EventID=4732 or EventID=4733 or
                        EventID=4738 or EventID=4756 or EventID=4757 or
                        EventID=4768 or EventID=4769 or EventID=4771 or EventID=4662
                    )
                ]
            ]
        )";

        EVT_HANDLE subscription = ::EvtSubscribe(
            nullptr,
            nullptr,
            L"Security",
            std::wstring(query).c_str(),
            nullptr,
            this,
            &EventSubscriptionCallback,
            EvtSubscribeToFutureEvents);

        if (subscription == nullptr) {
            const DWORD error = ::GetLastError();
            Logger::Error("{} EvtSubscribe failed error={}", kLogPrefix, error);
            std::unique_lock lock(m_mutex);
            m_monitoring.store(false, std::memory_order_release);
            m_statistics.monitoringActive = false;
            return;
        }

        {
            std::unique_lock lock(m_mutex);
            m_subscriptionHandle = subscription;
        }

        while (!stopToken.stop_requested()) {
            std::this_thread::sleep_for(std::chrono::milliseconds{500});
        }

        {
            std::unique_lock lock(m_mutex);
            if (m_subscriptionHandle != nullptr) {
                ::EvtClose(m_subscriptionHandle);
                m_subscriptionHandle = nullptr;
            }
        }
    }

    void ProcessSecurityEvent(const EVT_HANDLE eventHandle) {
        const std::wstring xml = RenderEventXml(eventHandle);
        if (xml.empty()) {
            Logger::Warn("{} unable to render event XML", kLogPrefix);
            return;
        }

        const uint32_t eventId = ExtractEventId(xml);
        if (eventId == 0U) {
            return;
        }

        const IdentityTimestamp timestamp = ParseSystemTime(xml);
        const std::wstring computer = ExtractXmlElement(xml, L"Computer");
        const std::wstring provider = ExtractXmlElement(xml, L"Provider");

        PersistRawEvent(timestamp, eventId, provider.empty() ? L"Microsoft-Windows-Security-Auditing" : provider, computer, xml);

        {
            std::unique_lock lock(m_mutex);
            ++m_statistics.totalEventsProcessed;
        }

        switch (eventId) {
        case 4624:
        case 4625:
        case 4648:
        case 4771:
            ProcessLogonEvent(xml, eventId, timestamp, computer);
            break;
        case 4728:
        case 4729:
        case 4732:
        case 4733:
        case 4756:
        case 4757:
            ProcessGroupMembershipEvent(xml, eventId, timestamp);
            break;
        case 4720:
        case 4722:
        case 4726:
        case 4738:
            ProcessIdentityManagementEvent(xml, eventId, timestamp);
            break;
        case 4768:
        case 4769:
            ProcessKerberosEvent(xml, eventId, timestamp, computer);
            break;
        case 4662:
            DetectDCSync(xml, timestamp, computer);
            break;
        default:
            break;
        }
    }

    void PersistRawEvent(
        const IdentityTimestamp timestamp,
        const uint32_t eventId,
        const std::wstring& provider,
        const std::wstring& computer,
        const std::wstring& xml) const {
        DatabaseError dbError{};
        if (!DatabaseManager::Instance().ExecuteWithParams(
                kInsertRawEventSql,
                &dbError,
                ToUnixSeconds(timestamp),
                static_cast<int>(eventId),
                SU::ToNarrow(provider),
                SU::ToNarrow(computer),
                SU::ToNarrow(xml),
                ToUnixSeconds(std::chrono::system_clock::now()))) {
            LogDatabaseError("PersistRawEvent", dbError);
        }
    }

    void ProcessLogonEvent(
        std::wstring_view xml,
        const uint32_t eventId,
        const IdentityTimestamp timestamp,
        const std::wstring& computer) {
        LogonEvent event{};
        event.timestamp = timestamp;
        event.userName = ExtractTargetUser(xml);
        event.domain = Trimmed(ExtractEventData(xml, L"TargetDomainName"));
        event.logonType = ParseLogonType(ExtractEventData(xml, L"LogonType"));
        event.sourceIP = Trimmed(ExtractEventData(xml, L"IpAddress"));
        event.sourceHost = computer;
        event.workstation = Trimmed(ExtractEventData(xml, L"WorkstationName"));
        event.success = (eventId == 4624 || eventId == 4648);
        event.eventId = eventId;
        event.logonId = Trimmed(ExtractEventData(xml, L"TargetLogonId"));

        if (event.logonId.empty()) {
            event.logonId = Trimmed(ExtractEventData(xml, L"SubjectLogonId"));
        }

        if (eventId == 4771) {
            event.success = false;
            event.logonType = LogonType::Network;
            if (event.sourceIP.empty()) {
                event.sourceIP = Trimmed(ExtractEventData(xml, L"ClientAddress"));
            }
        }

        const std::wstring authenticationPackage = Trimmed(ExtractEventData(xml, L"AuthenticationPackageName"));
        PersistLogonEvent(event, authenticationPackage);

        {
            std::unique_lock lock(m_mutex);
            ++m_statistics.logonEvents;
            if (!event.success) {
                ++m_statistics.failedLogons;
            }
        }

        if (!event.success) {
            TrackFailedLogon(event);
        }
    }

    void ProcessGroupMembershipEvent(
        std::wstring_view xml,
        const uint32_t eventId,
        const IdentityTimestamp timestamp) {
        GroupChangeEvent event{};
        event.timestamp = timestamp;
        event.actor = Trimmed(ExtractEventData(xml, L"SubjectUserName"));
        event.targetUser = ExtractMemberName(ExtractEventData(xml, L"MemberName"));
        event.groupName = Trimmed(ExtractEventData(xml, L"TargetUserName"));
        event.changeType = (eventId == 4729 || eventId == 4733 || eventId == 4757) ? L"remove" : L"add";
        event.domain = Trimmed(ExtractEventData(xml, L"TargetDomainName"));

        if (event.targetUser.empty()) {
            event.targetUser = Trimmed(ExtractEventData(xml, L"TargetUserName"));
        }

        DatabaseError dbError{};
        if (!DatabaseManager::Instance().ExecuteWithParams(
                kInsertGroupChangeSql,
                &dbError,
                ToUnixSeconds(event.timestamp),
                SU::ToNarrow(event.actor),
                SU::ToNarrow(event.targetUser),
                SU::ToNarrow(event.groupName),
                SU::ToNarrow(event.changeType),
                SU::ToNarrow(event.domain))) {
            LogDatabaseError("ProcessGroupMembershipEvent", dbError);
        }

        std::unique_lock lock(m_mutex);
        ++m_statistics.groupChanges;
    }

    void ProcessIdentityManagementEvent(
        std::wstring_view xml,
        const uint32_t eventId,
        const IdentityTimestamp timestamp) {
        const std::wstring actor = Trimmed(ExtractEventData(xml, L"SubjectUserName"));
        const std::wstring target = Trimmed(ExtractEventData(xml, L"TargetUserName"));
        const std::wstring action = [&]() -> std::wstring {
            switch (eventId) {
            case 4720:
                return L"user-created";
            case 4722:
                return L"user-enabled";
            case 4726:
                return L"user-deleted";
            case 4738:
                return L"user-modified";
            default:
                return L"identity-change";
            }
        }();

        DatabaseError dbError{};
        if (!DatabaseManager::Instance().ExecuteWithParams(
                kInsertGroupChangeSql,
                &dbError,
                ToUnixSeconds(timestamp),
                SU::ToNarrow(actor),
                SU::ToNarrow(target),
                "identity-management",
                SU::ToNarrow(action),
                SU::ToNarrow(Trimmed(ExtractEventData(xml, L"TargetDomainName"))))) {
            LogDatabaseError("ProcessIdentityManagementEvent", dbError);
        }

        std::unique_lock lock(m_mutex);
        ++m_statistics.groupChanges;
    }

    void ProcessKerberosEvent(
        std::wstring_view xml,
        const uint32_t eventId,
        const IdentityTimestamp timestamp,
        const std::wstring& computer) {
        const std::wstring userName = ExtractTargetUser(xml);
        std::wstring sourceIp = Trimmed(ExtractEventData(xml, L"IpAddress"));
        if (sourceIp.empty()) {
            sourceIp = Trimmed(ExtractEventData(xml, L"ClientAddress"));
        }

        const std::wstring serviceName = Trimmed(ExtractEventData(xml, L"ServiceName"));
        const std::wstring encryptionType = Trimmed(ExtractEventData(xml, L"TicketEncryptionType"));
        const std::wstring ticketOptions = Trimmed(ExtractEventData(xml, L"TicketOptions"));
        const std::wstring failureCode = Trimmed(ExtractEventData(xml, L"FailureCode"));
        const std::wstring preauthType = Trimmed(ExtractEventData(xml, L"PreAuthType"));

        DatabaseError dbError{};
        if (!DatabaseManager::Instance().ExecuteWithParams(
                kInsertKerberosSql,
                &dbError,
                ToUnixSeconds(timestamp),
                static_cast<int>(eventId),
                SU::ToNarrow(userName),
                SU::ToNarrow(serviceName),
                SU::ToNarrow(sourceIp),
                SU::ToNarrow(computer),
                SU::ToNarrow(encryptionType),
                SU::ToNarrow(ticketOptions),
                SU::ToNarrow(failureCode),
                SU::ToNarrow(preauthType))) {
            LogDatabaseError("ProcessKerberosEvent", dbError);
        }

        {
            std::unique_lock lock(m_mutex);
            ++m_statistics.kerberosEvents;
        }

        if (eventId == 4769) {
            DetectKerberoasting(userName, serviceName, sourceIp, encryptionType, timestamp);
        }

        if (eventId == 4771) {
            LogonEvent failedLogon{};
            failedLogon.timestamp = timestamp;
            failedLogon.userName = userName;
            failedLogon.domain = Trimmed(ExtractEventData(xml, L"TargetDomainName"));
            failedLogon.logonType = LogonType::Network;
            failedLogon.sourceIP = sourceIp;
            failedLogon.sourceHost = computer;
            failedLogon.success = false;
            failedLogon.eventId = eventId;
            TrackFailedLogon(failedLogon);
        }
    }

    void PersistLogonEvent(const LogonEvent& event, std::wstring_view authenticationPackage) const {
        DatabaseError dbError{};
        if (!DatabaseManager::Instance().ExecuteWithParams(
                kInsertLogonSql,
                &dbError,
                ToUnixSeconds(event.timestamp),
                SU::ToNarrow(event.userName),
                SU::ToNarrow(event.domain),
                static_cast<int>(event.logonType),
                SU::ToNarrow(event.sourceIP),
                SU::ToNarrow(event.sourceHost),
                SU::ToNarrow(event.workstation),
                event.success ? 1 : 0,
                static_cast<int>(event.eventId),
                SU::ToNarrow(event.logonId),
                SU::ToNarrow(authenticationPackage))) {
            LogDatabaseError("PersistLogonEvent", dbError);
        }
    }

    void TrackFailedLogon(const LogonEvent& event) {
        const IdentityTimestamp now = event.timestamp;
        const std::wstring normalizedUser = NormalizePrincipal(event.userName);
        const std::wstring normalizedSource = Lower(event.sourceIP);

        if (normalizedUser.empty()) {
            return;
        }

        {
            std::unique_lock lock(m_mutex);
            auto& failures = m_recentFailedByAccount[normalizedUser];
            failures.push_back(now);
            PruneTimestamps(failures, now - kBruteForceWindow);
            if (failures.size() > kMaxBurstEntries) {
                failures.erase(failures.begin(), failures.begin() + static_cast<std::ptrdiff_t>(failures.size() - kMaxBurstEntries));
            }

            if (failures.size() >= 8U) {
                const IdentityAlert alert = MakeAlert(
                    IdentityThreat::BruteForce,
                    SeverityForThreat(IdentityThreat::BruteForce),
                    std::format(L"{} failed authentication attempts for user '{}' in {} minutes",
                        failures.size(),
                        event.userName,
                        kBruteForceWindow.count()),
                    event.userName,
                    event.sourceIP,
                    event.timestamp);
                EmitAlertUnlocked(alert, std::format(L"bf:{}:{}", normalizedUser, normalizedSource));
            }

            if (!normalizedSource.empty() && !IsPlaceholderValue(normalizedSource)) {
                auto& sourceFailures = m_recentFailedBySource[normalizedSource];
                sourceFailures.emplace_back(now, normalizedUser);
                PruneSourceEntries(sourceFailures, now - kPasswordSprayWindow);
                if (sourceFailures.size() > kMaxBurstEntries) {
                    sourceFailures.erase(sourceFailures.begin(),
                        sourceFailures.begin() + static_cast<std::ptrdiff_t>(sourceFailures.size() - kMaxBurstEntries));
                }

                std::unordered_set<std::wstring> uniqueUsers;
                uniqueUsers.reserve(sourceFailures.size());
                for (const auto& [_, account] : sourceFailures) {
                    uniqueUsers.insert(account);
                }

                if (uniqueUsers.size() >= 10U) {
                    const IdentityAlert alert = MakeAlert(
                        IdentityThreat::PasswordSpray,
                        SeverityForThreat(IdentityThreat::PasswordSpray),
                        std::format(L"source '{}' generated failed logons against {} unique identities in {} minutes",
                            event.sourceIP,
                            uniqueUsers.size(),
                            kPasswordSprayWindow.count()),
                        L"",
                        event.sourceIP,
                        event.timestamp);
                    EmitAlertUnlocked(alert, std::format(L"ps:{}", normalizedSource));
                }
            }
        }
    }

    void DetectKerberoasting(
        const std::wstring& userName,
        const std::wstring& serviceName,
        const std::wstring& sourceIp,
        const std::wstring& encryptionType,
        const IdentityTimestamp timestamp) {
        const std::wstring normalizedService = Lower(serviceName);
        const std::wstring normalizedEnc = Lower(encryptionType);
        const bool usesRc4 = normalizedEnc == L"0x17" || normalizedEnc == L"23" || ContainsInsensitive(normalizedEnc, L"rc4");
        const bool serviceLikelyRoastable = !normalizedService.empty() &&
            !EndsWithInsensitive(normalizedService, L"$") &&
            normalizedService != L"krbtgt";

        if (!usesRc4 || !serviceLikelyRoastable) {
            return;
        }

        std::unique_lock lock(m_mutex);
        const IdentityAlert alert = MakeAlert(
            IdentityThreat::Kerberoasting,
            SeverityForThreat(IdentityThreat::Kerberoasting),
            std::format(L"service ticket request for '{}' used RC4-compatible encryption from '{}'",
                serviceName,
                sourceIp),
            userName,
            sourceIp,
            timestamp);
        EmitAlertUnlocked(alert, std::format(L"kr:{}:{}:{}", Lower(userName), normalizedService, Lower(sourceIp)));
    }

    void DetectDCSync(std::wstring_view xml, const IdentityTimestamp timestamp, const std::wstring& computer) {
        const std::wstring properties = Lower(ExtractEventData(xml, L"Properties"));
        const std::wstring accessMask = Lower(ExtractEventData(xml, L"AccessMask"));
        const std::wstring actor = Trimmed(ExtractEventData(xml, L"SubjectUserName"));
        const std::wstring sourceHost = Trimmed(ExtractEventData(xml, L"Workstation"));
        const std::wstring sourceIp = Trimmed(ExtractEventData(xml, L"IpAddress"));
        const bool replicationRequest =
            ContainsInsensitive(properties, L"replication-get-changes") ||
            ContainsInsensitive(properties, L"1131f6aa") ||
            ContainsInsensitive(properties, L"1131f6ad") ||
            accessMask == L"0x100" ||
            accessMask == L"0x10000";
        const bool trustedSource =
            IsPrivilegedMachineAccount(actor) ||
            IsLikelyDomainControllerHost(sourceHost) ||
            IsLikelyDomainControllerHost(computer);

        if (!replicationRequest || trustedSource) {
            return;
        }

        std::unique_lock lock(m_mutex);
        const IdentityAlert alert = MakeAlert(
            IdentityThreat::DCSync,
            SeverityForThreat(IdentityThreat::DCSync),
            std::format(L"directory replication rights were exercised by '{}' from '{}'",
                actor,
                sourceHost.empty() ? computer : sourceHost),
            actor,
            sourceIp,
            timestamp);
        EmitAlertUnlocked(alert, std::format(L"dcsync:{}:{}:{}",
            Lower(actor),
            Lower(sourceHost.empty() ? computer : sourceHost),
            Lower(sourceIp)));
    }

    void EmitAlertUnlocked(const IdentityAlert& alert, const std::wstring& fingerprint) {
        const auto existing = m_lastAlertByFingerprint.find(fingerprint);
        if (existing != m_lastAlertByFingerprint.end() && (alert.timestamp - existing->second) < kDuplicateAlertWindow) {
            return;
        }

        m_lastAlertByFingerprint[fingerprint] = alert.timestamp;
        ++m_statistics.alertsRaised;

        switch (alert.threatType) {
        case IdentityThreat::BruteForce:
            ++m_statistics.bruteForceDetections;
            break;
        case IdentityThreat::PasswordSpray:
            ++m_statistics.passwordSprayDetections;
            break;
        case IdentityThreat::Kerberoasting:
            ++m_statistics.kerberoastingDetections;
            break;
        case IdentityThreat::DCSync:
            ++m_statistics.dcsyncDetections;
            break;
        default:
            break;
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
                SU::ToNarrow(alert.mitreTechnique))) {
            LogDatabaseError("EmitAlertUnlocked", dbError);
        }

        Logger::Warn(
            "{} threat={} severity={} user={} source={} evidence={}",
            kLogPrefix,
            static_cast<int>(alert.threatType),
            alert.severity,
            SU::ToNarrow(alert.affectedUser),
            SU::ToNarrow(alert.sourceIP),
            SU::ToNarrow(alert.evidence));
    }

    static void PruneTimestamps(std::vector<IdentityTimestamp>& timestamps, const IdentityTimestamp threshold) {
        timestamps.erase(
            std::remove_if(timestamps.begin(), timestamps.end(), [&](const IdentityTimestamp value) {
                return value < threshold;
            }),
            timestamps.end());
    }

    static void PruneSourceEntries(
        std::vector<std::pair<IdentityTimestamp, std::wstring>>& entries,
        const IdentityTimestamp threshold) {
        entries.erase(
            std::remove_if(entries.begin(), entries.end(), [&](const auto& entry) {
                return entry.first < threshold;
            }),
            entries.end());
    }

    mutable std::shared_mutex m_mutex;
    std::atomic<bool> m_initialized{false};
    std::atomic<bool> m_monitoring{false};
    std::wstring m_databasePath;
    std::jthread m_worker;
    EVT_HANDLE m_subscriptionHandle{nullptr};
    ADMonitorStatistics m_statistics{};
    std::unordered_map<std::wstring, std::vector<IdentityTimestamp>> m_recentFailedByAccount;
    std::unordered_map<std::wstring, std::vector<std::pair<IdentityTimestamp, std::wstring>>> m_recentFailedBySource;
    std::unordered_map<std::wstring, IdentityTimestamp> m_lastAlertByFingerprint;
};

DWORD WINAPI EventSubscriptionCallback(
    const EVT_SUBSCRIBE_NOTIFY_ACTION action,
    const PVOID userContext,
    const EVT_HANDLE eventHandle) {
    auto* impl = static_cast<ADMonitorImpl*>(userContext);
    if (impl == nullptr) {
        return ERROR_INVALID_PARAMETER;
    }

    return impl->HandleSubscriptionCallback(action, eventHandle);
}

ADMonitor& ADMonitor::Instance() {
    static ADMonitor instance;
    return instance;
}

ADMonitor::ADMonitor()
    : m_impl(std::make_unique<ADMonitorImpl>()) {
}

ADMonitor::~ADMonitor() = default;

bool ADMonitor::Initialize(const std::wstring& databasePath) {
    return m_impl->Initialize(databasePath);
}

void ADMonitor::Shutdown() {
    m_impl->Shutdown();
}

bool ADMonitor::StartMonitoring() {
    return m_impl->StartMonitoring();
}

void ADMonitor::StopMonitoring() {
    m_impl->StopMonitoring();
}

bool ADMonitor::IsInitialized() const noexcept {
    return m_impl->IsInitialized();
}

bool ADMonitor::IsMonitoring() const noexcept {
    return m_impl->IsMonitoring();
}

std::vector<LogonEvent> ADMonitor::GetRecentLogons(const size_t limit, const bool successfulOnly) const {
    return m_impl->GetRecentLogons(limit, successfulOnly);
}

std::vector<LogonEvent> ADMonitor::GetFailedLogons(const size_t limit, std::wstring_view sourceIP) const {
    return m_impl->GetFailedLogons(limit, sourceIP);
}

std::vector<GroupChangeEvent> ADMonitor::GetGroupChanges(const size_t limit, std::wstring_view targetUser) const {
    return m_impl->GetGroupChanges(limit, targetUser);
}

std::vector<IdentityAlert> ADMonitor::GetAlerts(const size_t limit, const std::optional<IdentityThreat> threat) const {
    return m_impl->GetAlerts(limit, threat);
}

ADMonitorStatistics ADMonitor::GetStatistics() const {
    return m_impl->GetStatistics();
}

} // namespace ShadowStrike::Products::PhantomXDR::IdentityProtection
