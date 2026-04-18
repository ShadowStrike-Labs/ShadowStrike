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
#include "Products/Community/PhantomXDR/IdentityProtection/CredentialProtection.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <format>
#include <memory>
#include <optional>
#include <set>
#include <shared_mutex>
#include <string>
#include <string_view>
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
#include <tlhelp32.h>
#include <wincred.h>

#include "PhantomCore/Database/DatabaseManager.hpp"
#include "PhantomCore/Utils/FileUtils.hpp"
#include "PhantomCore/Utils/Logger.hpp"
#include "PhantomCore/Utils/StringUtils.hpp"

#pragma comment(lib, "Advapi32.lib")

namespace ShadowStrike::Products::PhantomXDR::IdentityProtection {

namespace {

using ShadowStrike::Database::DatabaseConfig;
using ShadowStrike::Database::DatabaseError;
using ShadowStrike::Database::DatabaseManager;
using ShadowStrike::Database::QueryResult;
using ShadowStrike::Utils::Logger;
namespace FileUtils = ShadowStrike::Utils::FileUtils;
namespace SU = ShadowStrike::Utils::StringUtils;

constexpr std::string_view kLogPrefix = "[IdentityProtection::CredentialProtection]";
constexpr size_t kDefaultLimit = 100;
constexpr size_t kMaxLimit = 500;

constexpr std::string_view kCreateAccessTableSql = R"SQL(
    CREATE TABLE IF NOT EXISTS credential_access_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp INTEGER NOT NULL,
        process_name TEXT NOT NULL,
        target_name TEXT NOT NULL,
        access_type TEXT NOT NULL,
        success INTEGER NOT NULL,
        evidence TEXT NOT NULL
    );
)SQL";

constexpr std::string_view kCreateAlertsTableSql = R"SQL(
    CREATE TABLE IF NOT EXISTS credential_alerts (
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

constexpr std::string_view kCreateHoneypotTableSql = R"SQL(
    CREATE TABLE IF NOT EXISTS credential_honeypots (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        created_at INTEGER NOT NULL,
        credential_target TEXT NOT NULL,
        user_name TEXT NOT NULL,
        secret_hint TEXT NOT NULL,
        active INTEGER NOT NULL
    );
)SQL";

constexpr std::string_view kCreateIndexesSql = R"SQL(
    CREATE INDEX IF NOT EXISTS idx_credential_access_time ON credential_access_events(timestamp DESC, target_name);
    CREATE INDEX IF NOT EXISTS idx_credential_alerts_time ON credential_alerts(timestamp DESC, threat_type);
    CREATE INDEX IF NOT EXISTS idx_credential_honeypots_user ON credential_honeypots(user_name, active);
)SQL";

constexpr std::string_view kInsertAccessSql = R"SQL(
    INSERT INTO credential_access_events(timestamp, process_name, target_name, access_type, success, evidence)
    VALUES (?, ?, ?, ?, ?, ?);
)SQL";

constexpr std::string_view kInsertAlertSql = R"SQL(
    INSERT INTO credential_alerts(timestamp, threat_type, severity, evidence, affected_user, source_ip, mitre_technique, module_name)
    VALUES (?, ?, ?, ?, ?, ?, ?, 'CredentialProtection');
)SQL";

constexpr std::string_view kInsertHoneypotSql = R"SQL(
    INSERT INTO credential_honeypots(created_at, credential_target, user_name, secret_hint, active)
    VALUES (?, ?, ?, ?, ?);
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

[[nodiscard]] std::wstring NullSafeWString(const QueryResult& result, const char* columnName) {
    return result.IsNull(columnName) ? std::wstring{} : result.GetWString(columnName);
}

[[nodiscard]] bool ContainsInsensitive(std::wstring_view haystack, std::wstring_view needle) {
    return SU::IContains(haystack, needle);
}

[[nodiscard]] uint32_t SeverityForThreat(const IdentityThreat threat) {
    switch (threat) {
    case IdentityThreat::CredentialDumping:
        return 95;
    case IdentityThreat::PassTheHash:
        return 90;
    case IdentityThreat::OverPassTheHash:
        return 90;
    case IdentityThreat::PassTheTicket:
        return 85;
    default:
        return 75;
    }
}

[[nodiscard]] std::wstring MitreTechniqueForThreat(const IdentityThreat threat) {
    switch (threat) {
    case IdentityThreat::CredentialDumping:
        return L"T1003.001";
    case IdentityThreat::PassTheHash:
        return L"T1550.002";
    case IdentityThreat::OverPassTheHash:
        return L"T1550.002";
    case IdentityThreat::PassTheTicket:
        return L"T1550.003";
    default:
        return L"T1003";
    }
}

[[nodiscard]] std::vector<std::wstring> GetKnownCredentialToolNames() {
    return {
        L"mimikatz.exe",
        L"mimikatz",
        L"rubeus.exe",
        L"rubeus",
        L"procdump.exe",
        L"procdump64.exe",
        L"nanodump.exe",
        L"nanodump",
        L"comsvcs.dll",
        L"dumpert.exe",
        L"pwdump.exe",
        L"secretsdump.py",
        L"lsassy.exe"
    };
}

[[nodiscard]] std::vector<std::wstring> GetSensitiveTargets() {
    return {L"lsass", L"sam", L"ntds.dit", L"wdigest", L"kerberos"};
}

[[nodiscard]] bool IsSensitiveTarget(std::wstring_view value) {
    for (const auto& target : GetSensitiveTargets()) {
        if (ContainsInsensitive(value, target)) {
            return true;
        }
    }
    return false;
}

[[nodiscard]] bool IsSuspiciousProcessName(std::wstring_view processName) {
    const std::wstring normalized = Lower(std::wstring{processName});
    for (const auto& tool : GetKnownCredentialToolNames()) {
        if (ContainsInsensitive(normalized, Lower(tool))) {
            return true;
        }
    }
    return false;
}

[[nodiscard]] std::wstring GenerateHoneypotUserName() {
    FILETIME fileTime{};
    ::GetSystemTimeAsFileTime(&fileTime);
    const ULARGE_INTEGER ts{
        .LowPart = fileTime.dwLowDateTime,
        .HighPart = fileTime.dwHighDateTime
    };
    return std::format(L"svc_shadow_hny_{:08x}", static_cast<unsigned int>(ts.LowPart ^ ts.HighPart));
}

[[nodiscard]] std::wstring GenerateHoneypotPasswordHint() {
    FILETIME fileTime{};
    ::GetSystemTimeAsFileTime(&fileTime);
    return std::format(L"DoNotUse-{:08x}{:08x}", fileTime.dwHighDateTime, fileTime.dwLowDateTime);
}

[[nodiscard]] std::optional<DWORD> FindProcessIdByName(std::wstring_view processName) {
    HANDLE snapshot = ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return std::nullopt;
    }

    PROCESSENTRY32W entry{};
    entry.dwSize = sizeof(entry);
    std::optional<DWORD> pid;

    if (::Process32FirstW(snapshot, &entry) != FALSE) {
        do {
            if (SU::IEquals(entry.szExeFile, processName)) {
                pid = entry.th32ProcessID;
                break;
            }
        } while (::Process32NextW(snapshot, &entry) != FALSE);
    }

    ::CloseHandle(snapshot);
    return pid;
}

[[nodiscard]] IdentityThreat ThreatFromInt(const int value) {
    if (value < 0 || value > static_cast<int>(IdentityThreat::PrivilegeEscalation)) {
        return IdentityThreat::None;
    }
    return static_cast<IdentityThreat>(value);
}

[[nodiscard]] bool ReadRegistryDword(const HKEY rootKey, std::wstring_view path, std::wstring_view valueName, DWORD& value) {
    HKEY key = nullptr;
    if (::RegOpenKeyExW(rootKey, std::wstring(path).c_str(), 0, KEY_QUERY_VALUE, &key) != ERROR_SUCCESS) {
        return false;
    }

    DWORD type = 0;
    DWORD size = sizeof(value);
    const LONG status = ::RegQueryValueExW(key, std::wstring(valueName).c_str(), nullptr, &type, reinterpret_cast<LPBYTE>(&value), &size);
    ::RegCloseKey(key);
    return status == ERROR_SUCCESS && type == REG_DWORD;
}

} // namespace

class CredentialProtectionImpl final {
public:
    [[nodiscard]] bool Initialize(const std::wstring& requestedDatabasePath, const bool deployHoneypot) {
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

        const std::array<std::string_view, 3> statements{
            kCreateAccessTableSql,
            kCreateAlertsTableSql,
            kCreateHoneypotTableSql
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

        m_statistics.lsassProtected = QueryLSASSProtectionState();
        if (deployHoneypot) {
            DeployHoneypotCredentialUnlocked();
        }

        m_initialized.store(true, std::memory_order_release);
        Logger::Info(
            "{} initialized databasePath={} honeypotActive={}",
            kLogPrefix,
            SU::ToNarrow(m_databasePath),
            m_statistics.honeypotActive);
        return true;
    }

    void Shutdown() {
        std::unique_lock lock(m_mutex);
        m_initialized.store(false, std::memory_order_release);
        m_databasePath.clear();
        m_honeypotUser.clear();
        m_honeypotTarget.clear();
        m_honeypotHint.clear();
        m_lastAlertFingerprint.clear();
    }

    [[nodiscard]] bool IsInitialized() const noexcept {
        return m_initialized.load(std::memory_order_acquire);
    }

    [[nodiscard]] std::vector<IdentityAlert> MonitorLSASS() {
        std::vector<IdentityAlert> alerts;
        if (!m_initialized.load(std::memory_order_acquire)) {
            Logger::Warn("{} MonitorLSASS called before Initialize", kLogPrefix);
            return alerts;
        }

        {
            std::unique_lock lock(m_mutex);
            ++m_statistics.lsassChecks;
            m_statistics.lsassProtected = QueryLSASSProtectionState();
        }

        const std::optional<DWORD> lsassPid = FindProcessIdByName(L"lsass.exe");
        if (!lsassPid.has_value()) {
            Logger::Warn("{} unable to resolve lsass.exe process identifier", kLogPrefix);
        }

        HANDLE snapshot = ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snapshot == INVALID_HANDLE_VALUE) {
            Logger::Error("{} CreateToolhelp32Snapshot failed error={}", kLogPrefix, ::GetLastError());
            return alerts;
        }

        PROCESSENTRY32W entry{};
        entry.dwSize = sizeof(entry);
        if (::Process32FirstW(snapshot, &entry) != FALSE) {
            do {
                const std::wstring processName = entry.szExeFile;
                if (processName.empty()) {
                    continue;
                }

                if (lsassPid.has_value() && entry.th32ProcessID == *lsassPid) {
                    continue;
                }

                if (IsSuspiciousProcessName(processName)) {
                    const CredentialAccessEvent accessEvent{
                        std::chrono::system_clock::now(),
                        processName,
                        L"lsass",
                        L"credential-dumping-tool-presence",
                        true
                    };
                    PersistAccessEvent(accessEvent, std::format(L"process '{}' matched known credential dumping indicators", processName));

                    IdentityAlert alert{};
                    alert.timestamp = accessEvent.timestamp;
                    alert.threatType = IdentityThreat::CredentialDumping;
                    alert.severity = SeverityForThreat(IdentityThreat::CredentialDumping);
                    alert.evidence = std::format(
                        L"process '{}' is commonly used for LSASS or credential material access",
                        processName);
                    alert.affectedUser = processName;
                    alert.mitreTechnique = MitreTechniqueForThreat(IdentityThreat::CredentialDumping);
                    alerts.push_back(std::move(alert));
                }
            } while (::Process32NextW(snapshot, &entry) != FALSE);
        }

        ::CloseHandle(snapshot);

        auto externalAlerts = ScanRawSecurityEvents();
        alerts.insert(alerts.end(), externalAlerts.begin(), externalAlerts.end());

        DeduplicateAndPersistAlerts(alerts);
        return alerts;
    }

    [[nodiscard]] std::vector<IdentityAlert> DetectCredentialAccess() {
        std::vector<IdentityAlert> alerts = MonitorLSASS();

        auto ntlmAlerts = DetectPassTheHashPatterns();
        alerts.insert(alerts.end(), ntlmAlerts.begin(), ntlmAlerts.end());

        auto honeypotAlerts = DetectHoneypotUsage();
        alerts.insert(alerts.end(), honeypotAlerts.begin(), honeypotAlerts.end());

        DeduplicateAndPersistAlerts(alerts);
        return alerts;
    }

    [[nodiscard]] std::vector<IdentityAlert> GetCredentialAlerts(const size_t limit) const {
        std::vector<IdentityAlert> alerts;
        if (!m_initialized.load(std::memory_order_acquire)) {
            return alerts;
        }

        DatabaseError dbError{};
        const std::string sql =
            "SELECT timestamp, threat_type, severity, evidence, affected_user, source_ip, mitre_technique "
            "FROM credential_alerts WHERE module_name = 'CredentialProtection' "
            "ORDER BY timestamp DESC LIMIT " + std::to_string(ClampLimit(limit));
        auto result = DatabaseManager::Instance().Query(sql, &dbError);
        if (dbError.HasError()) {
            LogDatabaseError("GetCredentialAlerts", dbError);
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

    [[nodiscard]] bool IsLSASSProtected() const {
        if (!m_initialized.load(std::memory_order_acquire)) {
            return false;
        }

        std::shared_lock lock(m_mutex);
        return m_statistics.lsassProtected;
    }

    [[nodiscard]] CredentialProtectionStatistics GetStatistics() const {
        std::shared_lock lock(m_mutex);
        return m_statistics;
    }

private:
    [[nodiscard]] bool QueryLSASSProtectionState() const {
        DWORD runAsPpl = 0;
        if (ReadRegistryDword(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Lsa", L"RunAsPPL", runAsPpl) && runAsPpl != 0U) {
            return true;
        }

        DWORD credentialGuard = 0;
        return ReadRegistryDword(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Lsa", L"LsaCfgFlags", credentialGuard) && credentialGuard != 0U;
    }

    void DeployHoneypotCredentialUnlocked() {
        if (m_statistics.honeypotActive) {
            return;
        }

        m_honeypotUser = GenerateHoneypotUserName();
        m_honeypotTarget = std::format(L"ShadowStrike-Identity-Honeypot-{}", m_honeypotUser);
        m_honeypotHint = GenerateHoneypotPasswordHint();

        std::vector<wchar_t> secret(m_honeypotHint.begin(), m_honeypotHint.end());
        CREDENTIALW credential{};
        credential.Type = CRED_TYPE_GENERIC;
        credential.TargetName = m_honeypotTarget.data();
        credential.UserName = m_honeypotUser.data();
        credential.CredentialBlob = reinterpret_cast<LPBYTE>(secret.data());
        credential.CredentialBlobSize = static_cast<DWORD>(secret.size() * sizeof(wchar_t));
        credential.Persist = CRED_PERSIST_LOCAL_MACHINE;
        credential.Comment = const_cast<LPWSTR>(L"ShadowStrike Identity honeypot credential");

        if (::CredWriteW(&credential, 0) == FALSE) {
            Logger::Warn("{} CredWriteW failed error={}", kLogPrefix, ::GetLastError());
            return;
        }

        DatabaseError dbError{};
        if (!DatabaseManager::Instance().ExecuteWithParams(
                kInsertHoneypotSql,
                &dbError,
                ToUnixSeconds(std::chrono::system_clock::now()),
                SU::ToNarrow(m_honeypotTarget),
                SU::ToNarrow(m_honeypotUser),
                SU::ToNarrow(m_honeypotHint),
                1)) {
            LogDatabaseError("DeployHoneypotCredentialUnlocked", dbError);
            return;
        }

        ++m_statistics.honeypotDeployments;
        m_statistics.honeypotActive = true;
    }

    void PersistAccessEvent(const CredentialAccessEvent& event, const std::wstring& evidence) {
        DatabaseError dbError{};
        if (!DatabaseManager::Instance().ExecuteWithParams(
                kInsertAccessSql,
                &dbError,
                ToUnixSeconds(event.timestamp),
                SU::ToNarrow(event.process),
                SU::ToNarrow(event.target),
                SU::ToNarrow(event.accessType),
                event.success ? 1 : 0,
                SU::ToNarrow(evidence))) {
            LogDatabaseError("PersistAccessEvent", dbError);
            return;
        }

        std::unique_lock lock(m_mutex);
        ++m_statistics.credentialAccessEvents;
    }

    [[nodiscard]] std::vector<IdentityAlert> ScanRawSecurityEvents() {
        std::vector<IdentityAlert> alerts;

        DatabaseError dbError{};
        const auto startTime = std::chrono::system_clock::now() - std::chrono::hours{12};
        auto result = DatabaseManager::Instance().QueryWithParams(
            "SELECT timestamp, event_id, computer, event_xml FROM identity_raw_events "
            "WHERE timestamp >= ? ORDER BY timestamp DESC LIMIT 500",
            &dbError,
            ToUnixSeconds(startTime));
        if (dbError.HasError()) {
            LogDatabaseError("ScanRawSecurityEvents", dbError);
            return alerts;
        }

        while (result.Next()) {
            const std::wstring xml = NullSafeWString(result, "event_xml");
            if (!IsSensitiveTarget(xml)) {
                continue;
            }

            const std::wstring computer = NullSafeWString(result, "computer");
            const int eventId = result.GetInt("event_id");
            const std::wstring subject = ExtractXmlData(xml, L"SubjectUserName");
            const std::wstring processName = ExtractXmlData(xml, L"ProcessName");
            const std::wstring objectName = ExtractXmlData(xml, L"ObjectName");
            const std::wstring accessMask = ExtractXmlData(xml, L"AccessMask");

            if (!IsSensitiveTarget(objectName) && !IsSensitiveTarget(processName) && !IsSensitiveTarget(xml)) {
                continue;
            }

            const CredentialAccessEvent accessEvent{
                FromUnixSeconds(result.GetInt64("timestamp")),
                processName.empty() ? computer : processName,
                objectName.empty() ? L"lsass" : objectName,
                accessMask.empty() ? std::format(L"event-{}", eventId) : accessMask,
                true
            };
            PersistAccessEvent(
                accessEvent,
                std::format(L"security event {} indicated access to '{}'", eventId, accessEvent.target));

            IdentityAlert alert{};
            alert.timestamp = accessEvent.timestamp;
            alert.threatType = IdentityThreat::CredentialDumping;
            alert.severity = SeverityForThreat(IdentityThreat::CredentialDumping);
            alert.evidence = std::format(
                L"event {} indicates '{}' attempted access to sensitive credential material '{}'",
                eventId,
                accessEvent.process,
                accessEvent.target);
            alert.affectedUser = subject;
            alert.sourceIP = computer;
            alert.mitreTechnique = MitreTechniqueForThreat(IdentityThreat::CredentialDumping);
            alerts.push_back(std::move(alert));
        }

        return alerts;
    }

    [[nodiscard]] std::vector<IdentityAlert> DetectPassTheHashPatterns() {
        std::vector<IdentityAlert> alerts;
        DatabaseError dbError{};
        const auto startTime = std::chrono::system_clock::now() - std::chrono::minutes{30};
        auto result = DatabaseManager::Instance().QueryWithParams(
            "SELECT user_name, source_ip, source_host, logon_type, event_id, authentication_package, timestamp "
            "FROM identity_logons WHERE timestamp >= ? AND success = 1 AND logon_type = ? "
            "ORDER BY user_name ASC, timestamp DESC",
            &dbError,
            ToUnixSeconds(startTime),
            static_cast<int>(LogonType::Network));
        if (dbError.HasError()) {
            LogDatabaseError("DetectPassTheHashPatterns", dbError);
            return alerts;
        }

        struct SourceSummary {
            std::unordered_set<std::wstring> sources;
            std::unordered_set<std::wstring> hosts;
            bool ntlmObserved{false};
            IdentityTimestamp newest{};
        };

        std::unordered_map<std::wstring, SourceSummary> summaryByUser;
        while (result.Next()) {
            const std::wstring userName = Lower(NullSafeWString(result, "user_name"));
            if (userName.empty()) {
                continue;
            }

            auto& summary = summaryByUser[userName];
            const std::wstring sourceIp = Lower(NullSafeWString(result, "source_ip"));
            const std::wstring sourceHost = Lower(NullSafeWString(result, "source_host"));
            if (!sourceIp.empty()) {
                summary.sources.insert(sourceIp);
            }
            if (!sourceHost.empty()) {
                summary.hosts.insert(sourceHost);
            }

            const std::wstring packageName = Lower(NullSafeWString(result, "authentication_package"));
            if (packageName.empty() || ContainsInsensitive(packageName, L"ntlm")) {
                summary.ntlmObserved = true;
            }

            summary.newest = FromUnixSeconds(result.GetInt64("timestamp"));
        }

        for (const auto& [userName, summary] : summaryByUser) {
            if (!summary.ntlmObserved || summary.sources.size() < 3U) {
                continue;
            }

            IdentityAlert alert{};
            alert.timestamp = summary.newest;
            alert.threatType = IdentityThreat::PassTheHash;
            alert.severity = SeverityForThreat(IdentityThreat::PassTheHash);
            alert.evidence = std::format(
                L"user '{}' completed NTLM-style network logons from {} distinct sources inside a 30 minute window",
                userName,
                summary.sources.size());
            alert.affectedUser = userName;
            alert.sourceIP = summary.sources.empty() ? L"" : *summary.sources.begin();
            alert.mitreTechnique = MitreTechniqueForThreat(IdentityThreat::PassTheHash);
            alerts.push_back(std::move(alert));
        }

        return alerts;
    }

    [[nodiscard]] std::vector<IdentityAlert> DetectHoneypotUsage() {
        std::vector<IdentityAlert> alerts;
        std::shared_lock lock(m_mutex);
        if (!m_statistics.honeypotActive || m_honeypotUser.empty()) {
            return alerts;
        }
        const std::wstring honeypotUser = m_honeypotUser;
        lock.unlock();

        DatabaseError dbError{};
        auto result = DatabaseManager::Instance().QueryWithParams(
            "SELECT timestamp, source_ip, source_host FROM identity_logons "
            "WHERE user_name = ? AND success = 1 ORDER BY timestamp DESC LIMIT 25",
            &dbError,
            SU::ToNarrow(honeypotUser));
        if (dbError.HasError()) {
            LogDatabaseError("DetectHoneypotUsage", dbError);
            return alerts;
        }

        while (result.Next()) {
            IdentityAlert alert{};
            alert.timestamp = FromUnixSeconds(result.GetInt64("timestamp"));
            alert.threatType = IdentityThreat::CredentialDumping;
            alert.severity = 100;
            alert.evidence = std::format(
                L"honeypot credential '{}' was used successfully from '{}'/'{}'",
                honeypotUser,
                NullSafeWString(result, "source_ip"),
                NullSafeWString(result, "source_host"));
            alert.affectedUser = honeypotUser;
            alert.sourceIP = NullSafeWString(result, "source_ip");
            alert.mitreTechnique = L"T1003";
            alerts.push_back(std::move(alert));
        }

        return alerts;
    }

    void DeduplicateAndPersistAlerts(std::vector<IdentityAlert>& alerts) {
        std::vector<IdentityAlert> uniqueAlerts;
        uniqueAlerts.reserve(alerts.size());

        for (const auto& alert : alerts) {
            const std::wstring fingerprint = std::format(
                L"{}:{}:{}:{}",
                static_cast<int>(alert.threatType),
                Lower(alert.affectedUser),
                Lower(alert.sourceIP),
                Lower(alert.evidence.substr(0, std::min<size_t>(alert.evidence.size(), 96))));

            bool duplicate = false;
            {
                std::unique_lock lock(m_mutex);
                const auto existing = m_lastAlertFingerprint.find(fingerprint);
                if (existing != m_lastAlertFingerprint.end() &&
                    (alert.timestamp - existing->second) < std::chrono::minutes{30}) {
                    duplicate = true;
                } else {
                    m_lastAlertFingerprint[fingerprint] = alert.timestamp;
                }
            }

            if (duplicate) {
                continue;
            }

            uniqueAlerts.push_back(alert);
            PersistAlert(alert);
        }

        alerts.swap(uniqueAlerts);
    }

    void PersistAlert(const IdentityAlert& alert) {
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
            LogDatabaseError("PersistAlert", dbError);
            return;
        }

        std::unique_lock lock(m_mutex);
        ++m_statistics.credentialAlerts;
        if (alert.threatType == IdentityThreat::PassTheHash || alert.threatType == IdentityThreat::OverPassTheHash) {
            ++m_statistics.passTheHashDetections;
        }
        if (alert.threatType == IdentityThreat::CredentialDumping) {
            ++m_statistics.credentialDumpingDetections;
        }

        Logger::Warn(
            "{} threat={} user={} source={} evidence={}",
            kLogPrefix,
            static_cast<int>(alert.threatType),
            SU::ToNarrow(alert.affectedUser),
            SU::ToNarrow(alert.sourceIP),
            SU::ToNarrow(alert.evidence));
    }

    [[nodiscard]] std::wstring ExtractXmlData(std::wstring_view xml, std::wstring_view name) const {
        const std::array<std::wstring, 2> markers{
            std::format(L"<Data Name='{}'>", name),
            std::format(L"<Data Name=\"{}\">", name)
        };

        for (const auto& marker : markers) {
            const size_t start = xml.find(marker);
            if (start == std::wstring_view::npos) {
                continue;
            }

            const size_t valueStart = start + marker.size();
            const size_t end = xml.find(L"</Data>", valueStart);
            if (end == std::wstring_view::npos || end <= valueStart) {
                continue;
            }

            return Trimmed(std::wstring{xml.substr(valueStart, end - valueStart)});
        }

        return {};
    }

    mutable std::shared_mutex m_mutex;
    std::atomic<bool> m_initialized{false};
    std::wstring m_databasePath;
    std::wstring m_honeypotUser;
    std::wstring m_honeypotTarget;
    std::wstring m_honeypotHint;
    std::unordered_map<std::wstring, IdentityTimestamp> m_lastAlertFingerprint;
    CredentialProtectionStatistics m_statistics{};
};

CredentialProtection& CredentialProtection::Instance() {
    static CredentialProtection instance;
    return instance;
}

CredentialProtection::CredentialProtection()
    : m_impl(std::make_unique<CredentialProtectionImpl>()) {
}

CredentialProtection::~CredentialProtection() = default;

bool CredentialProtection::Initialize(const std::wstring& databasePath, const bool deployHoneypot) {
    return m_impl->Initialize(databasePath, deployHoneypot);
}

void CredentialProtection::Shutdown() {
    m_impl->Shutdown();
}

bool CredentialProtection::IsInitialized() const noexcept {
    return m_impl->IsInitialized();
}

std::vector<IdentityAlert> CredentialProtection::MonitorLSASS() {
    return m_impl->MonitorLSASS();
}

std::vector<IdentityAlert> CredentialProtection::DetectCredentialAccess() {
    return m_impl->DetectCredentialAccess();
}

std::vector<IdentityAlert> CredentialProtection::GetCredentialAlerts(const size_t limit) const {
    return m_impl->GetCredentialAlerts(limit);
}

bool CredentialProtection::IsLSASSProtected() const {
    return m_impl->IsLSASSProtected();
}

CredentialProtectionStatistics CredentialProtection::GetStatistics() const {
    return m_impl->GetStatistics();
}

} // namespace ShadowStrike::Products::PhantomXDR::IdentityProtection
