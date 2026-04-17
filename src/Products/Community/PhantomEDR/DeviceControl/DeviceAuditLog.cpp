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
#include "Products/Community/PhantomEDR/DeviceControl/DeviceAuditLog.hpp"

#include "PhantomCore/Database/DatabaseManager.hpp"
#include "PhantomCore/Utils/FileUtils.hpp"
#include "PhantomCore/Utils/Logger.hpp"
#include "PhantomCore/Utils/StringUtils.hpp"

#include <algorithm>
#include <filesystem>
#include <string>
#include <string_view>

namespace ShadowStrike::Products::PhantomEDR::DeviceControl {

namespace {

using ShadowStrike::Database::DatabaseConfig;
using ShadowStrike::Database::DatabaseError;
using ShadowStrike::Database::DatabaseManager;
using ShadowStrike::Database::QueryResult;
using ShadowStrike::Utils::Logger;
namespace FileUtils = ShadowStrike::Utils::FileUtils;
namespace StringUtils = ShadowStrike::Utils::StringUtils;

constexpr std::string_view kLogPrefix = "[DeviceAuditLog]";
constexpr uint32_t kDefaultRetentionDays = 90;
constexpr uint32_t kMaxRetentionDays = 3650;
constexpr uint32_t kMaxQueryLimit = 10000;

[[nodiscard]] int64_t ToUnixSeconds(const DeviceTimestamp value) noexcept
{
    return std::chrono::duration_cast<std::chrono::seconds>(value.time_since_epoch()).count();
}

[[nodiscard]] DeviceTimestamp FromUnixSeconds(const int64_t value) noexcept
{
    return DeviceTimestamp{std::chrono::seconds{value}};
}

[[nodiscard]] std::wstring GetProgramDataRoot()
{
    DWORD length = ::GetEnvironmentVariableW(L"ProgramData", nullptr, 0);
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

[[nodiscard]] std::wstring GetDefaultDatabasePath()
{
    return GetProgramDataRoot() + L"\\ShadowStrike\\DeviceControl\\device_control.db";
}

[[nodiscard]] bool EnsureDatabaseReady(const std::wstring& databasePath, DatabaseError* dbErr)
{
    auto& db = DatabaseManager::Instance();
    if (db.IsInitialized()) {
        return true;
    }

    FileUtils::Error fileErr;
    const std::filesystem::path dbPath{databasePath};
    if (!FileUtils::CreateDirectories(dbPath.parent_path().wstring(), &fileErr)) {
        Logger::Error("{} Unable to create database directory: {}", kLogPrefix, fileErr.message);
        return false;
    }

    DatabaseConfig config{};
    config.databasePath = databasePath;
    config.enableWAL = true;
    config.minConnections = 1;
    config.maxConnections = 4;
    config.autoBackup = false;
    config.enableMemoryMappedIO = true;
    return db.Initialize(config, dbErr);
}

void LogDatabaseError(const std::string_view context, const DatabaseError& error)
{
    Logger::Error(
        "{} {} sqliteCode={} message={}",
        kLogPrefix,
        context,
        error.sqliteCode,
        StringUtils::ToNarrow(error.message));
}

[[nodiscard]] std::string NullSafeString(const QueryResult& result, const int columnIndex)
{
    return result.IsNull(columnIndex) ? std::string{} : result.GetString(columnIndex);
}

[[nodiscard]] std::wstring NullSafeWString(const QueryResult& result, const int columnIndex)
{
    return result.IsNull(columnIndex) ? std::wstring{} : result.GetWString(columnIndex);
}

constexpr std::string_view kCreateEventsTableSql = R"(
    CREATE TABLE IF NOT EXISTS device_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp INTEGER NOT NULL,
        event_kind INTEGER NOT NULL,
        device_type INTEGER NOT NULL,
        vid TEXT,
        pid TEXT,
        serial TEXT,
        description TEXT,
        manufacturer TEXT,
        action_taken INTEGER NOT NULL,
        user TEXT,
        hostname TEXT,
        instance_id TEXT,
        interface_path TEXT,
        reason TEXT
    );
)";

constexpr std::string_view kCreateEventsIndexSql = R"(
    CREATE INDEX IF NOT EXISTS idx_device_events_timestamp ON device_events(timestamp DESC);
    CREATE INDEX IF NOT EXISTS idx_device_events_type_action ON device_events(device_type, action_taken);
    CREATE INDEX IF NOT EXISTS idx_device_events_serial ON device_events(serial);
)";

constexpr std::string_view kInsertEventSql = R"(
    INSERT INTO device_events (
        timestamp, event_kind, device_type, vid, pid, serial, description,
        manufacturer, action_taken, user, hostname, instance_id, interface_path, reason
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
)";

constexpr std::string_view kPurgeSql = R"(
    DELETE FROM device_events WHERE timestamp < ?;
)";

} // namespace

class DeviceAuditLogImpl final {
public:
    [[nodiscard]] bool Initialize(const std::wstring& databasePath, const uint32_t retentionDays)
    {
        std::unique_lock lock(m_mutex);

        DatabaseError dbError;
        m_databasePath = databasePath.empty() ? GetDefaultDatabasePath() : databasePath;
        if (!EnsureDatabaseReady(m_databasePath, &dbError)) {
            if (dbError.HasError()) {
                LogDatabaseError("Initialize", dbError);
            }
            return false;
        }

        auto& db = DatabaseManager::Instance();
        if (!db.Execute(kCreateEventsTableSql, &dbError) || !db.Execute(kCreateEventsIndexSql, &dbError)) {
            LogDatabaseError("InitializeSchema", dbError);
            return false;
        }

        m_retentionDays = std::clamp(retentionDays, 1U, kMaxRetentionDays);
        m_initialized = true;
        lock.unlock();

        (void)PurgeExpiredEvents();
        Logger::Info("{} Initialized databasePath={}", kLogPrefix, StringUtils::ToNarrow(m_databasePath));
        return true;
    }

    void Shutdown()
    {
        std::unique_lock lock(m_mutex);
        m_initialized = false;
    }

    [[nodiscard]] bool IsInitialized() const
    {
        std::shared_lock lock(m_mutex);
        return m_initialized;
    }

    [[nodiscard]] bool RecordEvent(const DeviceEvent& event)
    {
        std::shared_lock lock(m_mutex);
        if (!m_initialized) {
            Logger::Warn("{} RecordEvent called before initialization", kLogPrefix);
            return false;
        }

        DatabaseError dbError;
        const bool success = DatabaseManager::Instance().ExecuteWithParams(
            kInsertEventSql,
            &dbError,
            ToUnixSeconds(event.timestamp),
            static_cast<int>(event.eventKind),
            static_cast<int>(event.device.type),
            event.device.vendorId,
            event.device.productId,
            event.device.serialNumber,
            event.device.description,
            event.device.manufacturer,
            static_cast<int>(event.actionTaken),
            event.userName,
            event.hostName,
            StringUtils::ToNarrow(event.device.instanceId),
            StringUtils::ToNarrow(event.device.interfacePath),
            event.reason);

        if (!success) {
            LogDatabaseError("RecordEvent", dbError);
            return false;
        }

        return true;
    }

    [[nodiscard]] std::vector<DeviceEvent> QueryEvents(const DeviceEventQuery& query) const
    {
        std::shared_lock lock(m_mutex);
        std::vector<DeviceEvent> events;
        if (!m_initialized) {
            return events;
        }

        std::string sql =
            "SELECT id, timestamp, event_kind, device_type, vid, pid, serial, description, manufacturer, "
            "action_taken, user, hostname, instance_id, interface_path, reason FROM device_events WHERE 1=1";
        std::vector<std::string> params;

        if (query.startTime.has_value()) {
            sql += " AND timestamp >= ?";
            params.push_back(std::to_string(ToUnixSeconds(*query.startTime)));
        }
        if (query.endTime.has_value()) {
            sql += " AND timestamp <= ?";
            params.push_back(std::to_string(ToUnixSeconds(*query.endTime)));
        }
        if (query.deviceType.has_value()) {
            sql += " AND device_type = ?";
            params.push_back(std::to_string(static_cast<int>(*query.deviceType)));
        }
        if (query.actionTaken.has_value()) {
            sql += " AND action_taken = ?";
            params.push_back(std::to_string(static_cast<int>(*query.actionTaken)));
        }

        const uint32_t limit = std::clamp(query.limit, 1U, kMaxQueryLimit);
        sql += " ORDER BY timestamp DESC LIMIT " + std::to_string(limit);

        DatabaseError dbError;
        auto result = DatabaseManager::Instance().QueryWithParamsVector(sql, params, &dbError);
        while (result.Next()) {
            DeviceEvent event;
            event.eventId = result.GetInt64(0);
            event.timestamp = FromUnixSeconds(result.GetInt64(1));
            event.eventKind = static_cast<DeviceEventKind>(result.GetInt(2));
            event.device.type = static_cast<DeviceType>(result.GetInt(3));
            event.device.vendorId = NullSafeString(result, 4);
            event.device.productId = NullSafeString(result, 5);
            event.device.serialNumber = NullSafeString(result, 6);
            event.device.description = NullSafeString(result, 7);
            event.device.manufacturer = NullSafeString(result, 8);
            event.actionTaken = static_cast<DevicePolicyAction>(result.GetInt(9));
            event.userName = NullSafeString(result, 10);
            event.hostName = NullSafeString(result, 11);
            event.device.instanceId = NullSafeWString(result, 12);
            event.device.interfacePath = NullSafeWString(result, 13);
            event.reason = NullSafeString(result, 14);
            events.push_back(std::move(event));
        }

        if (dbError.HasError()) {
            LogDatabaseError("QueryEvents", dbError);
            events.clear();
        }

        return events;
    }

    [[nodiscard]] uint64_t PurgeExpiredEvents()
    {
        std::shared_lock lock(m_mutex);
        if (!m_initialized) {
            return 0;
        }

        DatabaseError dbError;
        const int64_t cutoff = ToUnixSeconds(std::chrono::system_clock::now() - std::chrono::hours(24 * m_retentionDays));
        if (!DatabaseManager::Instance().ExecuteWithParams(kPurgeSql, &dbError, cutoff)) {
            LogDatabaseError("PurgeExpiredEvents", dbError);
            return 0;
        }

        return static_cast<uint64_t>(std::max(DatabaseManager::Instance().GetChangedRowCount(), 0));
    }

    [[nodiscard]] bool SetRetentionDays(const uint32_t retentionDays)
    {
        {
            std::unique_lock lock(m_mutex);
            if (!m_initialized) {
                return false;
            }
            m_retentionDays = std::clamp(retentionDays, 1U, kMaxRetentionDays);
        }

        (void)PurgeExpiredEvents();
        return true;
    }

    [[nodiscard]] uint32_t GetRetentionDays() const
    {
        std::shared_lock lock(m_mutex);
        return m_retentionDays;
    }

private:
    mutable std::shared_mutex m_mutex;
    bool m_initialized = false;
    std::wstring m_databasePath;
    uint32_t m_retentionDays = kDefaultRetentionDays;
};

DeviceAuditLog& DeviceAuditLog::Instance()
{
    static DeviceAuditLog instance;
    return instance;
}

DeviceAuditLog::DeviceAuditLog() : m_impl(std::make_unique<DeviceAuditLogImpl>()) {}
DeviceAuditLog::~DeviceAuditLog() = default;

bool DeviceAuditLog::Initialize(const std::wstring& databasePath, const uint32_t retentionDays)
{
    return m_impl->Initialize(databasePath, retentionDays);
}

void DeviceAuditLog::Shutdown()
{
    m_impl->Shutdown();
}

bool DeviceAuditLog::IsInitialized() const
{
    return m_impl->IsInitialized();
}

bool DeviceAuditLog::RecordEvent(const DeviceEvent& event)
{
    return m_impl->RecordEvent(event);
}

std::vector<DeviceEvent> DeviceAuditLog::QueryEvents(const DeviceEventQuery& query) const
{
    return m_impl->QueryEvents(query);
}

uint64_t DeviceAuditLog::PurgeExpiredEvents()
{
    return m_impl->PurgeExpiredEvents();
}

bool DeviceAuditLog::SetRetentionDays(const uint32_t retentionDays)
{
    return m_impl->SetRetentionDays(retentionDays);
}

uint32_t DeviceAuditLog::GetRetentionDays() const
{
    return m_impl->GetRetentionDays();
}

} // namespace ShadowStrike::Products::PhantomEDR::DeviceControl
