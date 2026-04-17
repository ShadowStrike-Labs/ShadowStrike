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
#include "Products/Community/PhantomEDR/DeviceControl/DeviceExceptions.hpp"

#include "PhantomCore/Database/DatabaseManager.hpp"
#include "PhantomCore/Utils/FileUtils.hpp"
#include "PhantomCore/Utils/Logger.hpp"
#include "PhantomCore/Utils/StringUtils.hpp"

#include <algorithm>
#include <cctype>
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

constexpr std::string_view kLogPrefix = "[DeviceExceptions]";
constexpr uint32_t kMaxExceptionsReturned = 10000;

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

[[nodiscard]] std::string NormalizeSerial(std::string_view value)
{
    std::string result;
    result.reserve(value.size());
    for (const unsigned char ch : value) {
        if (std::isalnum(ch) != 0) {
            result.push_back(static_cast<char>(std::toupper(ch)));
        }
    }
    return result;
}

[[nodiscard]] std::string NormalizeUser(std::string_view value)
{
    std::string result;
    result.reserve(value.size());
    for (const unsigned char ch : value) {
        result.push_back(static_cast<char>(std::tolower(ch)));
    }
    return result;
}

[[nodiscard]] bool MatchTimeWindow(const DeviceExceptionEntry& entry, const DeviceTimestamp when)
{
    if (!entry.startMinuteOfDay.has_value() || !entry.endMinuteOfDay.has_value()) {
        return entry.type != DeviceExceptionType::TimeWindow;
    }

    std::time_t currentTime = std::chrono::system_clock::to_time_t(when);
    std::tm localTime{};
    if (::localtime_s(&localTime, &currentTime) != 0) {
        return false;
    }

    const uint8_t dayMask = static_cast<uint8_t>(1U << static_cast<uint8_t>(localTime.tm_wday));
    if ((entry.daysOfWeekMask & dayMask) == 0U) {
        return false;
    }

    const uint16_t currentMinute = static_cast<uint16_t>((localTime.tm_hour * 60) + localTime.tm_min);
    const uint16_t startMinute = *entry.startMinuteOfDay;
    const uint16_t endMinute = *entry.endMinuteOfDay;

    if (startMinute <= endMinute) {
        return currentMinute >= startMinute && currentMinute <= endMinute;
    }

    return currentMinute >= startMinute || currentMinute <= endMinute;
}

[[nodiscard]] int MatchScore(
    const DeviceExceptionEntry& entry,
    const DeviceInfo& device,
    const std::string_view userName,
    const DeviceTimestamp when,
    std::string* matchReason)
{
    if (!entry.enabled) {
        return -1;
    }

    if (entry.validFrom.has_value() && when < *entry.validFrom) {
        return -1;
    }
    if (entry.validUntil.has_value() && when > *entry.validUntil) {
        return -1;
    }
    if (entry.deviceType != DeviceType::Unknown && entry.deviceType != device.type) {
        return -1;
    }

    int score = 0;
    if (entry.serialNumber.has_value()) {
        if (NormalizeSerial(*entry.serialNumber) != NormalizeSerial(device.serialNumber)) {
            return -1;
        }
        score += 100;
        if (matchReason != nullptr) {
            *matchReason = "serial-number";
        }
    }

    if (entry.userName.has_value()) {
        if (NormalizeUser(*entry.userName) != NormalizeUser(userName)) {
            return -1;
        }
        score += 50;
        if (matchReason != nullptr) {
            *matchReason = matchReason->empty() ? "user" : (*matchReason + "+user");
        }
    }

    if (entry.startMinuteOfDay.has_value() || entry.endMinuteOfDay.has_value() || entry.type == DeviceExceptionType::TimeWindow) {
        if (!MatchTimeWindow(entry, when)) {
            return -1;
        }
        score += 25;
        if (matchReason != nullptr) {
            *matchReason = matchReason->empty() ? "time-window" : (*matchReason + "+time-window");
        }
    }

    switch (entry.type) {
    case DeviceExceptionType::DeviceSerial:
        return entry.serialNumber.has_value() ? score + 10 : -1;
    case DeviceExceptionType::User:
        return entry.userName.has_value() ? score + 10 : -1;
    case DeviceExceptionType::TimeWindow:
        return (entry.startMinuteOfDay.has_value() && entry.endMinuteOfDay.has_value()) ? score + 10 : -1;
    default:
        break;
    }

    return score;
}

[[nodiscard]] std::string NullSafeString(const QueryResult& result, const int columnIndex)
{
    return result.IsNull(columnIndex) ? std::string{} : result.GetString(columnIndex);
}

[[nodiscard]] std::optional<int64_t> NullSafeInt64(const QueryResult& result, const int columnIndex)
{
    return result.IsNull(columnIndex) ? std::optional<int64_t>{} : std::optional<int64_t>{result.GetInt64(columnIndex)};
}

constexpr std::string_view kCreateExceptionsTableSql = R"(
    CREATE TABLE IF NOT EXISTS device_exceptions (
        exception_id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        type INTEGER NOT NULL,
        device_type INTEGER NOT NULL,
        enabled INTEGER NOT NULL,
        serial_normalized TEXT,
        user_normalized TEXT,
        start_minute INTEGER,
        end_minute INTEGER,
        days_mask INTEGER NOT NULL,
        valid_from INTEGER,
        valid_until INTEGER,
        override_action INTEGER NOT NULL,
        notes TEXT NOT NULL,
        updated_at INTEGER NOT NULL
    );
)";

constexpr std::string_view kCreateExceptionsIndexSql = R"(
    CREATE INDEX IF NOT EXISTS idx_device_exceptions_serial ON device_exceptions(serial_normalized);
    CREATE INDEX IF NOT EXISTS idx_device_exceptions_user ON device_exceptions(user_normalized);
    CREATE INDEX IF NOT EXISTS idx_device_exceptions_type_enabled ON device_exceptions(type, enabled);
)";

constexpr std::string_view kUpsertExceptionSql = R"(
    INSERT INTO device_exceptions (
        exception_id, name, type, device_type, enabled, serial_normalized, user_normalized,
        start_minute, end_minute, days_mask, valid_from, valid_until, override_action, notes, updated_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(exception_id) DO UPDATE SET
        name = excluded.name,
        type = excluded.type,
        device_type = excluded.device_type,
        enabled = excluded.enabled,
        serial_normalized = excluded.serial_normalized,
        user_normalized = excluded.user_normalized,
        start_minute = excluded.start_minute,
        end_minute = excluded.end_minute,
        days_mask = excluded.days_mask,
        valid_from = excluded.valid_from,
        valid_until = excluded.valid_until,
        override_action = excluded.override_action,
        notes = excluded.notes,
        updated_at = excluded.updated_at;
)";

constexpr std::string_view kDeleteExceptionSql = R"(
    DELETE FROM device_exceptions WHERE exception_id = ?;
)";

constexpr std::string_view kSelectExceptionSql = R"(
    SELECT exception_id, name, type, device_type, enabled, serial_normalized, user_normalized,
           start_minute, end_minute, days_mask, valid_from, valid_until, override_action, notes
      FROM device_exceptions
     WHERE exception_id = ?;
)";

constexpr std::string_view kSelectAllExceptionsSql = R"(
    SELECT exception_id, name, type, device_type, enabled, serial_normalized, user_normalized,
           start_minute, end_minute, days_mask, valid_from, valid_until, override_action, notes
      FROM device_exceptions
     WHERE enabled = 1
     ORDER BY updated_at DESC
     LIMIT 10000;
)";

} // namespace

class DeviceExceptionsImpl final {
public:
    [[nodiscard]] bool Initialize(const std::wstring& databasePath)
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
        if (!db.Execute(kCreateExceptionsTableSql, &dbError) || !db.Execute(kCreateExceptionsIndexSql, &dbError)) {
            LogDatabaseError("InitializeSchema", dbError);
            return false;
        }

        m_initialized = true;
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

    [[nodiscard]] bool UpsertException(const DeviceExceptionEntry& entry)
    {
        std::shared_lock lock(m_mutex);
        if (!m_initialized || entry.exceptionId.empty() || entry.name.empty()) {
            return false;
        }

        DatabaseError dbError;
        const auto validFrom = entry.validFrom.has_value() ? std::optional<int64_t>{ToUnixSeconds(*entry.validFrom)} : std::optional<int64_t>{};
        const auto validUntil = entry.validUntil.has_value() ? std::optional<int64_t>{ToUnixSeconds(*entry.validUntil)} : std::optional<int64_t>{};

        const bool success = DatabaseManager::Instance().ExecuteWithParams(
            kUpsertExceptionSql,
            &dbError,
            entry.exceptionId,
            entry.name,
            static_cast<int>(entry.type),
            static_cast<int>(entry.deviceType),
            entry.enabled ? 1 : 0,
            entry.serialNumber.has_value() ? NormalizeSerial(*entry.serialNumber) : std::string{},
            entry.userName.has_value() ? NormalizeUser(*entry.userName) : std::string{},
            entry.startMinuteOfDay.has_value() ? static_cast<int>(*entry.startMinuteOfDay) : -1,
            entry.endMinuteOfDay.has_value() ? static_cast<int>(*entry.endMinuteOfDay) : -1,
            static_cast<int>(entry.daysOfWeekMask),
            validFrom.value_or(0),
            validUntil.value_or(0),
            static_cast<int>(entry.overrideAction),
            entry.notes,
            ToUnixSeconds(std::chrono::system_clock::now()));

        if (!success) {
            LogDatabaseError("UpsertException", dbError);
            return false;
        }

        return true;
    }

    [[nodiscard]] bool RemoveException(std::string_view exceptionId)
    {
        std::shared_lock lock(m_mutex);
        if (!m_initialized || exceptionId.empty()) {
            return false;
        }

        DatabaseError dbError;
        if (!DatabaseManager::Instance().ExecuteWithParams(kDeleteExceptionSql, &dbError, std::string{exceptionId})) {
            LogDatabaseError("RemoveException", dbError);
            return false;
        }

        return DatabaseManager::Instance().GetChangedRowCount() > 0;
    }

    [[nodiscard]] std::optional<DeviceExceptionEntry> GetException(std::string_view exceptionId) const
    {
        std::shared_lock lock(m_mutex);
        if (!m_initialized || exceptionId.empty()) {
            return std::nullopt;
        }

        DatabaseError dbError;
        auto result = DatabaseManager::Instance().QueryWithParams(kSelectExceptionSql, &dbError, std::string{exceptionId});
        if (!result.Next()) {
            if (dbError.HasError()) {
                LogDatabaseError("GetException", dbError);
            }
            return std::nullopt;
        }

        return RowToEntry(result);
    }

    [[nodiscard]] std::vector<DeviceExceptionEntry> ListExceptions() const
    {
        std::shared_lock lock(m_mutex);
        std::vector<DeviceExceptionEntry> entries;
        if (!m_initialized) {
            return entries;
        }

        DatabaseError dbError;
        auto result = DatabaseManager::Instance().Query(kSelectAllExceptionsSql, &dbError);
        while (result.Next() && entries.size() < kMaxExceptionsReturned) {
            entries.push_back(RowToEntry(result));
        }

        if (dbError.HasError()) {
            LogDatabaseError("ListExceptions", dbError);
            entries.clear();
        }

        return entries;
    }

    [[nodiscard]] std::optional<DeviceExceptionMatch> MatchException(
        const DeviceInfo& device,
        std::string_view userName,
        const DeviceTimestamp when) const
    {
        const std::vector<DeviceExceptionEntry> entries = ListExceptions();
        int bestScore = -1;
        std::optional<DeviceExceptionMatch> bestMatch;

        for (const auto& entry : entries) {
            std::string reason;
            const int score = MatchScore(entry, device, userName, when, &reason);
            if (score <= bestScore) {
                continue;
            }

            bestScore = score;
            bestMatch = DeviceExceptionMatch{entry, entry.overrideAction, std::move(reason)};
        }

        return bestMatch;
    }

private:
    [[nodiscard]] static DeviceExceptionEntry RowToEntry(const QueryResult& result)
    {
        DeviceExceptionEntry entry;
        entry.exceptionId = result.GetString(0);
        entry.name = result.GetString(1);
        entry.type = static_cast<DeviceExceptionType>(result.GetInt(2));
        entry.deviceType = static_cast<DeviceType>(result.GetInt(3));
        entry.enabled = result.GetInt(4) != 0;

        const std::string serialValue = NullSafeString(result, 5);
        if (!serialValue.empty()) {
            entry.serialNumber = serialValue;
        }

        const std::string userValue = NullSafeString(result, 6);
        if (!userValue.empty()) {
            entry.userName = userValue;
        }

        if (!result.IsNull(7) && result.GetInt(7) >= 0) {
            entry.startMinuteOfDay = static_cast<uint16_t>(result.GetInt(7));
        }
        if (!result.IsNull(8) && result.GetInt(8) >= 0) {
            entry.endMinuteOfDay = static_cast<uint16_t>(result.GetInt(8));
        }

        entry.daysOfWeekMask = static_cast<uint8_t>(result.GetInt(9));

        const auto validFrom = NullSafeInt64(result, 10);
        if (validFrom.has_value() && *validFrom > 0) {
            entry.validFrom = FromUnixSeconds(*validFrom);
        }

        const auto validUntil = NullSafeInt64(result, 11);
        if (validUntil.has_value() && *validUntil > 0) {
            entry.validUntil = FromUnixSeconds(*validUntil);
        }

        entry.overrideAction = static_cast<DevicePolicyAction>(result.GetInt(12));
        entry.notes = NullSafeString(result, 13);
        return entry;
    }

    mutable std::shared_mutex m_mutex;
    bool m_initialized = false;
    std::wstring m_databasePath;
};

DeviceExceptions& DeviceExceptions::Instance()
{
    static DeviceExceptions instance;
    return instance;
}

DeviceExceptions::DeviceExceptions() : m_impl(std::make_unique<DeviceExceptionsImpl>()) {}
DeviceExceptions::~DeviceExceptions() = default;

bool DeviceExceptions::Initialize(const std::wstring& databasePath)
{
    return m_impl->Initialize(databasePath);
}

void DeviceExceptions::Shutdown()
{
    m_impl->Shutdown();
}

bool DeviceExceptions::IsInitialized() const
{
    return m_impl->IsInitialized();
}

bool DeviceExceptions::UpsertException(const DeviceExceptionEntry& entry)
{
    return m_impl->UpsertException(entry);
}

bool DeviceExceptions::RemoveException(std::string_view exceptionId)
{
    return m_impl->RemoveException(exceptionId);
}

std::optional<DeviceExceptionEntry> DeviceExceptions::GetException(std::string_view exceptionId) const
{
    return m_impl->GetException(exceptionId);
}

std::vector<DeviceExceptionEntry> DeviceExceptions::ListExceptions() const
{
    return m_impl->ListExceptions();
}

std::optional<DeviceExceptionMatch> DeviceExceptions::MatchException(
    const DeviceInfo& device,
    std::string_view userName,
    const DeviceTimestamp when) const
{
    return m_impl->MatchException(device, userName, when);
}

} // namespace ShadowStrike::Products::PhantomEDR::DeviceControl
