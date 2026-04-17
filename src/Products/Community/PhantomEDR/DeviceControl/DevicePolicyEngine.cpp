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
#include "Products/Community/PhantomEDR/DeviceControl/DevicePolicyEngine.hpp"

#include "PhantomCore/Database/DatabaseManager.hpp"
#include "PhantomCore/Utils/FileUtils.hpp"
#include "PhantomCore/Utils/Logger.hpp"
#include "PhantomCore/Utils/StringUtils.hpp"
#include "Products/Community/PhantomEDR/DeviceControl/DeviceAuditLog.hpp"
#include "Products/Community/PhantomEDR/DeviceControl/DeviceExceptions.hpp"

#include <SetupAPI.h>
#include <cfgmgr32.h>
#include <devguid.h>
#include <initguid.h>
#include <usbiodef.h>
#include <dbt.h>

#include <algorithm>
#include <atomic>
#include <cctype>
#include <filesystem>
#include <fstream>
#include <map>
#include <nlohmann/json.hpp>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

namespace ShadowStrike::Products::PhantomEDR::DeviceControl {

namespace {

using json = nlohmann::json;
using ShadowStrike::Database::DatabaseConfig;
using ShadowStrike::Database::DatabaseError;
using ShadowStrike::Database::DatabaseManager;
using ShadowStrike::Database::QueryResult;
using ShadowStrike::Utils::Logger;
namespace FileUtils = ShadowStrike::Utils::FileUtils;
namespace StringUtils = ShadowStrike::Utils::StringUtils;

constexpr std::string_view kLogPrefix = "[DevicePolicyEngine]";
constexpr uint32_t kConfigSchemaVersion = 1;
constexpr uint32_t kDefaultAuditRetentionDays = 90;
constexpr uint32_t kMaximumPolicyCount = 10000;
constexpr UINT kRefreshMessage = WM_APP + 0x230;
constexpr DWORD kConfigFlagDisabled = 0x00000001UL;

constexpr std::string_view kCreatePoliciesTableSql = R"(
    CREATE TABLE IF NOT EXISTS device_policies (
        policy_id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        description TEXT NOT NULL,
        device_type INTEGER NOT NULL,
        action INTEGER NOT NULL,
        enabled INTEGER NOT NULL,
        priority INTEGER NOT NULL,
        vendor_id TEXT,
        product_id TEXT,
        serial_normalized TEXT,
        description_pattern TEXT,
        manufacturer_pattern TEXT,
        user_normalized TEXT,
        updated_at INTEGER NOT NULL
    );
)";

constexpr std::string_view kCreatePoliciesIndexSql = R"(
    CREATE INDEX IF NOT EXISTS idx_device_policies_enabled_priority ON device_policies(enabled, priority);
    CREATE INDEX IF NOT EXISTS idx_device_policies_type_action ON device_policies(device_type, action);
)";

constexpr std::string_view kUpsertPolicySql = R"(
    INSERT INTO device_policies (
        policy_id, name, description, device_type, action, enabled, priority,
        vendor_id, product_id, serial_normalized, description_pattern, manufacturer_pattern,
        user_normalized, updated_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(policy_id) DO UPDATE SET
        name = excluded.name,
        description = excluded.description,
        device_type = excluded.device_type,
        action = excluded.action,
        enabled = excluded.enabled,
        priority = excluded.priority,
        vendor_id = excluded.vendor_id,
        product_id = excluded.product_id,
        serial_normalized = excluded.serial_normalized,
        description_pattern = excluded.description_pattern,
        manufacturer_pattern = excluded.manufacturer_pattern,
        user_normalized = excluded.user_normalized,
        updated_at = excluded.updated_at;
)";

constexpr std::string_view kDeletePolicySql = R"(
    DELETE FROM device_policies WHERE policy_id = ?;
)";

constexpr std::string_view kSelectPoliciesSql = R"(
    SELECT policy_id, name, description, device_type, action, enabled, priority,
           vendor_id, product_id, serial_normalized, description_pattern, manufacturer_pattern, user_normalized
      FROM device_policies
     ORDER BY priority ASC, updated_at DESC
     LIMIT 10000;
)";

[[nodiscard]] int64_t ToUnixSeconds(const DeviceTimestamp value) noexcept
{
    return std::chrono::duration_cast<std::chrono::seconds>(value.time_since_epoch()).count();
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

[[nodiscard]] std::wstring GetDeviceControlRoot()
{
    return GetProgramDataRoot() + L"\\ShadowStrike\\DeviceControl";
}

[[nodiscard]] std::wstring GetDefaultDatabasePath()
{
    return GetDeviceControlRoot() + L"\\device_control.db";
}

[[nodiscard]] std::wstring GetDefaultConfigPath()
{
    return GetDeviceControlRoot() + L"\\device_control_config.json";
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
    config.maxConnections = 6;
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

[[nodiscard]] std::string ToLowerAscii(std::string value)
{
    std::transform(
        value.begin(),
        value.end(),
        value.begin(),
        [](const unsigned char ch) { return static_cast<char>(std::tolower(ch)); });
    return value;
}

[[nodiscard]] bool ContainsInsensitive(std::string_view haystack, std::string_view needle)
{
    if (needle.empty()) {
        return true;
    }

    return ToLowerAscii(std::string{haystack}).find(ToLowerAscii(std::string{needle})) != std::string::npos;
}

[[nodiscard]] std::string ExtractToken(std::string_view source, std::string_view marker)
{
    const size_t pos = source.find(marker);
    if (pos == std::string_view::npos) {
        return {};
    }

    const size_t start = pos + marker.size();
    const size_t remaining = source.size() - start;
    if (remaining < 4U) {
        return {};
    }

    return ToLowerAscii(std::string{source.substr(start, 4)});
}

[[nodiscard]] std::wstring GetDeviceInstanceId(HDEVINFO deviceInfoSet, SP_DEVINFO_DATA& deviceInfoData)
{
    std::wstring buffer(MAX_DEVICE_ID_LEN, L'\0');
    if (::SetupDiGetDeviceInstanceIdW(
            deviceInfoSet,
            &deviceInfoData,
            buffer.data(),
            static_cast<DWORD>(buffer.size()),
            nullptr) == FALSE) {
        return {};
    }

    buffer.resize(std::wcslen(buffer.c_str()));
    return buffer;
}

[[nodiscard]] std::wstring GetRegistryProperty(HDEVINFO deviceInfoSet, SP_DEVINFO_DATA& deviceInfoData, const DWORD property)
{
    DWORD dataType = 0;
    DWORD requiredSize = 0;
    std::array<BYTE, 4096> buffer{};

    if (::SetupDiGetDeviceRegistryPropertyW(
            deviceInfoSet,
            &deviceInfoData,
            property,
            &dataType,
            buffer.data(),
            static_cast<DWORD>(buffer.size()),
            &requiredSize) == FALSE) {
        return {};
    }

    if (dataType == REG_MULTI_SZ) {
        const auto* multi = reinterpret_cast<const wchar_t*>(buffer.data());
        return std::wstring{multi};
    }

    const auto* stringData = reinterpret_cast<const wchar_t*>(buffer.data());
    return std::wstring{stringData};
}

[[nodiscard]] DWORD GetDwordProperty(HDEVINFO deviceInfoSet, SP_DEVINFO_DATA& deviceInfoData, const DWORD property)
{
    DWORD dataType = 0;
    DWORD value = 0;
    if (::SetupDiGetDeviceRegistryPropertyW(
            deviceInfoSet,
            &deviceInfoData,
            property,
            &dataType,
            reinterpret_cast<PBYTE>(&value),
            sizeof(value),
            nullptr) == FALSE) {
        return 0;
    }

    return dataType == REG_DWORD ? value : 0;
}

[[nodiscard]] std::string GetCurrentUserName()
{
    std::array<wchar_t, 256> buffer{};
    DWORD size = static_cast<DWORD>(buffer.size());
    if (::GetUserNameW(buffer.data(), &size) == FALSE || size == 0U) {
        return {};
    }

    return StringUtils::ToNarrow(buffer.data());
}

[[nodiscard]] std::string GetCurrentHostName()
{
    std::array<wchar_t, MAX_COMPUTERNAME_LENGTH + 1> buffer{};
    DWORD size = static_cast<DWORD>(buffer.size());
    if (::GetComputerNameW(buffer.data(), &size) == FALSE || size == 0U) {
        return {};
    }

    return StringUtils::ToNarrow(std::wstring_view{buffer.data(), size});
}

[[nodiscard]] DeviceType ClassifyDevice(const std::string& className, const std::string& hardwareId, const std::string& description)
{
    const std::string lowerClass = ToLowerAscii(className);
    const std::string upperHardware = ToLowerAscii(hardwareId);
    const std::string lowerDescription = ToLowerAscii(description);

    if (upperHardware.find("usbstor") != std::string::npos || lowerClass == "diskdrive") {
        return DeviceType::UsbMassStorage;
    }
    if (lowerClass == "hidclass") {
        return DeviceType::UsbHid;
    }
    if (lowerClass == "bluetooth" || upperHardware.starts_with("bth")) {
        return DeviceType::Bluetooth;
    }
    if (upperHardware.find("thunderbolt") != std::string::npos || lowerDescription.find("thunderbolt") != std::string::npos) {
        return DeviceType::Thunderbolt;
    }
    if (lowerClass == "net" && upperHardware.find("usb") != std::string::npos) {
        return DeviceType::UsbNetwork;
    }
    if (lowerClass == "printer" || upperHardware.find("usbprint") != std::string::npos) {
        return DeviceType::UsbPrinter;
    }
    if (lowerClass == "usb" && lowerDescription.find("hub") != std::string::npos) {
        return DeviceType::UsbHub;
    }
    if (lowerClass == "usb" && lowerDescription.find("composite") != std::string::npos) {
        return DeviceType::UsbComposite;
    }
    if (lowerClass == "image") {
        return DeviceType::Imaging;
    }
    if (lowerClass == "smartcardreader") {
        return DeviceType::SmartCard;
    }
    if (lowerClass == "media") {
        return DeviceType::AudioVideo;
    }
    if (lowerClass == "net" && (upperHardware.find("bth") != std::string::npos || lowerDescription.find("wireless") != std::string::npos)) {
        return DeviceType::WirelessAdapter;
    }
    if (upperHardware.find("usb") != std::string::npos) {
        return DeviceType::VendorSpecific;
    }

    return DeviceType::Unknown;
}

[[nodiscard]] bool IsManagedDeviceType(const DeviceType type) noexcept
{
    return type != DeviceType::Unknown;
}

[[nodiscard]] std::string NullSafeString(const QueryResult& result, const int columnIndex)
{
    return result.IsNull(columnIndex) ? std::string{} : result.GetString(columnIndex);
}

} // namespace

class DevicePolicyEngineImpl final {
public:
    [[nodiscard]] bool Initialize()
    {
        std::unique_lock lock(m_mutex);
        if (m_initialized) {
            return true;
        }

        if (!LoadOrCreateConfigLocked()) {
            return false;
        }

        DatabaseError dbError;
        if (!EnsureDatabaseReady(m_databasePath, &dbError)) {
            if (dbError.HasError()) {
                LogDatabaseError("Initialize", dbError);
            }
            return false;
        }

        auto& db = DatabaseManager::Instance();
        if (!db.Execute(kCreatePoliciesTableSql, &dbError) || !db.Execute(kCreatePoliciesIndexSql, &dbError)) {
            LogDatabaseError("InitializeSchema", dbError);
            return false;
        }

        if (!DeviceAuditLog::Instance().Initialize(m_databasePath, m_auditRetentionDays)) {
            Logger::Error("{} Failed to initialize DeviceAuditLog", kLogPrefix);
            return false;
        }

        if (!DeviceExceptions::Instance().Initialize(m_databasePath)) {
            Logger::Error("{} Failed to initialize DeviceExceptions", kLogPrefix);
            return false;
        }

        if (!ReloadPoliciesLocked()) {
            return false;
        }

        m_connectedDevices.clear();
        m_initialized = true;
        lock.unlock();

        (void)RefreshConnectedDevices();
        StartMonitoring();

        Logger::Info("{} Initialized databasePath={}", kLogPrefix, StringUtils::ToNarrow(m_databasePath));
        return true;
    }

    void Shutdown()
    {
        StopMonitoring();

        std::unique_lock lock(m_mutex);
        m_connectedDevices.clear();
        m_policies.clear();
        m_initialized = false;
        lock.unlock();

        DeviceExceptions::Instance().Shutdown();
        DeviceAuditLog::Instance().Shutdown();
    }

    [[nodiscard]] bool IsInitialized() const
    {
        std::shared_lock lock(m_mutex);
        return m_initialized;
    }

    [[nodiscard]] bool ReloadPolicies()
    {
        std::unique_lock lock(m_mutex);
        return ReloadPoliciesLocked();
    }

    [[nodiscard]] bool UpsertPolicy(DevicePolicy policy)
    {
        std::unique_lock lock(m_mutex);
        if (!m_initialized || policy.policyId.empty() || policy.name.empty()) {
            return false;
        }

        policy.vendorId = policy.vendorId.has_value() ? std::optional<std::string>{ToLowerAscii(*policy.vendorId)} : std::nullopt;
        policy.productId = policy.productId.has_value() ? std::optional<std::string>{ToLowerAscii(*policy.productId)} : std::nullopt;
        policy.serialNumber = policy.serialNumber.has_value() ? std::optional<std::string>{NormalizeSerial(*policy.serialNumber)} : std::nullopt;
        policy.userName = policy.userName.has_value() ? std::optional<std::string>{NormalizeUser(*policy.userName)} : std::nullopt;

        DatabaseError dbError;
        const bool success = DatabaseManager::Instance().ExecuteWithParams(
            kUpsertPolicySql,
            &dbError,
            policy.policyId,
            policy.name,
            policy.description,
            static_cast<int>(policy.deviceType),
            static_cast<int>(policy.action),
            policy.enabled ? 1 : 0,
            policy.priority,
            policy.vendorId.value_or(std::string{}),
            policy.productId.value_or(std::string{}),
            policy.serialNumber.value_or(std::string{}),
            policy.descriptionPattern.value_or(std::string{}),
            policy.manufacturerPattern.value_or(std::string{}),
            policy.userName.value_or(std::string{}),
            ToUnixSeconds(std::chrono::system_clock::now()));

        if (!success) {
            LogDatabaseError("UpsertPolicy", dbError);
            return false;
        }

        return ReloadPoliciesLocked();
    }

    [[nodiscard]] bool RemovePolicy(std::string_view policyId)
    {
        std::unique_lock lock(m_mutex);
        if (!m_initialized || policyId.empty()) {
            return false;
        }

        DatabaseError dbError;
        if (!DatabaseManager::Instance().ExecuteWithParams(kDeletePolicySql, &dbError, std::string{policyId})) {
            LogDatabaseError("RemovePolicy", dbError);
            return false;
        }

        return ReloadPoliciesLocked();
    }

    [[nodiscard]] std::vector<DevicePolicy> ListPolicies() const
    {
        std::shared_lock lock(m_mutex);
        return m_policies;
    }

    [[nodiscard]] DevicePolicyDecision EvaluateDevice(const DeviceInfo& device, std::string_view userName) const
    {
        DevicePolicyDecision decision;
        decision.action = m_defaultAction;
        decision.reason = "default-policy";

        const std::string normalizedUser = NormalizeUser(userName.empty() ? GetCurrentUserName() : std::string{userName});

        std::shared_lock lock(m_mutex);
        for (const auto& policy : m_policies) {
            if (!PolicyMatches(policy, device, normalizedUser)) {
                continue;
            }

            decision.action = policy.action;
            decision.matchedPolicyId = policy.policyId;
            decision.reason = policy.name.empty() ? "matched-policy" : policy.name;
            break;
        }
        lock.unlock();

        if (const auto exceptionMatch =
                DeviceExceptions::Instance().MatchException(device, normalizedUser, std::chrono::system_clock::now());
            exceptionMatch.has_value()) {
            decision.action = exceptionMatch->effectiveAction;
            decision.matchedExceptionId = exceptionMatch->exception.exceptionId;
            decision.reason = exceptionMatch->reason;
            decision.exceptionApplied = true;
        }

        return decision;
    }

    [[nodiscard]] bool HandleDeviceEvent(const DeviceEvent& event)
    {
        if (!IsInitialized()) {
            return false;
        }

        DeviceEvent auditEvent = event;
        auditEvent.timestamp = auditEvent.timestamp.time_since_epoch().count() == 0 ? std::chrono::system_clock::now() : auditEvent.timestamp;
        auditEvent.userName = auditEvent.userName.empty() ? GetCurrentUserName() : auditEvent.userName;
        auditEvent.hostName = auditEvent.hostName.empty() ? GetCurrentHostName() : auditEvent.hostName;

        const DevicePolicyDecision decision = EvaluateDevice(auditEvent.device, auditEvent.userName);
        auditEvent.actionTaken = decision.action;
        auditEvent.reason = decision.reason;

        bool enforcementApplied = false;
        if (event.eventKind == DeviceEventKind::Connected) {
            enforcementApplied = EnforceDecision(auditEvent.device, decision.action);
        }

        {
            std::unique_lock lock(m_mutex);
            if (event.eventKind == DeviceEventKind::Disconnected) {
                m_connectedDevices.erase(StringUtils::ToNarrow(auditEvent.device.instanceId));
            } else {
                m_connectedDevices[StringUtils::ToNarrow(auditEvent.device.instanceId)] = auditEvent.device;
            }
        }

        (void)enforcementApplied;
        return DeviceAuditLog::Instance().RecordEvent(auditEvent);
    }

    [[nodiscard]] bool RefreshConnectedDevices()
    {
        if (!IsInitialized()) {
            return false;
        }

        const std::vector<DeviceInfo> devices = EnumeratePresentDevices();
        std::unordered_map<std::string, DeviceInfo> current;
        current.reserve(devices.size());
        for (const auto& device : devices) {
            current.emplace(StringUtils::ToNarrow(device.instanceId), device);
        }

        std::vector<DeviceEvent> generatedEvents;
        {
            std::unique_lock lock(m_mutex);
            for (const auto& [key, device] : current) {
                if (!m_connectedDevices.contains(key)) {
                    DeviceEvent event;
                    event.timestamp = std::chrono::system_clock::now();
                    event.eventKind = DeviceEventKind::Connected;
                    event.device = device;
                    generatedEvents.push_back(std::move(event));
                }
            }

            for (const auto& [key, device] : m_connectedDevices) {
                if (!current.contains(key)) {
                    DeviceEvent event;
                    event.timestamp = std::chrono::system_clock::now();
                    event.eventKind = DeviceEventKind::Disconnected;
                    event.device = device;
                    generatedEvents.push_back(std::move(event));
                }
            }
        }

        for (const auto& event : generatedEvents) {
            (void)HandleDeviceEvent(event);
        }

        if (generatedEvents.empty()) {
            std::unique_lock lock(m_mutex);
            m_connectedDevices = std::move(current);
        }

        return true;
    }

    [[nodiscard]] std::vector<DeviceInfo> GetConnectedDevices() const
    {
        std::shared_lock lock(m_mutex);
        std::vector<DeviceInfo> devices;
        devices.reserve(m_connectedDevices.size());
        for (const auto& [_, device] : m_connectedDevices) {
            devices.push_back(device);
        }
        return devices;
    }

    [[nodiscard]] std::optional<DeviceInfo> GetConnectedDevice(std::string_view instanceId) const
    {
        std::shared_lock lock(m_mutex);
        const auto it = m_connectedDevices.find(std::string{instanceId});
        if (it == m_connectedDevices.end()) {
            return std::nullopt;
        }

        return it->second;
    }

private:
    struct LocalConfig final {
        std::wstring configPath = GetDefaultConfigPath();
        std::wstring databasePath = GetDefaultDatabasePath();
        DevicePolicyAction defaultAction = DevicePolicyAction::Allow;
        uint32_t auditRetentionDays = kDefaultAuditRetentionDays;
        bool enableLiveMonitoring = true;
    };

    [[nodiscard]] bool LoadOrCreateConfigLocked()
    {
        m_configPath = GetDefaultConfigPath();
        m_databasePath = GetDefaultDatabasePath();
        m_defaultAction = DevicePolicyAction::Allow;
        m_auditRetentionDays = kDefaultAuditRetentionDays;
        m_enableLiveMonitoring = true;

        FileUtils::Error fileErr;
        if (!FileUtils::CreateDirectories(GetDeviceControlRoot(), &fileErr)) {
            Logger::Error("{} Unable to create DeviceControl directory: {}", kLogPrefix, fileErr.message);
            return false;
        }

        const std::filesystem::path configPath{m_configPath};
        if (!std::filesystem::exists(configPath)) {
            return WriteConfigLocked();
        }

        try {
            std::ifstream stream(configPath, std::ios::binary);
            if (!stream.is_open()) {
                Logger::Error("{} Unable to open config file {}", kLogPrefix, StringUtils::ToNarrow(m_configPath));
                return false;
            }

            json document;
            stream >> document;
            m_databasePath = StringUtils::ToWide(document.value("databasePath", StringUtils::ToNarrow(m_databasePath)));
            m_auditRetentionDays = document.value("auditRetentionDays", kDefaultAuditRetentionDays);
            m_enableLiveMonitoring = document.value("enableLiveMonitoring", true);
            m_defaultAction = static_cast<DevicePolicyAction>(document.value("defaultAction", static_cast<int>(DevicePolicyAction::Allow)));
            return true;
        } catch (const std::exception& ex) {
            Logger::Error("{} Failed to parse config: {}", kLogPrefix, ex.what());
            return false;
        }
    }

    [[nodiscard]] bool WriteConfigLocked() const
    {
        try {
            json document;
            document["schemaVersion"] = kConfigSchemaVersion;
            document["databasePath"] = StringUtils::ToNarrow(m_databasePath);
            document["auditRetentionDays"] = m_auditRetentionDays;
            document["enableLiveMonitoring"] = m_enableLiveMonitoring;
            document["defaultAction"] = static_cast<int>(m_defaultAction);

            std::ofstream stream(std::filesystem::path{m_configPath}, std::ios::binary | std::ios::trunc);
            if (!stream.is_open()) {
                Logger::Error("{} Unable to write config file {}", kLogPrefix, StringUtils::ToNarrow(m_configPath));
                return false;
            }

            stream << document.dump(4);
            return true;
        } catch (const std::exception& ex) {
            Logger::Error("{} Failed to write config: {}", kLogPrefix, ex.what());
            return false;
        }
    }

    [[nodiscard]] bool ReloadPoliciesLocked()
    {
        DatabaseError dbError;
        auto result = DatabaseManager::Instance().Query(kSelectPoliciesSql, &dbError);
        std::vector<DevicePolicy> policies;
        while (result.Next() && policies.size() < kMaximumPolicyCount) {
            DevicePolicy policy;
            policy.policyId = result.GetString(0);
            policy.name = result.GetString(1);
            policy.description = result.GetString(2);
            policy.deviceType = static_cast<DeviceType>(result.GetInt(3));
            policy.action = static_cast<DevicePolicyAction>(result.GetInt(4));
            policy.enabled = result.GetInt(5) != 0;
            policy.priority = result.GetInt(6);

            const std::string vendorId = NullSafeString(result, 7);
            if (!vendorId.empty()) {
                policy.vendorId = vendorId;
            }
            const std::string productId = NullSafeString(result, 8);
            if (!productId.empty()) {
                policy.productId = productId;
            }
            const std::string serialNumber = NullSafeString(result, 9);
            if (!serialNumber.empty()) {
                policy.serialNumber = serialNumber;
            }
            const std::string descriptionPattern = NullSafeString(result, 10);
            if (!descriptionPattern.empty()) {
                policy.descriptionPattern = descriptionPattern;
            }
            const std::string manufacturerPattern = NullSafeString(result, 11);
            if (!manufacturerPattern.empty()) {
                policy.manufacturerPattern = manufacturerPattern;
            }
            const std::string userName = NullSafeString(result, 12);
            if (!userName.empty()) {
                policy.userName = userName;
            }

            policies.push_back(std::move(policy));
        }

        if (dbError.HasError()) {
            LogDatabaseError("ReloadPolicies", dbError);
            return false;
        }

        m_policies = std::move(policies);
        return true;
    }

    [[nodiscard]] static bool PolicyMatches(const DevicePolicy& policy, const DeviceInfo& device, std::string_view normalizedUser)
    {
        if (!policy.enabled) {
            return false;
        }
        if (policy.deviceType != DeviceType::Unknown && policy.deviceType != device.type) {
            return false;
        }
        if (policy.vendorId.has_value() && ToLowerAscii(device.vendorId) != *policy.vendorId) {
            return false;
        }
        if (policy.productId.has_value() && ToLowerAscii(device.productId) != *policy.productId) {
            return false;
        }
        if (policy.serialNumber.has_value() && NormalizeSerial(device.serialNumber) != *policy.serialNumber) {
            return false;
        }
        if (policy.descriptionPattern.has_value() && !ContainsInsensitive(device.description, *policy.descriptionPattern)) {
            return false;
        }
        if (policy.manufacturerPattern.has_value() && !ContainsInsensitive(device.manufacturer, *policy.manufacturerPattern)) {
            return false;
        }
        if (policy.userName.has_value() && normalizedUser != *policy.userName) {
            return false;
        }

        return true;
    }

    [[nodiscard]] std::vector<DeviceInfo> EnumeratePresentDevices() const
    {
        std::vector<DeviceInfo> devices;

        const HDEVINFO deviceInfoSet = ::SetupDiGetClassDevsW(nullptr, nullptr, nullptr, DIGCF_ALLCLASSES | DIGCF_PRESENT);
        if (deviceInfoSet == INVALID_HANDLE_VALUE) {
            Logger::Error("{} SetupDiGetClassDevsW failed lastError={}", kLogPrefix, ::GetLastError());
            return devices;
        }

        SP_DEVINFO_DATA deviceInfoData{};
        deviceInfoData.cbSize = sizeof(deviceInfoData);

        for (DWORD index = 0; ::SetupDiEnumDeviceInfo(deviceInfoSet, index, &deviceInfoData) != FALSE; ++index) {
            DeviceInfo device;
            device.instanceId = GetDeviceInstanceId(deviceInfoSet, deviceInfoData);
            if (device.instanceId.empty()) {
                continue;
            }

            const std::wstring className = GetRegistryProperty(deviceInfoSet, deviceInfoData, SPDRP_CLASS);
            const std::wstring description = [&]() -> std::wstring {
                const std::wstring friendly = GetRegistryProperty(deviceInfoSet, deviceInfoData, SPDRP_FRIENDLYNAME);
                return friendly.empty() ? GetRegistryProperty(deviceInfoSet, deviceInfoData, SPDRP_DEVICEDESC) : friendly;
            }();
            const std::wstring manufacturer = GetRegistryProperty(deviceInfoSet, deviceInfoData, SPDRP_MFG);
            const std::wstring hardwareId = GetRegistryProperty(deviceInfoSet, deviceInfoData, SPDRP_HARDWAREID);
            const DWORD capabilities = GetDwordProperty(deviceInfoSet, deviceInfoData, SPDRP_CAPABILITIES);

            device.className = StringUtils::ToNarrow(className);
            device.description = StringUtils::ToNarrow(description);
            device.manufacturer = StringUtils::ToNarrow(manufacturer);
            device.hardwareId = StringUtils::ToNarrow(hardwareId);
            device.removable = (capabilities & CM_DEVCAP_REMOVABLE) != 0U;
            device.usbBus = ContainsInsensitive(StringUtils::ToNarrow(device.instanceId), "USB\\")
                || ContainsInsensitive(device.hardwareId, "USB");
            device.bluetoothBus = ContainsInsensitive(StringUtils::ToNarrow(device.instanceId), "BTH")
                || ContainsInsensitive(device.className, "bluetooth");
            device.thunderboltBus = ContainsInsensitive(device.description, "thunderbolt")
                || ContainsInsensitive(device.hardwareId, "thunderbolt");
            device.vendorId = ExtractToken(ToLowerAscii(device.hardwareId), "vid_");
            device.productId = ExtractToken(ToLowerAscii(device.hardwareId), "pid_");

            const std::wstring instanceString = device.instanceId;
            const std::wstring::size_type serialSep = instanceString.rfind(L'\\');
            if (serialSep != std::wstring::npos && serialSep + 1U < instanceString.size()) {
                device.serialNumber = NormalizeSerial(StringUtils::ToNarrow(instanceString.substr(serialSep + 1U)));
            }

            device.type = ClassifyDevice(device.className, device.hardwareId, device.description);
            if (!IsManagedDeviceType(device.type)) {
                continue;
            }

            devices.push_back(std::move(device));
        }

        ::SetupDiDestroyDeviceInfoList(deviceInfoSet);
        return devices;
    }

    [[nodiscard]] bool ApplyReadOnly(const DeviceInfo& device) const
    {
        if (device.type != DeviceType::UsbMassStorage) {
            return true;
        }

        HKEY key = nullptr;
        const LONG status = ::RegCreateKeyExW(
            HKEY_LOCAL_MACHINE,
            L"SYSTEM\\CurrentControlSet\\Control\\StorageDevicePolicies",
            0,
            nullptr,
            REG_OPTION_NON_VOLATILE,
            KEY_SET_VALUE,
            nullptr,
            &key,
            nullptr);
        if (status != ERROR_SUCCESS) {
            Logger::Warn("{} Failed to open StorageDevicePolicies status={}", kLogPrefix, status);
            return false;
        }

        const DWORD writeProtect = 1;
        const LONG setStatus = ::RegSetValueExW(
            key,
            L"WriteProtect",
            0,
            REG_DWORD,
            reinterpret_cast<const BYTE*>(&writeProtect),
            sizeof(writeProtect));
        ::RegCloseKey(key);
        if (setStatus != ERROR_SUCCESS) {
            Logger::Warn("{} Failed to enforce read-only status={}", kLogPrefix, setStatus);
            return false;
        }

        return true;
    }

    [[nodiscard]] bool ApplyBlock(const DeviceInfo& device) const
    {
        if (device.instanceId.empty()) {
            return false;
        }

        const HDEVINFO deviceInfoSet = ::SetupDiGetClassDevsW(nullptr, nullptr, nullptr, DIGCF_ALLCLASSES | DIGCF_PRESENT);
        if (deviceInfoSet == INVALID_HANDLE_VALUE) {
            Logger::Warn("{} SetupDiGetClassDevsW failed during block lastError={}", kLogPrefix, ::GetLastError());
            return false;
        }

        bool success = false;
        SP_DEVINFO_DATA deviceInfoData{};
        deviceInfoData.cbSize = sizeof(deviceInfoData);
        for (DWORD index = 0; ::SetupDiEnumDeviceInfo(deviceInfoSet, index, &deviceInfoData) != FALSE; ++index) {
            if (GetDeviceInstanceId(deviceInfoSet, deviceInfoData) != device.instanceId) {
                continue;
            }

            DWORD configFlags = GetDwordProperty(deviceInfoSet, deviceInfoData, SPDRP_CONFIGFLAGS);
            configFlags |= kConfigFlagDisabled;
            (void)::SetupDiSetDeviceRegistryPropertyW(
                deviceInfoSet,
                &deviceInfoData,
                SPDRP_CONFIGFLAGS,
                reinterpret_cast<const BYTE*>(&configFlags),
                sizeof(configFlags));

            SP_PROPCHANGE_PARAMS params{};
            params.ClassInstallHeader.cbSize = sizeof(SP_CLASSINSTALL_HEADER);
            params.ClassInstallHeader.InstallFunction = DIF_PROPERTYCHANGE;
            params.StateChange = DICS_DISABLE;
            params.Scope = DICS_FLAG_GLOBAL;
            params.HwProfile = 0;

            if (::SetupDiSetClassInstallParamsW(
                    deviceInfoSet,
                    &deviceInfoData,
                    &params.ClassInstallHeader,
                    sizeof(params)) != FALSE
                && ::SetupDiCallClassInstaller(DIF_PROPERTYCHANGE, deviceInfoSet, &deviceInfoData) != FALSE) {
                success = true;
            }
            break;
        }

        ::SetupDiDestroyDeviceInfoList(deviceInfoSet);
        if (!success) {
            Logger::Warn("{} Failed to disable device instance={}", kLogPrefix, StringUtils::ToNarrow(device.instanceId));
        }

        return success;
    }

    [[nodiscard]] bool EnforceDecision(const DeviceInfo& device, const DevicePolicyAction action) const
    {
        switch (action) {
        case DevicePolicyAction::Allow:
        case DevicePolicyAction::AuditOnly:
            return true;
        case DevicePolicyAction::ReadOnly:
            return ApplyReadOnly(device);
        case DevicePolicyAction::Block:
            return ApplyBlock(device);
        default:
            return false;
        }
    }

    void StartMonitoring()
    {
        if (!m_enableLiveMonitoring || m_monitorThread.joinable()) {
            return;
        }

        m_monitorThread = std::jthread([this](std::stop_token stopToken) { MonitorLoop(stopToken); });
    }

    void StopMonitoring()
    {
        if (!m_monitorThread.joinable()) {
            return;
        }

        if (m_windowHandle != nullptr) {
            ::PostMessageW(m_windowHandle, WM_CLOSE, 0, 0);
        }
        m_monitorThread.request_stop();
        m_monitorThread.join();
        m_windowHandle = nullptr;
        m_cfgNotification = nullptr;
    }

    void MonitorLoop(const std::stop_token stopToken)
    {
        m_windowClassName = L"ShadowStrikeDevicePolicyEngineWindow";

        WNDCLASSW windowClass{};
        windowClass.lpfnWndProc = &DevicePolicyEngineImpl::WindowProc;
        windowClass.hInstance = ::GetModuleHandleW(nullptr);
        windowClass.lpszClassName = m_windowClassName.c_str();
        (void)::RegisterClassW(&windowClass);

        m_windowHandle = ::CreateWindowExW(
            0,
            m_windowClassName.c_str(),
            L"ShadowStrikeDevicePolicyEngine",
            WS_OVERLAPPED,
            0,
            0,
            0,
            0,
            nullptr,
            nullptr,
            ::GetModuleHandleW(nullptr),
            this);

        RegisterCfgMgrNotification();

        MSG message{};
        while (!stopToken.stop_requested() && ::GetMessageW(&message, nullptr, 0, 0) > 0) {
            ::TranslateMessage(&message);
            ::DispatchMessageW(&message);
        }

        if (m_cfgNotification != nullptr) {
            (void)::CM_Unregister_Notification(m_cfgNotification);
            m_cfgNotification = nullptr;
        }
        if (m_windowHandle != nullptr) {
            ::DestroyWindow(m_windowHandle);
            m_windowHandle = nullptr;
        }
        (void)::UnregisterClassW(m_windowClassName.c_str(), ::GetModuleHandleW(nullptr));
    }

    void RegisterCfgMgrNotification()
    {
        CM_NOTIFY_FILTER filter{};
        filter.cbSize = sizeof(filter);
        filter.Flags = CM_NOTIFY_FILTER_FLAG_ALL_INTERFACE_CLASSES;
        filter.FilterType = CM_NOTIFY_FILTER_TYPE_DEVICEINTERFACE;
        filter.u.DeviceInterface.ClassGuid = GUID_DEVINTERFACE_USB_DEVICE;

        if (::CM_Register_Notification(
                &filter,
                this,
                &DevicePolicyEngineImpl::CfgMgrNotificationCallback,
                &m_cfgNotification) != CR_SUCCESS) {
            Logger::Warn("{} CM_Register_Notification failed, relying on WM_DEVICECHANGE fallback", kLogPrefix);
        }
    }

    void QueueRefresh()
    {
        if (m_windowHandle != nullptr) {
            (void)::PostMessageW(m_windowHandle, kRefreshMessage, 0, 0);
        }
    }

    static LRESULT CALLBACK WindowProc(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam)
    {
        if (message == WM_CREATE) {
            const auto* createStruct = reinterpret_cast<const CREATESTRUCTW*>(lParam);
            ::SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(createStruct->lpCreateParams));
            return 0;
        }

        auto* self = reinterpret_cast<DevicePolicyEngineImpl*>(::GetWindowLongPtrW(hwnd, GWLP_USERDATA));
        if (self == nullptr) {
            return ::DefWindowProcW(hwnd, message, wParam, lParam);
        }

        switch (message) {
        case WM_DEVICECHANGE:
            if (wParam == DBT_DEVICEARRIVAL || wParam == DBT_DEVICEREMOVECOMPLETE || wParam == DBT_DEVNODES_CHANGED) {
                self->QueueRefresh();
            }
            return 0;
        case kRefreshMessage:
            (void)self->RefreshConnectedDevices();
            return 0;
        case WM_CLOSE:
            ::PostQuitMessage(0);
            return 0;
        default:
            return ::DefWindowProcW(hwnd, message, wParam, lParam);
        }
    }

    static DWORD CALLBACK CfgMgrNotificationCallback(
        HCMNOTIFICATION,
        PVOID context,
        CM_NOTIFY_ACTION action,
        PCM_NOTIFY_EVENT_DATA,
        DWORD)
    {
        auto* self = static_cast<DevicePolicyEngineImpl*>(context);
        if (self == nullptr) {
            return ERROR_INVALID_PARAMETER;
        }

        switch (action) {
        case CM_NOTIFY_ACTION_DEVICEINTERFACEARRIVAL:
        case CM_NOTIFY_ACTION_DEVICEINTERFACEREMOVAL:
        case CM_NOTIFY_ACTION_DEVICEINSTANCESTARTED:
        case CM_NOTIFY_ACTION_DEVICEINSTANCEREMOVED:
            self->QueueRefresh();
            break;
        default:
            break;
        }

        return ERROR_SUCCESS;
    }

    mutable std::shared_mutex m_mutex;
    bool m_initialized = false;
    std::wstring m_configPath;
    std::wstring m_databasePath;
    DevicePolicyAction m_defaultAction = DevicePolicyAction::Allow;
    uint32_t m_auditRetentionDays = kDefaultAuditRetentionDays;
    bool m_enableLiveMonitoring = true;
    std::vector<DevicePolicy> m_policies;
    std::unordered_map<std::string, DeviceInfo> m_connectedDevices;
    std::jthread m_monitorThread;
    std::wstring m_windowClassName;
    HWND m_windowHandle = nullptr;
    HCMNOTIFICATION m_cfgNotification = nullptr;
};

DevicePolicyEngine& DevicePolicyEngine::Instance()
{
    static DevicePolicyEngine instance;
    return instance;
}

DevicePolicyEngine::DevicePolicyEngine() : m_impl(std::make_unique<DevicePolicyEngineImpl>()) {}
DevicePolicyEngine::~DevicePolicyEngine() = default;

bool DevicePolicyEngine::Initialize()
{
    return m_impl->Initialize();
}

void DevicePolicyEngine::Shutdown()
{
    m_impl->Shutdown();
}

bool DevicePolicyEngine::IsInitialized() const
{
    return m_impl->IsInitialized();
}

bool DevicePolicyEngine::ReloadPolicies()
{
    return m_impl->ReloadPolicies();
}

bool DevicePolicyEngine::UpsertPolicy(const DevicePolicy& policy)
{
    return m_impl->UpsertPolicy(policy);
}

bool DevicePolicyEngine::RemovePolicy(std::string_view policyId)
{
    return m_impl->RemovePolicy(policyId);
}

std::vector<DevicePolicy> DevicePolicyEngine::ListPolicies() const
{
    return m_impl->ListPolicies();
}

DevicePolicyDecision DevicePolicyEngine::EvaluateDevice(const DeviceInfo& device, std::string_view userName) const
{
    return m_impl->EvaluateDevice(device, userName);
}

bool DevicePolicyEngine::HandleDeviceEvent(const DeviceEvent& event)
{
    return m_impl->HandleDeviceEvent(event);
}

bool DevicePolicyEngine::RefreshConnectedDevices()
{
    return m_impl->RefreshConnectedDevices();
}

std::vector<DeviceInfo> DevicePolicyEngine::GetConnectedDevices() const
{
    return m_impl->GetConnectedDevices();
}

std::optional<DeviceInfo> DevicePolicyEngine::GetConnectedDevice(std::string_view instanceId) const
{
    return m_impl->GetConnectedDevice(instanceId);
}

} // namespace ShadowStrike::Products::PhantomEDR::DeviceControl
