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
#include "Products/Community/PhantomEDR/AssetInventory/AssetDatabase.hpp"

#include "PhantomCore/Database/DatabaseManager.hpp"
#include "PhantomCore/Utils/Logger.hpp"
#include "PhantomCore/Utils/StringUtils.hpp"
#include "Products/Community/PhantomEDR/AssetInventory/SoftwareInventory.hpp"

#include <filesystem>
#include <unordered_set>

namespace ShadowStrike::Products::PhantomEDR::AssetInventory {

namespace {

using ShadowStrike::Database::DatabaseConfig;
using ShadowStrike::Database::DatabaseError;
using ShadowStrike::Database::DatabaseManager;
using ShadowStrike::Database::QueryResult;
using ShadowStrike::Utils::Logger;
namespace StringUtils = ShadowStrike::Utils::StringUtils;

constexpr const char* kLogPrefix = "[AssetDatabase]";

[[nodiscard]] int64_t CurrentUnixTime() noexcept {
    return std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}

[[nodiscard]] std::wstring GetEnvironmentValue(const wchar_t* name) {
    const DWORD required = ::GetEnvironmentVariableW(name, nullptr, 0);
    if (required == 0) {
        return {};
    }

    std::wstring value(static_cast<size_t>(required), L'\0');
    const DWORD written = ::GetEnvironmentVariableW(name, value.data(), required);
    if (written == 0) {
        return {};
    }

    value.resize(static_cast<size_t>(written));
    return value;
}

[[nodiscard]] std::wstring BuildDefaultDatabasePath() {
    std::wstring baseDirectory = GetEnvironmentValue(L"ProgramData");
    if (baseDirectory.empty()) {
        baseDirectory = GetEnvironmentValue(L"LOCALAPPDATA");
    }
    if (baseDirectory.empty()) {
        baseDirectory = std::filesystem::current_path().wstring();
    }

    std::filesystem::path directory(baseDirectory);
    directory /= L"ShadowStrike";
    directory /= L"PhantomEDR";

    std::error_code ec;
    std::filesystem::create_directories(directory, ec);
    if (ec) {
        Logger::Warn("{} failed to create storage directory, falling back to working directory", kLogPrefix);
        directory = std::filesystem::current_path();
    }

    directory /= L"asset_inventory.db";
    return directory.wstring();
}

[[nodiscard]] std::string Narrow(std::wstring_view value) {
    return StringUtils::ToNarrow(value);
}

[[nodiscard]] std::wstring Wide(std::string_view value) {
    return StringUtils::ToWide(value);
}

[[nodiscard]] std::wstring Trimmed(std::wstring value) {
    StringUtils::Trim(value);
    return value;
}

[[nodiscard]] std::wstring JoinWide(const std::vector<std::wstring>& values) {
    return StringUtils::Join(values, L";");
}

[[nodiscard]] std::vector<std::wstring> SplitWide(std::wstring_view value) {
    if (value.empty()) {
        return {};
    }

    auto parts = StringUtils::Split(value, L";");
    for (auto& part : parts) {
        StringUtils::Trim(part);
    }
    parts.erase(std::remove_if(parts.begin(), parts.end(), [](const std::wstring& item) {
        return item.empty();
    }), parts.end());
    return parts;
}

[[nodiscard]] std::string NormalizeLookupValue(std::string_view value) {
    std::wstring wide = Wide(value);
    wide = StringUtils::ToLowerCopy(wide);
    return Narrow(wide);
}

[[nodiscard]] std::string MakeAdapterKey(const NetworkAdapterInfo& adapter) {
    if (!adapter.adapterId.empty()) {
        return Narrow(StringUtils::ToLowerCopy(adapter.adapterId));
    }
    if (!adapter.macAddress.empty()) {
        return Narrow(StringUtils::ToLowerCopy(adapter.macAddress));
    }
    return Narrow(StringUtils::ToLowerCopy(adapter.friendlyName));
}

[[nodiscard]] std::string MakeUserKey(const LocalUserInfo& user) {
    if (!user.sid.empty()) {
        return Narrow(StringUtils::ToLowerCopy(user.sid));
    }
    return Narrow(StringUtils::ToLowerCopy(user.accountName));
}

[[nodiscard]] std::string MakePatchKey(const PatchInfo& patch) {
    if (!patch.hotfixId.empty()) {
        return Narrow(StringUtils::ToLowerCopy(patch.hotfixId));
    }

    return Narrow(StringUtils::ToLowerCopy(patch.description));
}

[[nodiscard]] bool LogDatabaseFailure(std::string_view operation, const DatabaseError& error) {
    Logger::Error("{} {} failed: sqlite={} context={} message={}",
        kLogPrefix,
        operation,
        error.sqliteCode,
        Narrow(error.context),
        Narrow(error.message));
    return false;
}

[[nodiscard]] bool ExecuteOrLog(
    DatabaseManager& db,
    std::string_view sql,
    DatabaseError& error,
    std::string_view operation) {
    if (db.Execute(sql, &error)) {
        return true;
    }

    return LogDatabaseFailure(operation, error);
}

[[nodiscard]] int64_t GetCurrentAssetVersion(DatabaseManager& db, std::string_view assetId, DatabaseError& error) {
    auto result = db.QueryWithParams(
        "SELECT COALESCE(MAX(version), 0) FROM assets WHERE asset_id = ?",
        &error,
        std::string(assetId));

    if (error.HasError()) {
        return 0;
    }

    if (result.Next()) {
        return result.GetInt64(0);
    }

    return 0;
}

[[nodiscard]] std::optional<int64_t> GetCurrentSnapshotVersion(
    DatabaseManager& db,
    std::string_view tableName,
    std::string_view assetId,
    DatabaseError& error) {
    const std::string sql = "SELECT snapshot_version FROM " + std::string(tableName) +
        " WHERE asset_id = ? AND is_current = 1 LIMIT 1";

    auto result = db.QueryWithParams(sql, &error, std::string(assetId));
    if (error.HasError()) {
        return std::nullopt;
    }

    if (result.Next()) {
        return result.GetInt64(0);
    }

    return std::nullopt;
}

void PopulateAssetCoreFromRow(QueryResult& result, AssetRecord& record) {
    record.assetId = result.GetString("asset_id");
    record.computerName = result.GetWString("computer_name");
    record.fullyQualifiedDomainName = result.GetWString("fqdn");
    record.domainName = result.GetWString("domain_name");
    record.currentUser = result.GetWString("current_user");
    record.osName = result.GetWString("os_name");
    record.osVersion = result.GetWString("os_version");
    record.osBuild = result.GetWString("os_build");
    record.osArchitecture = result.GetWString("os_architecture");
    record.osInstallDate = result.GetWString("os_install_date");
    record.discoveredAtUnixSeconds = result.GetInt64("discovered_at");
    record.uptimeSeconds = result.GetInt64("uptime_seconds");
}

void PopulateHardwareFromRow(QueryResult& result, HardwareInventory& hardware) {
    hardware.manufacturer = result.GetWString("manufacturer");
    hardware.model = result.GetWString("model");
    hardware.systemFamily = result.GetWString("system_family");
    hardware.systemSku = result.GetWString("system_sku");
    hardware.biosVersion = result.GetWString("bios_version");
    hardware.cpuName = result.GetWString("cpu_name");
    hardware.cpuVendor = result.GetWString("cpu_vendor");
    hardware.cpuArchitecture = result.GetWString("cpu_architecture");
    hardware.processorIdentifier = result.GetWString("processor_identifier");
    hardware.physicalCoreCount = static_cast<uint32_t>(result.GetInt("physical_core_count"));
    hardware.logicalProcessorCount = static_cast<uint32_t>(result.GetInt("logical_processor_count"));
    hardware.processorCount = static_cast<uint32_t>(result.GetInt("processor_count"));
    hardware.memoryModuleCount = static_cast<uint32_t>(result.GetInt("memory_module_count"));
    hardware.diskCount = static_cast<uint32_t>(result.GetInt("disk_count"));
    hardware.totalMemoryBytes = static_cast<uint64_t>(result.GetInt64("total_memory_bytes"));
    hardware.totalStorageBytes = static_cast<uint64_t>(result.GetInt64("total_storage_bytes"));
    hardware.systemDriveTotalBytes = static_cast<uint64_t>(result.GetInt64("system_drive_total_bytes"));
    hardware.systemDriveFreeBytes = static_cast<uint64_t>(result.GetInt64("system_drive_free_bytes"));
}

} // namespace

class AssetDatabaseImpl final {
public:
    std::atomic<bool> initialized{ false };
    mutable std::shared_mutex mutex;
    bool ownsDatabaseManager = false;
    std::wstring databasePath;
};

AssetDatabase& AssetDatabase::Instance() {
    static AssetDatabase instance;
    return instance;
}

AssetDatabase::AssetDatabase()
    : m_impl(std::make_unique<AssetDatabaseImpl>()) {
}

AssetDatabase::~AssetDatabase() = default;

bool AssetDatabase::Initialize() {
    if (m_impl->initialized.load(std::memory_order_acquire)) {
        return true;
    }

    std::unique_lock lock(m_impl->mutex);
    if (m_impl->initialized.load(std::memory_order_relaxed)) {
        return true;
    }

    auto& db = DatabaseManager::Instance();
    DatabaseError error{};

    if (!db.IsInitialized()) {
        DatabaseConfig config{};
        config.databasePath = BuildDefaultDatabasePath();
        config.autoBackup = false;
        config.maxConnections = 4;
        config.minConnections = 1;
        config.cacheSizeKB = 4096;

        if (!db.Initialize(config, &error)) {
            return LogDatabaseFailure("Initialize(DatabaseManager)", error);
        }

        m_impl->ownsDatabaseManager = true;
        m_impl->databasePath = config.databasePath;
    } else {
        m_impl->databasePath.clear();
    }

    static constexpr std::string_view kSchema = R"SQL(
        CREATE TABLE IF NOT EXISTS assets (
            asset_id TEXT NOT NULL,
            version INTEGER NOT NULL,
            is_current INTEGER NOT NULL DEFAULT 1,
            discovered_at INTEGER NOT NULL,
            computer_name TEXT NOT NULL,
            fqdn TEXT,
            domain_name TEXT,
            current_user TEXT,
            os_name TEXT,
            os_version TEXT,
            os_build TEXT,
            os_architecture TEXT,
            os_install_date TEXT,
            uptime_seconds INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY (asset_id, version)
        );

        CREATE INDEX IF NOT EXISTS idx_assets_current_asset
            ON assets(asset_id, is_current, discovered_at DESC);
        CREATE INDEX IF NOT EXISTS idx_assets_hostname
            ON assets(computer_name, is_current);
        CREATE INDEX IF NOT EXISTS idx_assets_domain
            ON assets(domain_name, is_current);
        CREATE INDEX IF NOT EXISTS idx_assets_os
            ON assets(os_name, os_build, is_current);

        CREATE TABLE IF NOT EXISTS hardware_info (
            asset_id TEXT NOT NULL,
            snapshot_version INTEGER NOT NULL,
            is_current INTEGER NOT NULL DEFAULT 1,
            discovered_at INTEGER NOT NULL,
            manufacturer TEXT,
            model TEXT,
            system_family TEXT,
            system_sku TEXT,
            bios_version TEXT,
            cpu_name TEXT,
            cpu_vendor TEXT,
            cpu_architecture TEXT,
            processor_identifier TEXT,
            physical_core_count INTEGER NOT NULL DEFAULT 0,
            logical_processor_count INTEGER NOT NULL DEFAULT 0,
            processor_count INTEGER NOT NULL DEFAULT 0,
            memory_module_count INTEGER NOT NULL DEFAULT 0,
            disk_count INTEGER NOT NULL DEFAULT 0,
            total_memory_bytes INTEGER NOT NULL DEFAULT 0,
            total_storage_bytes INTEGER NOT NULL DEFAULT 0,
            system_drive_total_bytes INTEGER NOT NULL DEFAULT 0,
            system_drive_free_bytes INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY (asset_id, snapshot_version),
            FOREIGN KEY (asset_id, snapshot_version)
                REFERENCES assets(asset_id, version) ON DELETE CASCADE
        );

        CREATE INDEX IF NOT EXISTS idx_hardware_current
            ON hardware_info(asset_id, is_current);

        CREATE TABLE IF NOT EXISTS disk_volumes (
            asset_id TEXT NOT NULL,
            snapshot_version INTEGER NOT NULL,
            volume_key TEXT NOT NULL,
            is_current INTEGER NOT NULL DEFAULT 1,
            root_path TEXT NOT NULL,
            volume_label TEXT,
            file_system TEXT,
            drive_type INTEGER NOT NULL DEFAULT 0,
            total_bytes INTEGER NOT NULL DEFAULT 0,
            free_bytes INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY (asset_id, snapshot_version, volume_key),
            FOREIGN KEY (asset_id, snapshot_version)
                REFERENCES assets(asset_id, version) ON DELETE CASCADE
        );

        CREATE INDEX IF NOT EXISTS idx_disk_volumes_current
            ON disk_volumes(asset_id, is_current);

        CREATE TABLE IF NOT EXISTS network_adapters (
            asset_id TEXT NOT NULL,
            snapshot_version INTEGER NOT NULL,
            adapter_key TEXT NOT NULL,
            is_current INTEGER NOT NULL DEFAULT 1,
            discovered_at INTEGER NOT NULL,
            adapter_id TEXT,
            friendly_name TEXT,
            description TEXT,
            dns_suffix TEXT,
            mac_address TEXT,
            interface_type INTEGER NOT NULL DEFAULT 0,
            operational_status INTEGER NOT NULL DEFAULT 0,
            mtu INTEGER NOT NULL DEFAULT 0,
            link_speed_bps INTEGER NOT NULL DEFAULT 0,
            dhcp_enabled INTEGER NOT NULL DEFAULT 0,
            ipv4_enabled INTEGER NOT NULL DEFAULT 0,
            ipv6_enabled INTEGER NOT NULL DEFAULT 0,
            ipv4_addresses TEXT,
            ipv6_addresses TEXT,
            gateways TEXT,
            dns_servers TEXT,
            PRIMARY KEY (asset_id, snapshot_version, adapter_key),
            FOREIGN KEY (asset_id, snapshot_version)
                REFERENCES assets(asset_id, version) ON DELETE CASCADE
        );

        CREATE INDEX IF NOT EXISTS idx_network_current
            ON network_adapters(asset_id, is_current);
        CREATE INDEX IF NOT EXISTS idx_network_mac
            ON network_adapters(mac_address, is_current);

        CREATE TABLE IF NOT EXISTS local_users (
            asset_id TEXT NOT NULL,
            snapshot_version INTEGER NOT NULL,
            user_key TEXT NOT NULL,
            is_current INTEGER NOT NULL DEFAULT 1,
            account_name TEXT NOT NULL,
            full_name TEXT,
            comment TEXT,
            home_directory TEXT,
            script_path TEXT,
            sid TEXT,
            flags INTEGER NOT NULL DEFAULT 0,
            privilege_level INTEGER NOT NULL DEFAULT 0,
            enabled INTEGER NOT NULL DEFAULT 1,
            locked INTEGER NOT NULL DEFAULT 0,
            password_required INTEGER NOT NULL DEFAULT 1,
            password_never_expires INTEGER NOT NULL DEFAULT 0,
            last_logon INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY (asset_id, snapshot_version, user_key),
            FOREIGN KEY (asset_id, snapshot_version)
                REFERENCES assets(asset_id, version) ON DELETE CASCADE
        );

        CREATE INDEX IF NOT EXISTS idx_local_users_current
            ON local_users(asset_id, is_current);
        CREATE INDEX IF NOT EXISTS idx_local_users_name
            ON local_users(account_name, is_current);

        CREATE TABLE IF NOT EXISTS installed_patches (
            asset_id TEXT NOT NULL,
            snapshot_version INTEGER NOT NULL,
            patch_key TEXT NOT NULL,
            is_current INTEGER NOT NULL DEFAULT 1,
            hotfix_id TEXT,
            description TEXT,
            installed_by TEXT,
            installed_on TEXT,
            PRIMARY KEY (asset_id, snapshot_version, patch_key),
            FOREIGN KEY (asset_id, snapshot_version)
                REFERENCES assets(asset_id, version) ON DELETE CASCADE
        );

        CREATE INDEX IF NOT EXISTS idx_patches_current
            ON installed_patches(asset_id, is_current);
        CREATE INDEX IF NOT EXISTS idx_patches_hotfix
            ON installed_patches(hotfix_id, is_current);
    )SQL";

    if (!ExecuteOrLog(db, kSchema, error, "CreateSchema")) {
        if (m_impl->ownsDatabaseManager) {
            db.Shutdown();
            m_impl->ownsDatabaseManager = false;
        }
        return false;
    }

    m_impl->initialized.store(true, std::memory_order_release);
    Logger::Info("{} initialized", kLogPrefix);
    return true;
}

void AssetDatabase::Shutdown() {
    if (!m_impl->initialized.load(std::memory_order_acquire)) {
        return;
    }

    std::unique_lock lock(m_impl->mutex);
    if (!m_impl->initialized.load(std::memory_order_relaxed)) {
        return;
    }

    if (m_impl->ownsDatabaseManager && DatabaseManager::Instance().IsInitialized()) {
        DatabaseManager::Instance().Shutdown();
    }

    m_impl->ownsDatabaseManager = false;
    m_impl->initialized.store(false, std::memory_order_release);
    Logger::Info("{} shutdown complete", kLogPrefix);
}

bool AssetDatabase::IsInitialized() const noexcept {
    return m_impl->initialized.load(std::memory_order_acquire);
}

bool AssetDatabase::UpsertAssetRecord(const AssetRecord& record) {
    if (!Initialize()) {
        return false;
    }

    if (record.assetId.empty()) {
        Logger::Error("{} upsert rejected because asset identifier is empty", kLogPrefix);
        return false;
    }

    std::unique_lock lock(m_impl->mutex);

    auto& db = DatabaseManager::Instance();
    DatabaseError error{};
    auto transaction = db.BeginTransaction(ShadowStrike::Database::Transaction::Type::Immediate, &error);
    if (!transaction) {
        return LogDatabaseFailure("BeginTransaction", error);
    }

    const int64_t nextVersion = GetCurrentAssetVersion(db, record.assetId, error) + 1;
    if (error.HasError()) {
        return LogDatabaseFailure("GetCurrentAssetVersion", error);
    }

    const auto markHistorical = [&](std::string_view table, std::string_view column) -> bool {
        const std::string sql = "UPDATE " + std::string(table) + " SET " + std::string(column) +
            " = 0 WHERE asset_id = ? AND " + std::string(column) + " = 1";
        return transaction->ExecuteWithParams(sql, &error, record.assetId);
    };

    if (!markHistorical("assets", "is_current") ||
        !markHistorical("hardware_info", "is_current") ||
        !markHistorical("disk_volumes", "is_current") ||
        !markHistorical("network_adapters", "is_current") ||
        !markHistorical("local_users", "is_current") ||
        !markHistorical("installed_patches", "is_current")) {
        (void)transaction->Rollback();
        return LogDatabaseFailure("MarkHistoricalRows", error);
    }

    const int64_t discoveredAt = record.discoveredAtUnixSeconds != 0
        ? record.discoveredAtUnixSeconds
        : CurrentUnixTime();

    if (!transaction->ExecuteWithParams(R"SQL(
            INSERT INTO assets (
                asset_id, version, is_current, discovered_at, computer_name, fqdn, domain_name,
                current_user, os_name, os_version, os_build, os_architecture, os_install_date,
                uptime_seconds
            ) VALUES (?, ?, 1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        )SQL",
        &error,
        record.assetId,
        nextVersion,
        discoveredAt,
        Narrow(record.computerName),
        Narrow(record.fullyQualifiedDomainName),
        Narrow(record.domainName),
        Narrow(record.currentUser),
        Narrow(record.osName),
        Narrow(record.osVersion),
        Narrow(record.osBuild),
        Narrow(record.osArchitecture),
        Narrow(record.osInstallDate),
        record.uptimeSeconds)) {
        (void)transaction->Rollback();
        return LogDatabaseFailure("InsertAsset", error);
    }

    if (!transaction->ExecuteWithParams(R"SQL(
            INSERT INTO hardware_info (
                asset_id, snapshot_version, is_current, discovered_at, manufacturer, model, system_family,
                system_sku, bios_version, cpu_name, cpu_vendor, cpu_architecture, processor_identifier,
                physical_core_count, logical_processor_count, processor_count, memory_module_count,
                disk_count, total_memory_bytes, total_storage_bytes, system_drive_total_bytes,
                system_drive_free_bytes
            ) VALUES (?, ?, 1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        )SQL",
        &error,
        record.assetId,
        nextVersion,
        discoveredAt,
        Narrow(record.hardware.manufacturer),
        Narrow(record.hardware.model),
        Narrow(record.hardware.systemFamily),
        Narrow(record.hardware.systemSku),
        Narrow(record.hardware.biosVersion),
        Narrow(record.hardware.cpuName),
        Narrow(record.hardware.cpuVendor),
        Narrow(record.hardware.cpuArchitecture),
        Narrow(record.hardware.processorIdentifier),
        static_cast<int>(record.hardware.physicalCoreCount),
        static_cast<int>(record.hardware.logicalProcessorCount),
        static_cast<int>(record.hardware.processorCount),
        static_cast<int>(record.hardware.memoryModuleCount),
        static_cast<int>(record.hardware.diskCount),
        static_cast<int64_t>(record.hardware.totalMemoryBytes),
        static_cast<int64_t>(record.hardware.totalStorageBytes),
        static_cast<int64_t>(record.hardware.systemDriveTotalBytes),
        static_cast<int64_t>(record.hardware.systemDriveFreeBytes))) {
        (void)transaction->Rollback();
        return LogDatabaseFailure("InsertHardware", error);
    }

    for (const auto& volume : record.hardware.diskVolumes) {
        const std::wstring volumeKey = volume.rootPath.empty() ? volume.volumeLabel : volume.rootPath;
        if (!transaction->ExecuteWithParams(R"SQL(
                INSERT INTO disk_volumes (
                    asset_id, snapshot_version, volume_key, is_current, root_path, volume_label,
                    file_system, drive_type, total_bytes, free_bytes
                ) VALUES (?, ?, ?, 1, ?, ?, ?, ?, ?, ?)
            )SQL",
            &error,
            record.assetId,
            nextVersion,
            Narrow(StringUtils::ToLowerCopy(volumeKey)),
            Narrow(volume.rootPath),
            Narrow(volume.volumeLabel),
            Narrow(volume.fileSystem),
            static_cast<int>(volume.driveType),
            static_cast<int64_t>(volume.totalBytes),
            static_cast<int64_t>(volume.freeBytes))) {
            (void)transaction->Rollback();
            return LogDatabaseFailure("InsertDiskVolume", error);
        }
    }

    for (const auto& adapter : record.networkAdapters) {
        if (!transaction->ExecuteWithParams(R"SQL(
                INSERT INTO network_adapters (
                    asset_id, snapshot_version, adapter_key, is_current, discovered_at, adapter_id,
                    friendly_name, description, dns_suffix, mac_address, interface_type,
                    operational_status, mtu, link_speed_bps, dhcp_enabled, ipv4_enabled,
                    ipv6_enabled, ipv4_addresses, ipv6_addresses, gateways, dns_servers
                ) VALUES (?, ?, ?, 1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            )SQL",
            &error,
            record.assetId,
            nextVersion,
            MakeAdapterKey(adapter),
            discoveredAt,
            Narrow(adapter.adapterId),
            Narrow(adapter.friendlyName),
            Narrow(adapter.description),
            Narrow(adapter.dnsSuffix),
            Narrow(adapter.macAddress),
            static_cast<int>(adapter.interfaceType),
            static_cast<int>(adapter.operationalStatus),
            static_cast<int>(adapter.mtu),
            static_cast<int64_t>(adapter.linkSpeedBitsPerSecond),
            adapter.dhcpEnabled ? 1 : 0,
            adapter.ipv4Enabled ? 1 : 0,
            adapter.ipv6Enabled ? 1 : 0,
            Narrow(JoinWide(adapter.ipv4Addresses)),
            Narrow(JoinWide(adapter.ipv6Addresses)),
            Narrow(JoinWide(adapter.gateways)),
            Narrow(JoinWide(adapter.dnsServers)))) {
            (void)transaction->Rollback();
            return LogDatabaseFailure("InsertNetworkAdapter", error);
        }
    }

    for (const auto& user : record.localUsers) {
        if (!transaction->ExecuteWithParams(R"SQL(
                INSERT INTO local_users (
                    asset_id, snapshot_version, user_key, is_current, account_name, full_name,
                    comment, home_directory, script_path, sid, flags, privilege_level, enabled,
                    locked, password_required, password_never_expires, last_logon
                ) VALUES (?, ?, ?, 1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            )SQL",
            &error,
            record.assetId,
            nextVersion,
            MakeUserKey(user),
            Narrow(user.accountName),
            Narrow(user.fullName),
            Narrow(user.comment),
            Narrow(user.homeDirectory),
            Narrow(user.scriptPath),
            Narrow(user.sid),
            static_cast<int>(user.flags),
            static_cast<int>(user.privilegeLevel),
            user.enabled ? 1 : 0,
            user.locked ? 1 : 0,
            user.passwordRequired ? 1 : 0,
            user.passwordNeverExpires ? 1 : 0,
            user.lastLogonUnixSeconds)) {
            (void)transaction->Rollback();
            return LogDatabaseFailure("InsertLocalUser", error);
        }
    }

    for (const auto& patch : record.patches) {
        if (!transaction->ExecuteWithParams(R"SQL(
                INSERT INTO installed_patches (
                    asset_id, snapshot_version, patch_key, is_current, hotfix_id,
                    description, installed_by, installed_on
                ) VALUES (?, ?, ?, 1, ?, ?, ?, ?)
            )SQL",
            &error,
            record.assetId,
            nextVersion,
            MakePatchKey(patch),
            Narrow(patch.hotfixId),
            Narrow(patch.description),
            Narrow(patch.installedBy),
            Narrow(patch.installedOn))) {
            (void)transaction->Rollback();
            return LogDatabaseFailure("InsertPatch", error);
        }
    }

    if (!transaction->Commit(&error)) {
        return LogDatabaseFailure("Commit", error);
    }

    Logger::Info("{} stored asset={} version={}", kLogPrefix, record.assetId, nextVersion);
    return true;
}

std::optional<AssetRecord> AssetDatabase::GetAssetRecord(std::string_view assetId) const {
    if (!IsInitialized() && !const_cast<AssetDatabase*>(this)->Initialize()) {
        return std::nullopt;
    }

    std::shared_lock lock(m_impl->mutex);

    auto& db = DatabaseManager::Instance();
    DatabaseError error{};
    auto assetRow = db.QueryWithParams(R"SQL(
            SELECT asset_id, version, discovered_at, computer_name, fqdn, domain_name, current_user,
                   os_name, os_version, os_build, os_architecture, os_install_date, uptime_seconds
            FROM assets
            WHERE asset_id = ? AND is_current = 1
            ORDER BY version DESC
            LIMIT 1
        )SQL",
        &error,
        std::string(assetId));

    if (error.HasError()) {
        (void)LogDatabaseFailure("GetAssetRecord(asset)", error);
        return std::nullopt;
    }

    if (!assetRow.Next()) {
        return std::nullopt;
    }

    AssetRecord record{};
    PopulateAssetCoreFromRow(assetRow, record);
    const int64_t version = assetRow.GetInt64("version");

    auto hardwareRow = db.QueryWithParams(R"SQL(
            SELECT manufacturer, model, system_family, system_sku, bios_version, cpu_name,
                   cpu_vendor, cpu_architecture, processor_identifier, physical_core_count,
                   logical_processor_count, processor_count, memory_module_count, disk_count,
                   total_memory_bytes, total_storage_bytes, system_drive_total_bytes,
                   system_drive_free_bytes
            FROM hardware_info
            WHERE asset_id = ? AND snapshot_version = ? AND is_current = 1
            LIMIT 1
        )SQL",
        &error,
        std::string(assetId),
        version);

    if (error.HasError()) {
        (void)LogDatabaseFailure("GetAssetRecord(hardware)", error);
        return std::nullopt;
    }

    if (hardwareRow.Next()) {
        PopulateHardwareFromRow(hardwareRow, record.hardware);
    }

    auto volumeRows = db.QueryWithParams(R"SQL(
            SELECT root_path, volume_label, file_system, drive_type, total_bytes, free_bytes
            FROM disk_volumes
            WHERE asset_id = ? AND snapshot_version = ? AND is_current = 1
            ORDER BY root_path ASC
        )SQL",
        &error,
        std::string(assetId),
        version);

    if (error.HasError()) {
        (void)LogDatabaseFailure("GetAssetRecord(disk_volumes)", error);
        return std::nullopt;
    }

    while (volumeRows.Next()) {
        DiskVolumeInfo volume{};
        volume.rootPath = volumeRows.GetWString("root_path");
        volume.volumeLabel = volumeRows.GetWString("volume_label");
        volume.fileSystem = volumeRows.GetWString("file_system");
        volume.driveType = static_cast<uint32_t>(volumeRows.GetInt("drive_type"));
        volume.totalBytes = static_cast<uint64_t>(volumeRows.GetInt64("total_bytes"));
        volume.freeBytes = static_cast<uint64_t>(volumeRows.GetInt64("free_bytes"));
        record.hardware.diskVolumes.push_back(std::move(volume));
    }

    auto adapterRows = db.QueryWithParams(R"SQL(
            SELECT adapter_id, friendly_name, description, dns_suffix, mac_address, interface_type,
                   operational_status, mtu, link_speed_bps, dhcp_enabled, ipv4_enabled, ipv6_enabled,
                   ipv4_addresses, ipv6_addresses, gateways, dns_servers
            FROM network_adapters
            WHERE asset_id = ? AND snapshot_version = ? AND is_current = 1
            ORDER BY friendly_name ASC
        )SQL",
        &error,
        std::string(assetId),
        version);

    if (error.HasError()) {
        (void)LogDatabaseFailure("GetAssetRecord(network)", error);
        return std::nullopt;
    }

    while (adapterRows.Next()) {
        NetworkAdapterInfo adapter{};
        adapter.adapterId = adapterRows.GetWString("adapter_id");
        adapter.friendlyName = adapterRows.GetWString("friendly_name");
        adapter.description = adapterRows.GetWString("description");
        adapter.dnsSuffix = adapterRows.GetWString("dns_suffix");
        adapter.macAddress = adapterRows.GetWString("mac_address");
        adapter.interfaceType = static_cast<uint32_t>(adapterRows.GetInt("interface_type"));
        adapter.operationalStatus = static_cast<uint32_t>(adapterRows.GetInt("operational_status"));
        adapter.mtu = static_cast<uint32_t>(adapterRows.GetInt("mtu"));
        adapter.linkSpeedBitsPerSecond = static_cast<uint64_t>(adapterRows.GetInt64("link_speed_bps"));
        adapter.dhcpEnabled = adapterRows.GetInt("dhcp_enabled") != 0;
        adapter.ipv4Enabled = adapterRows.GetInt("ipv4_enabled") != 0;
        adapter.ipv6Enabled = adapterRows.GetInt("ipv6_enabled") != 0;
        adapter.ipv4Addresses = SplitWide(adapterRows.GetWString("ipv4_addresses"));
        adapter.ipv6Addresses = SplitWide(adapterRows.GetWString("ipv6_addresses"));
        adapter.gateways = SplitWide(adapterRows.GetWString("gateways"));
        adapter.dnsServers = SplitWide(adapterRows.GetWString("dns_servers"));
        record.networkAdapters.push_back(std::move(adapter));
    }

    auto userRows = db.QueryWithParams(R"SQL(
            SELECT account_name, full_name, comment, home_directory, script_path, sid, flags,
                   privilege_level, enabled, locked, password_required,
                   password_never_expires, last_logon
            FROM local_users
            WHERE asset_id = ? AND snapshot_version = ? AND is_current = 1
            ORDER BY account_name ASC
        )SQL",
        &error,
        std::string(assetId),
        version);

    if (error.HasError()) {
        (void)LogDatabaseFailure("GetAssetRecord(users)", error);
        return std::nullopt;
    }

    while (userRows.Next()) {
        LocalUserInfo user{};
        user.accountName = userRows.GetWString("account_name");
        user.fullName = userRows.GetWString("full_name");
        user.comment = userRows.GetWString("comment");
        user.homeDirectory = userRows.GetWString("home_directory");
        user.scriptPath = userRows.GetWString("script_path");
        user.sid = userRows.GetWString("sid");
        user.flags = static_cast<uint32_t>(userRows.GetInt("flags"));
        user.privilegeLevel = static_cast<uint32_t>(userRows.GetInt("privilege_level"));
        user.enabled = userRows.GetInt("enabled") != 0;
        user.locked = userRows.GetInt("locked") != 0;
        user.passwordRequired = userRows.GetInt("password_required") != 0;
        user.passwordNeverExpires = userRows.GetInt("password_never_expires") != 0;
        user.lastLogonUnixSeconds = userRows.GetInt64("last_logon");
        record.localUsers.push_back(std::move(user));
    }

    record.patches = GetInstalledPatches(assetId);
    if (SoftwareInventory::Instance().IsInitialized()) {
        record.installedSoftware = SoftwareInventory::Instance().GetInstalledSoftware(assetId);
    }

    return record;
}

std::vector<AssetRecord> AssetDatabase::QueryAssetsByField(
    std::string_view fieldName,
    std::string_view value) const {
    if (!IsInitialized() && !const_cast<AssetDatabase*>(this)->Initialize()) {
        return {};
    }

    if (!ShadowStrike::Database::IsValidSqlIdentifier(fieldName)) {
        Logger::Error("{} rejected query for invalid field '{}'", kLogPrefix, std::string(fieldName));
        return {};
    }

    std::shared_lock lock(m_impl->mutex);

    auto& db = DatabaseManager::Instance();
    DatabaseError error{};
    const std::string lookupValue = NormalizeLookupValue(value);
    const std::string wildcard = "%" + lookupValue + "%";

    std::vector<std::pair<std::string, std::string>> sources{
        { "assets", "a" },
        { "hardware_info", "h" },
        { "network_adapters", "n" },
        { "local_users", "u" },
        { "installed_patches", "p" },
        { "software_inventory", "s" }
    };

    std::unordered_set<std::string> assetIds;

    for (const auto& [tableName, alias] : sources) {
        if (!db.ColumnExists(tableName, fieldName, &error)) {
            if (error.HasError()) {
                (void)LogDatabaseFailure("QueryAssetsByField(ColumnExists)", error);
                return {};
            }
            continue;
        }

        std::string sql = "SELECT DISTINCT a.asset_id "
            "FROM assets a ";

        if (tableName == "assets") {
            sql += "WHERE a.is_current = 1 AND LOWER(COALESCE(a." + std::string(fieldName) + ", '')) LIKE ?";
        } else {
            sql += "JOIN " + tableName + " " + alias + " ON a.asset_id = " + alias + ".asset_id "
                "AND a.version = " + alias + ".snapshot_version "
                "WHERE a.is_current = 1 AND " + alias + ".is_current = 1 "
                "AND LOWER(COALESCE(" + alias + "." + std::string(fieldName) + ", '')) LIKE ?";
        }

        auto rows = db.QueryWithParams(sql, &error, wildcard);
        if (error.HasError()) {
            (void)LogDatabaseFailure("QueryAssetsByField(Query)", error);
            return {};
        }

        while (rows.Next()) {
            assetIds.insert(rows.GetString(0));
        }
    }

    std::vector<AssetRecord> records;
    records.reserve(assetIds.size());
    for (const auto& assetId : assetIds) {
        if (auto record = GetAssetRecord(assetId); record.has_value()) {
            records.push_back(std::move(record.value()));
        }
    }

    return records;
}

std::vector<PatchInfo> AssetDatabase::GetInstalledPatches(std::string_view assetId) const {
    if (!IsInitialized() && !const_cast<AssetDatabase*>(this)->Initialize()) {
        return {};
    }

    std::shared_lock lock(m_impl->mutex);

    auto& db = DatabaseManager::Instance();
    DatabaseError error{};
    auto version = GetCurrentSnapshotVersion(db, "installed_patches", assetId, error);
    if (error.HasError()) {
        (void)LogDatabaseFailure("GetInstalledPatches(Version)", error);
        return {};
    }
    if (!version.has_value()) {
        return {};
    }

    auto rows = db.QueryWithParams(R"SQL(
            SELECT hotfix_id, description, installed_by, installed_on
            FROM installed_patches
            WHERE asset_id = ? AND snapshot_version = ? AND is_current = 1
            ORDER BY hotfix_id ASC, description ASC
        )SQL",
        &error,
        std::string(assetId),
        version.value());

    if (error.HasError()) {
        (void)LogDatabaseFailure("GetInstalledPatches(Query)", error);
        return {};
    }

    std::vector<PatchInfo> patches;
    while (rows.Next()) {
        PatchInfo patch{};
        patch.hotfixId = rows.GetWString("hotfix_id");
        patch.description = rows.GetWString("description");
        patch.installedBy = rows.GetWString("installed_by");
        patch.installedOn = rows.GetWString("installed_on");
        patches.push_back(std::move(patch));
    }

    return patches;
}

bool AssetDatabase::DeleteAssetRecord(std::string_view assetId) {
    if (!Initialize()) {
        return false;
    }

    std::unique_lock lock(m_impl->mutex);

    auto& db = DatabaseManager::Instance();
    DatabaseError error{};
    auto transaction = db.BeginTransaction(ShadowStrike::Database::Transaction::Type::Immediate, &error);
    if (!transaction) {
        return LogDatabaseFailure("DeleteAssetRecord(BeginTransaction)", error);
    }

    std::vector<std::string> tables{
        "disk_volumes",
        "network_adapters",
        "local_users",
        "installed_patches",
        "hardware_info",
        "assets"
    };

    if (db.TableExists("software_inventory", &error)) {
        tables.emplace_back("software_inventory");
    } else if (error.HasError()) {
        return LogDatabaseFailure("DeleteAssetRecord(TableExists)", error);
    }

    for (const auto& table : tables) {
        const std::string sql = "DELETE FROM " + std::string(table) + " WHERE asset_id = ?";
        if (!transaction->ExecuteWithParams(sql, &error, std::string(assetId))) {
            (void)transaction->Rollback();
            return LogDatabaseFailure("DeleteAssetRecord(DeleteRows)", error);
        }
    }

    if (!transaction->Commit(&error)) {
        return LogDatabaseFailure("DeleteAssetRecord(Commit)", error);
    }

    Logger::Info("{} deleted asset={}", kLogPrefix, std::string(assetId));
    return true;
}

std::wstring AssetDatabase::GetDatabasePath() const {
    std::shared_lock lock(m_impl->mutex);
    return m_impl->databasePath;
}

} // namespace ShadowStrike::Products::PhantomEDR::AssetInventory
