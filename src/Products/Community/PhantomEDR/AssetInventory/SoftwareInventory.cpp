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
#include "Products/Community/PhantomEDR/AssetInventory/SoftwareInventory.hpp"

#include "PhantomCore/Database/DatabaseManager.hpp"
#include "PhantomCore/Utils/Logger.hpp"
#include "PhantomCore/Utils/StringUtils.hpp"
#include "Products/Community/PhantomEDR/AssetInventory/AssetDatabase.hpp"

#include <unordered_map>

namespace ShadowStrike::Products::PhantomEDR::AssetInventory {

namespace {

using ShadowStrike::Database::DatabaseError;
using ShadowStrike::Database::DatabaseManager;
using ShadowStrike::Utils::Logger;
namespace StringUtils = ShadowStrike::Utils::StringUtils;

constexpr const char* kLogPrefix = "[SoftwareInventory]";

struct RegistryKeyHandle final {
    HKEY handle = nullptr;

    ~RegistryKeyHandle() noexcept {
        if (handle != nullptr) {
            ::RegCloseKey(handle);
        }
    }

    RegistryKeyHandle() = default;
    RegistryKeyHandle(const RegistryKeyHandle&) = delete;
    RegistryKeyHandle& operator=(const RegistryKeyHandle&) = delete;
};

struct UninstallHive {
    HKEY root = nullptr;
    const wchar_t* path = nullptr;
    REGSAM sam = KEY_READ;
    SoftwareInstallScope scope = SoftwareInstallScope::Unknown;
    const wchar_t* source = L"";
};

[[nodiscard]] int64_t CurrentUnixTime() noexcept {
    return std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
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

[[nodiscard]] std::optional<std::wstring> ReadRegistryString(
    HKEY root,
    std::wstring_view subKey,
    std::wstring_view valueName,
    REGSAM sam) {
    RegistryKeyHandle key{};
    if (::RegOpenKeyExW(root, std::wstring(subKey).c_str(), 0, sam, &key.handle) != ERROR_SUCCESS) {
        return std::nullopt;
    }

    DWORD valueType = 0;
    DWORD bytes = 0;
    const LONG status = ::RegQueryValueExW(
        key.handle,
        valueName.empty() ? nullptr : std::wstring(valueName).c_str(),
        nullptr,
        &valueType,
        nullptr,
        &bytes);

    if (status != ERROR_SUCCESS || bytes == 0 ||
        (valueType != REG_SZ && valueType != REG_EXPAND_SZ)) {
        return std::nullopt;
    }

    std::wstring buffer(bytes / sizeof(wchar_t), L'\0');
    DWORD bufferBytes = bytes;
    if (::RegQueryValueExW(
            key.handle,
            valueName.empty() ? nullptr : std::wstring(valueName).c_str(),
            nullptr,
            &valueType,
            reinterpret_cast<LPBYTE>(buffer.data()),
            &bufferBytes) != ERROR_SUCCESS) {
        return std::nullopt;
    }

    const size_t actualLength = wcsnlen(buffer.c_str(), buffer.size());
    buffer.resize(actualLength);
    return Trimmed(std::move(buffer));
}

[[nodiscard]] std::optional<DWORD> ReadRegistryDword(
    HKEY root,
    std::wstring_view subKey,
    std::wstring_view valueName,
    REGSAM sam) {
    RegistryKeyHandle key{};
    if (::RegOpenKeyExW(root, std::wstring(subKey).c_str(), 0, sam, &key.handle) != ERROR_SUCCESS) {
        return std::nullopt;
    }

    DWORD valueType = 0;
    DWORD value = 0;
    DWORD bytes = sizeof(value);
    if (::RegQueryValueExW(
            key.handle,
            std::wstring(valueName).c_str(),
            nullptr,
            &valueType,
            reinterpret_cast<LPBYTE>(&value),
            &bytes) != ERROR_SUCCESS ||
        valueType != REG_DWORD) {
        return std::nullopt;
    }

    return value;
}

[[nodiscard]] std::wstring FormatInstallDate(std::wstring rawDate) {
    rawDate = Trimmed(std::move(rawDate));
    if (rawDate.size() == 8 && std::all_of(rawDate.begin(), rawDate.end(), iswdigit)) {
        return rawDate.substr(0, 4) + L"-" + rawDate.substr(4, 2) + L"-" + rawDate.substr(6, 2);
    }
    return rawDate;
}

[[nodiscard]] std::wstring MakeSoftwareKey(
    std::wstring_view name,
    std::wstring_view publisher,
    std::wstring_view installLocation) {
    std::wstring key = StringUtils::ToLowerCopy(name);
    key.append(L"|");
    key.append(StringUtils::ToLowerCopy(publisher));
    key.append(L"|");
    key.append(StringUtils::ToLowerCopy(installLocation));
    return key;
}

[[nodiscard]] bool IsMeaningfulSoftware(const SoftwareInfo& software) {
    if (software.name.empty()) {
        return false;
    }

    if (software.systemComponent && software.publisher.empty()) {
        return false;
    }

    return true;
}

[[nodiscard]] bool IsFieldChanged(const SoftwareInfo& current, const SoftwareInfo& previous) {
    return current.version != previous.version ||
        current.publisher != previous.publisher ||
        current.installDate != previous.installDate ||
        current.installLocation != previous.installLocation ||
        current.uninstallString != previous.uninstallString ||
        current.scope != previous.scope;
}

[[nodiscard]] InventoryChangeType DetermineChangeType(
    const SoftwareInfo& current,
    const std::optional<SoftwareInfo>& previous) {
    if (!previous.has_value()) {
        return InventoryChangeType::Added;
    }

    if (current.version != previous->version) {
        return InventoryChangeType::VersionChanged;
    }

    if (IsFieldChanged(current, previous.value())) {
        return InventoryChangeType::Updated;
    }

    return InventoryChangeType::None;
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

} // namespace

class SoftwareInventoryImpl final {
public:
    std::atomic<bool> initialized{ false };
    mutable std::shared_mutex mutex;
};

SoftwareInventory& SoftwareInventory::Instance() {
    static SoftwareInventory instance;
    return instance;
}

SoftwareInventory::SoftwareInventory()
    : m_impl(std::make_unique<SoftwareInventoryImpl>()) {
}

SoftwareInventory::~SoftwareInventory() = default;

bool SoftwareInventory::Initialize() {
    if (m_impl->initialized.load(std::memory_order_acquire)) {
        return true;
    }

    std::unique_lock lock(m_impl->mutex);
    if (m_impl->initialized.load(std::memory_order_relaxed)) {
        return true;
    }

    if (!AssetDatabase::Instance().Initialize()) {
        Logger::Error("{} failed to initialize because AssetDatabase initialization failed", kLogPrefix);
        return false;
    }

    auto& db = DatabaseManager::Instance();
    DatabaseError error{};
    if (!db.Execute(R"SQL(
            CREATE TABLE IF NOT EXISTS software_inventory (
                asset_id TEXT NOT NULL,
                snapshot_version INTEGER NOT NULL,
                software_key TEXT NOT NULL,
                is_current INTEGER NOT NULL DEFAULT 1,
                observed_at INTEGER NOT NULL,
                name TEXT NOT NULL,
                version TEXT,
                publisher TEXT,
                install_date TEXT,
                install_location TEXT,
                uninstall_string TEXT,
                scope INTEGER NOT NULL DEFAULT 0,
                source TEXT,
                system_component INTEGER NOT NULL DEFAULT 0,
                windows_installer INTEGER NOT NULL DEFAULT 0,
                change_type INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY (asset_id, snapshot_version, software_key)
            );

            CREATE INDEX IF NOT EXISTS idx_software_current_asset
                ON software_inventory(asset_id, is_current, name);
            CREATE INDEX IF NOT EXISTS idx_software_key
                ON software_inventory(asset_id, software_key, is_current);
            CREATE INDEX IF NOT EXISTS idx_software_change
                ON software_inventory(asset_id, change_type, observed_at DESC);
        )SQL", &error)) {
        return LogDatabaseFailure("CreateSchema", error);
    }

    m_impl->initialized.store(true, std::memory_order_release);
    Logger::Info("{} initialized", kLogPrefix);
    return true;
}

void SoftwareInventory::Shutdown() {
    if (!m_impl->initialized.load(std::memory_order_acquire)) {
        return;
    }

    std::unique_lock lock(m_impl->mutex);
    m_impl->initialized.store(false, std::memory_order_release);
    Logger::Info("{} shutdown complete", kLogPrefix);
}

bool SoftwareInventory::IsInitialized() const noexcept {
    return m_impl->initialized.load(std::memory_order_acquire);
}

std::vector<SoftwareInfo> SoftwareInventory::EnumerateInstalledSoftware() const {
    std::unordered_map<std::wstring, SoftwareInfo> collected;
    const int64_t observedAt = CurrentUnixTime();

    const std::array<UninstallHive, 3> hives{ {
        { HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall", KEY_READ | KEY_WOW64_64KEY, SoftwareInstallScope::Machine, L"HKLM64" },
        { HKEY_LOCAL_MACHINE, L"SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall", KEY_READ | KEY_WOW64_32KEY, SoftwareInstallScope::Machine, L"HKLM32" },
        { HKEY_CURRENT_USER, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall", KEY_READ, SoftwareInstallScope::User, L"HKCU" }
    } };

    for (const auto& hive : hives) {
        RegistryKeyHandle rootKey{};
        if (::RegOpenKeyExW(hive.root, hive.path, 0, hive.sam, &rootKey.handle) != ERROR_SUCCESS) {
            continue;
        }

        DWORD subKeyCount = 0;
        DWORD maxSubKeyLen = 0;
        if (::RegQueryInfoKeyW(rootKey.handle, nullptr, nullptr, nullptr, &subKeyCount, &maxSubKeyLen,
                nullptr, nullptr, nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS) {
            continue;
        }

        std::wstring keyName(static_cast<size_t>(maxSubKeyLen) + 1, L'\0');
        for (DWORD index = 0; index < subKeyCount; ++index) {
            DWORD nameLength = static_cast<DWORD>(keyName.size());
            FILETIME lastWrite{};
            const LONG enumStatus = ::RegEnumKeyExW(
                rootKey.handle,
                index,
                keyName.data(),
                &nameLength,
                nullptr,
                nullptr,
                nullptr,
                &lastWrite);

            if (enumStatus != ERROR_SUCCESS) {
                continue;
            }

            keyName.resize(nameLength);
            const std::wstring subPath = std::wstring(hive.path) + L"\\" + keyName;

            SoftwareInfo entry{};
            entry.scope = hive.scope;
            entry.source = hive.source;
            entry.observedAtUnixSeconds = observedAt;
            entry.name = ReadRegistryString(hive.root, subPath, L"DisplayName", hive.sam).value_or(L"");
            entry.version = ReadRegistryString(hive.root, subPath, L"DisplayVersion", hive.sam).value_or(L"");
            entry.publisher = ReadRegistryString(hive.root, subPath, L"Publisher", hive.sam).value_or(L"");
            entry.installDate = FormatInstallDate(
                ReadRegistryString(hive.root, subPath, L"InstallDate", hive.sam).value_or(L""));
            entry.installLocation = ReadRegistryString(hive.root, subPath, L"InstallLocation", hive.sam).value_or(L"");
            entry.uninstallString = ReadRegistryString(hive.root, subPath, L"UninstallString", hive.sam).value_or(L"");
            entry.systemComponent = ReadRegistryDword(hive.root, subPath, L"SystemComponent", hive.sam).value_or(0U) != 0;
            entry.windowsInstaller = ReadRegistryDword(hive.root, subPath, L"WindowsInstaller", hive.sam).value_or(0U) != 0;

            if (!IsMeaningfulSoftware(entry)) {
                keyName.resize(static_cast<size_t>(maxSubKeyLen) + 1, L'\0');
                continue;
            }

            entry.softwareKey = MakeSoftwareKey(entry.name, entry.publisher, entry.installLocation);
            auto [it, inserted] = collected.emplace(entry.softwareKey, entry);
            if (!inserted) {
                SoftwareInfo& existing = it->second;
                if (existing.version.empty() && !entry.version.empty()) {
                    existing.version = entry.version;
                }
                if (existing.publisher.empty() && !entry.publisher.empty()) {
                    existing.publisher = entry.publisher;
                }
                if (existing.installDate.empty() && !entry.installDate.empty()) {
                    existing.installDate = entry.installDate;
                }
                if (existing.installLocation.empty() && !entry.installLocation.empty()) {
                    existing.installLocation = entry.installLocation;
                }
                if (existing.uninstallString.empty() && !entry.uninstallString.empty()) {
                    existing.uninstallString = entry.uninstallString;
                }
                if (existing.source.empty() && !entry.source.empty()) {
                    existing.source = entry.source;
                }
                existing.systemComponent = existing.systemComponent && entry.systemComponent;
                existing.windowsInstaller = existing.windowsInstaller || entry.windowsInstaller;
            }

            keyName.resize(static_cast<size_t>(maxSubKeyLen) + 1, L'\0');
        }
    }

    std::vector<SoftwareInfo> software;
    software.reserve(collected.size());
    for (auto& [_, entry] : collected) {
        software.push_back(std::move(entry));
    }

    std::ranges::sort(software, [](const SoftwareInfo& left, const SoftwareInfo& right) {
        return left.name < right.name;
    });

    return software;
}

bool SoftwareInventory::PersistInventory(std::string_view assetId, const std::vector<SoftwareInfo>& software) {
    if (!Initialize()) {
        return false;
    }

    if (assetId.empty()) {
        Logger::Error("{} persist rejected because asset identifier is empty", kLogPrefix);
        return false;
    }

    std::unique_lock lock(m_impl->mutex);

    auto& db = DatabaseManager::Instance();
    DatabaseError error{};
    auto transaction = db.BeginTransaction(ShadowStrike::Database::Transaction::Type::Immediate, &error);
    if (!transaction) {
        return LogDatabaseFailure("BeginTransaction", error);
    }

    auto versionQuery = db.QueryWithParams(
        "SELECT COALESCE(MAX(snapshot_version), 0) FROM software_inventory WHERE asset_id = ?",
        &error,
        std::string(assetId));

    if (error.HasError()) {
        return LogDatabaseFailure("GetSnapshotVersion", error);
    }

    int64_t snapshotVersion = 1;
    if (versionQuery.Next()) {
        snapshotVersion = versionQuery.GetInt64(0) + 1;
    }

    auto previousRows = db.QueryWithParams(R"SQL(
            SELECT software_key, name, version, publisher, install_date, install_location,
                   uninstall_string, scope, source, system_component, windows_installer
            FROM software_inventory
            WHERE asset_id = ? AND is_current = 1
        )SQL",
        &error,
        std::string(assetId));

    if (error.HasError()) {
        return LogDatabaseFailure("LoadCurrentInventory", error);
    }

    std::unordered_map<std::wstring, SoftwareInfo> previousByKey;
    while (previousRows.Next()) {
        SoftwareInfo previous{};
        previous.assetId = std::string(assetId);
        previous.softwareKey = previousRows.GetWString("software_key");
        previous.name = previousRows.GetWString("name");
        previous.version = previousRows.GetWString("version");
        previous.publisher = previousRows.GetWString("publisher");
        previous.installDate = previousRows.GetWString("install_date");
        previous.installLocation = previousRows.GetWString("install_location");
        previous.uninstallString = previousRows.GetWString("uninstall_string");
        previous.scope = static_cast<SoftwareInstallScope>(previousRows.GetInt("scope"));
        previous.source = previousRows.GetWString("source");
        previous.systemComponent = previousRows.GetInt("system_component") != 0;
        previous.windowsInstaller = previousRows.GetInt("windows_installer") != 0;
        previousByKey.emplace(previous.softwareKey, std::move(previous));
    }

    if (!transaction->ExecuteWithParams(
            "UPDATE software_inventory SET is_current = 0 WHERE asset_id = ? AND is_current = 1",
            &error,
            std::string(assetId))) {
        (void)transaction->Rollback();
        return LogDatabaseFailure("RetireCurrentInventory", error);
    }

    for (const auto& entry : software) {
        SoftwareInfo persisted = entry;
        persisted.assetId = std::string(assetId);
        if (persisted.softwareKey.empty()) {
            persisted.softwareKey = MakeSoftwareKey(persisted.name, persisted.publisher, persisted.installLocation);
        }
        persisted.changeType = DetermineChangeType(
            persisted,
            previousByKey.contains(persisted.softwareKey)
                ? std::optional<SoftwareInfo>(previousByKey.at(persisted.softwareKey))
                : std::nullopt);

        if (!transaction->ExecuteWithParams(R"SQL(
                INSERT INTO software_inventory (
                    asset_id, snapshot_version, software_key, is_current, observed_at, name, version,
                    publisher, install_date, install_location, uninstall_string, scope, source,
                    system_component, windows_installer, change_type
                ) VALUES (?, ?, ?, 1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            )SQL",
            &error,
            persisted.assetId,
            snapshotVersion,
            Narrow(persisted.softwareKey),
            persisted.observedAtUnixSeconds != 0 ? persisted.observedAtUnixSeconds : CurrentUnixTime(),
            Narrow(persisted.name),
            Narrow(persisted.version),
            Narrow(persisted.publisher),
            Narrow(persisted.installDate),
            Narrow(persisted.installLocation),
            Narrow(persisted.uninstallString),
            static_cast<int>(persisted.scope),
            Narrow(persisted.source),
            persisted.systemComponent ? 1 : 0,
            persisted.windowsInstaller ? 1 : 0,
            static_cast<int>(persisted.changeType))) {
            (void)transaction->Rollback();
            return LogDatabaseFailure("InsertSoftware", error);
        }
    }

    if (!transaction->Commit(&error)) {
        return LogDatabaseFailure("Commit", error);
    }

    Logger::Info("{} stored {} software entries for asset={}",
        kLogPrefix,
        software.size(),
        std::string(assetId));
    return true;
}

std::vector<SoftwareInfo> SoftwareInventory::GetInstalledSoftware(std::string_view assetId) const {
    if (!IsInitialized() && !const_cast<SoftwareInventory*>(this)->Initialize()) {
        return {};
    }

    std::shared_lock lock(m_impl->mutex);

    auto& db = DatabaseManager::Instance();
    DatabaseError error{};
    auto rows = db.QueryWithParams(R"SQL(
            SELECT software_key, observed_at, name, version, publisher, install_date, install_location,
                   uninstall_string, scope, source, system_component, windows_installer, change_type
            FROM software_inventory
            WHERE asset_id = ? AND is_current = 1
            ORDER BY name ASC, publisher ASC
        )SQL",
        &error,
        std::string(assetId));

    if (error.HasError()) {
        (void)LogDatabaseFailure("GetInstalledSoftware", error);
        return {};
    }

    std::vector<SoftwareInfo> software;
    while (rows.Next()) {
        SoftwareInfo entry{};
        entry.assetId = std::string(assetId);
        entry.softwareKey = rows.GetWString("software_key");
        entry.observedAtUnixSeconds = rows.GetInt64("observed_at");
        entry.name = rows.GetWString("name");
        entry.version = rows.GetWString("version");
        entry.publisher = rows.GetWString("publisher");
        entry.installDate = rows.GetWString("install_date");
        entry.installLocation = rows.GetWString("install_location");
        entry.uninstallString = rows.GetWString("uninstall_string");
        entry.scope = static_cast<SoftwareInstallScope>(rows.GetInt("scope"));
        entry.source = rows.GetWString("source");
        entry.systemComponent = rows.GetInt("system_component") != 0;
        entry.windowsInstaller = rows.GetInt("windows_installer") != 0;
        entry.changeType = static_cast<InventoryChangeType>(rows.GetInt("change_type"));
        software.push_back(std::move(entry));
    }

    return software;
}

std::vector<SoftwareInfo> SoftwareInventory::GetVersionChanges(std::string_view assetId) const {
    if (!IsInitialized() && !const_cast<SoftwareInventory*>(this)->Initialize()) {
        return {};
    }

    std::shared_lock lock(m_impl->mutex);

    auto& db = DatabaseManager::Instance();
    DatabaseError error{};
    auto rows = db.QueryWithParams(R"SQL(
            SELECT software_key, observed_at, name, version, publisher, install_date, install_location,
                   uninstall_string, scope, source, system_component, windows_installer, change_type
            FROM software_inventory
            WHERE asset_id = ? AND is_current = 1 AND change_type = ?
            ORDER BY observed_at DESC, name ASC
        )SQL",
        &error,
        std::string(assetId),
        static_cast<int>(InventoryChangeType::VersionChanged));

    if (error.HasError()) {
        (void)LogDatabaseFailure("GetVersionChanges", error);
        return {};
    }

    std::vector<SoftwareInfo> changes;
    while (rows.Next()) {
        SoftwareInfo entry{};
        entry.assetId = std::string(assetId);
        entry.softwareKey = rows.GetWString("software_key");
        entry.observedAtUnixSeconds = rows.GetInt64("observed_at");
        entry.name = rows.GetWString("name");
        entry.version = rows.GetWString("version");
        entry.publisher = rows.GetWString("publisher");
        entry.installDate = rows.GetWString("install_date");
        entry.installLocation = rows.GetWString("install_location");
        entry.uninstallString = rows.GetWString("uninstall_string");
        entry.scope = static_cast<SoftwareInstallScope>(rows.GetInt("scope"));
        entry.source = rows.GetWString("source");
        entry.systemComponent = rows.GetInt("system_component") != 0;
        entry.windowsInstaller = rows.GetInt("windows_installer") != 0;
        entry.changeType = static_cast<InventoryChangeType>(rows.GetInt("change_type"));
        changes.push_back(std::move(entry));
    }

    return changes;
}

std::vector<SoftwareInfo> SoftwareInventory::ScanAndStore(std::string_view assetId) {
    auto software = EnumerateInstalledSoftware();
    if (!PersistInventory(assetId, software)) {
        return {};
    }

    return GetInstalledSoftware(assetId);
}

} // namespace ShadowStrike::Products::PhantomEDR::AssetInventory
