/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */

#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace ShadowStrike::Products::PhantomEDR::AssetInventory {

enum class InventoryChangeType : uint8_t {
    None = 0,
    Added = 1,
    Updated = 2,
    Removed = 3,
    VersionChanged = 4
};

enum class SoftwareInstallScope : uint8_t {
    Unknown = 0,
    Machine = 1,
    User = 2
};

struct DiskVolumeInfo {
    std::wstring rootPath;
    std::wstring volumeLabel;
    std::wstring fileSystem;
    uint32_t driveType = 0;
    uint64_t totalBytes = 0;
    uint64_t freeBytes = 0;
};

struct NetworkAdapterInfo {
    std::wstring adapterId;
    std::wstring friendlyName;
    std::wstring description;
    std::wstring dnsSuffix;
    std::wstring macAddress;
    std::vector<std::wstring> ipv4Addresses;
    std::vector<std::wstring> ipv6Addresses;
    std::vector<std::wstring> gateways;
    std::vector<std::wstring> dnsServers;
    uint32_t interfaceType = 0;
    uint32_t operationalStatus = 0;
    uint32_t mtu = 0;
    uint64_t linkSpeedBitsPerSecond = 0;
    bool dhcpEnabled = false;
    bool ipv4Enabled = false;
    bool ipv6Enabled = false;
};

struct LocalUserInfo {
    std::wstring accountName;
    std::wstring fullName;
    std::wstring comment;
    std::wstring homeDirectory;
    std::wstring scriptPath;
    std::wstring sid;
    uint32_t flags = 0;
    uint32_t privilegeLevel = 0;
    bool enabled = true;
    bool locked = false;
    bool passwordRequired = true;
    bool passwordNeverExpires = false;
    int64_t lastLogonUnixSeconds = 0;
};

struct PatchInfo {
    std::wstring hotfixId;
    std::wstring description;
    std::wstring installedBy;
    std::wstring installedOn;
};

struct SoftwareInfo {
    std::string assetId;
    std::wstring softwareKey;
    std::wstring name;
    std::wstring version;
    std::wstring publisher;
    std::wstring installDate;
    std::wstring installLocation;
    std::wstring uninstallString;
    std::wstring source;
    SoftwareInstallScope scope = SoftwareInstallScope::Unknown;
    int64_t observedAtUnixSeconds = 0;
    InventoryChangeType changeType = InventoryChangeType::None;
    bool systemComponent = false;
    bool windowsInstaller = false;
};

struct HardwareInventory {
    std::wstring manufacturer;
    std::wstring model;
    std::wstring systemFamily;
    std::wstring systemSku;
    std::wstring biosVersion;
    std::wstring cpuName;
    std::wstring cpuVendor;
    std::wstring cpuArchitecture;
    std::wstring processorIdentifier;
    uint32_t physicalCoreCount = 0;
    uint32_t logicalProcessorCount = 0;
    uint32_t processorCount = 0;
    uint32_t memoryModuleCount = 0;
    uint32_t diskCount = 0;
    uint64_t totalMemoryBytes = 0;
    uint64_t totalStorageBytes = 0;
    uint64_t systemDriveTotalBytes = 0;
    uint64_t systemDriveFreeBytes = 0;
    std::vector<DiskVolumeInfo> diskVolumes;
};

struct AssetRecord {
    std::string assetId;
    std::wstring computerName;
    std::wstring fullyQualifiedDomainName;
    std::wstring domainName;
    std::wstring currentUser;
    std::wstring osName;
    std::wstring osVersion;
    std::wstring osBuild;
    std::wstring osArchitecture;
    std::wstring osInstallDate;
    int64_t discoveredAtUnixSeconds = 0;
    int64_t uptimeSeconds = 0;
    HardwareInventory hardware;
    std::vector<NetworkAdapterInfo> networkAdapters;
    std::vector<LocalUserInfo> localUsers;
    std::vector<PatchInfo> patches;
    std::vector<SoftwareInfo> installedSoftware;
};

} // namespace ShadowStrike::Products::PhantomEDR::AssetInventory
