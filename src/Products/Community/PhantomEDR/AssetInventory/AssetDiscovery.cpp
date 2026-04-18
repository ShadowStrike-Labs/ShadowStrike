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
#include "Products/Community/PhantomEDR/AssetInventory/AssetDiscovery.hpp"

#include "PhantomCore/Database/DatabaseManager.hpp"
#include "PhantomCore/Utils/Logger.hpp"
#include "PhantomCore/Utils/NetworkUtils.hpp"
#include "PhantomCore/Utils/StringUtils.hpp"
#include "Products/Community/PhantomEDR/AssetInventory/AssetDatabase.hpp"
#include "Products/Community/PhantomEDR/AssetInventory/SoftwareInventory.hpp"

#include <comdef.h>
#include <condition_variable>
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif
#ifndef NTDDI_VERSION
#define NTDDI_VERSION NTDDI_WIN7
#endif
#include <lm.h>
#include <sddl.h>
#include <wbemidl.h>
#include <winternl.h>

#pragma comment(lib, "netapi32.lib")
#pragma comment(lib, "wbemuuid.lib")

namespace ShadowStrike::Products::PhantomEDR::AssetInventory {

namespace {

using ShadowStrike::Utils::Logger;
namespace NetworkUtils = ShadowStrike::Utils::NetworkUtils;
namespace StringUtils = ShadowStrike::Utils::StringUtils;

constexpr const char* kLogPrefix = "[AssetDiscovery]";

template <typename T>
class ComPtr final {
public:
    ComPtr() = default;
    ~ComPtr() noexcept {
        Reset();
    }

    ComPtr(const ComPtr&) = delete;
    ComPtr& operator=(const ComPtr&) = delete;

    ComPtr(ComPtr&& other) noexcept
        : m_ptr(other.m_ptr) {
        other.m_ptr = nullptr;
    }

    ComPtr& operator=(ComPtr&& other) noexcept {
        if (this != &other) {
            Reset();
            m_ptr = other.m_ptr;
            other.m_ptr = nullptr;
        }
        return *this;
    }

    [[nodiscard]] T* Get() const noexcept {
        return m_ptr;
    }

    [[nodiscard]] T** Put() noexcept {
        Reset();
        return &m_ptr;
    }

    [[nodiscard]] T* operator->() const noexcept {
        return m_ptr;
    }

    void Reset(T* ptr = nullptr) noexcept {
        if (m_ptr != nullptr) {
            m_ptr->Release();
        }
        m_ptr = ptr;
    }

private:
    T* m_ptr = nullptr;
};

class VariantGuard final {
public:
    VariantGuard() noexcept {
        ::VariantInit(&m_value);
    }

    ~VariantGuard() noexcept {
        ::VariantClear(&m_value);
    }

    VariantGuard(const VariantGuard&) = delete;
    VariantGuard& operator=(const VariantGuard&) = delete;

    [[nodiscard]] VARIANT* Get() noexcept {
        return &m_value;
    }

    [[nodiscard]] const VARIANT& Value() const noexcept {
        return m_value;
    }

private:
    VARIANT m_value{};
};

class RegKeyHandle final {
public:
    RegKeyHandle() = default;
    explicit RegKeyHandle(HKEY handle) noexcept
        : m_handle(handle) {
    }

    ~RegKeyHandle() noexcept {
        if (m_handle != nullptr) {
            ::RegCloseKey(m_handle);
        }
    }

    RegKeyHandle(const RegKeyHandle&) = delete;
    RegKeyHandle& operator=(const RegKeyHandle&) = delete;

    [[nodiscard]] HKEY* Put() noexcept {
        if (m_handle != nullptr) {
            ::RegCloseKey(m_handle);
            m_handle = nullptr;
        }
        return &m_handle;
    }

    [[nodiscard]] HKEY Get() const noexcept {
        return m_handle;
    }

private:
    HKEY m_handle = nullptr;
};

class ComApartment final {
public:
    ComApartment() noexcept {
        const HRESULT hr = ::CoInitializeEx(nullptr, COINIT_MULTITHREADED);
        if (SUCCEEDED(hr)) {
            m_initialized = true;
            m_needsUninitialize = true;
        } else if (hr == RPC_E_CHANGED_MODE) {
            m_initialized = true;
            m_needsUninitialize = false;
        } else {
            m_hr = hr;
        }
    }

    ~ComApartment() noexcept {
        if (m_needsUninitialize) {
            ::CoUninitialize();
        }
    }

    ComApartment(const ComApartment&) = delete;
    ComApartment& operator=(const ComApartment&) = delete;

    [[nodiscard]] bool IsInitialized() const noexcept {
        return m_initialized;
    }

    [[nodiscard]] HRESULT Status() const noexcept {
        return m_hr;
    }

private:
    HRESULT m_hr = S_OK;
    bool m_initialized = false;
    bool m_needsUninitialize = false;
};

class WmiSession final {
public:
    [[nodiscard]] bool Connect() {
        if (!m_apartment.IsInitialized()) {
            Logger::Error("{} COM initialization failed: hr={:#x}", kLogPrefix, static_cast<uint32_t>(m_apartment.Status()));
            return false;
        }

        const HRESULT securityHr = ::CoInitializeSecurity(
            nullptr,
            -1,
            nullptr,
            nullptr,
            RPC_C_AUTHN_LEVEL_DEFAULT,
            RPC_C_IMP_LEVEL_IMPERSONATE,
            nullptr,
            EOAC_NONE,
            nullptr);

        if (FAILED(securityHr) && securityHr != RPC_E_TOO_LATE) {
            Logger::Warn("{} CoInitializeSecurity failed: hr={:#x}", kLogPrefix, static_cast<uint32_t>(securityHr));
            return false;
        }

        HRESULT hr = ::CoCreateInstance(
            CLSID_WbemLocator,
            nullptr,
            CLSCTX_INPROC_SERVER,
            IID_IWbemLocator,
            reinterpret_cast<void**>(m_locator.Put()));
        if (FAILED(hr)) {
            Logger::Warn("{} CoCreateInstance(IWbemLocator) failed: hr={:#x}", kLogPrefix, static_cast<uint32_t>(hr));
            return false;
        }

        hr = m_locator->ConnectServer(
            _bstr_t(L"ROOT\\CIMV2"),
            nullptr,
            nullptr,
            nullptr,
            0,
            nullptr,
            nullptr,
            m_services.Put());
        if (FAILED(hr)) {
            Logger::Warn("{} ConnectServer(ROOT\\\\CIMV2) failed: hr={:#x}", kLogPrefix, static_cast<uint32_t>(hr));
            return false;
        }

        hr = ::CoSetProxyBlanket(
            m_services.Get(),
            RPC_C_AUTHN_WINNT,
            RPC_C_AUTHZ_NONE,
            nullptr,
            RPC_C_AUTHN_LEVEL_CALL,
            RPC_C_IMP_LEVEL_IMPERSONATE,
            nullptr,
            EOAC_NONE);
        if (FAILED(hr)) {
            Logger::Warn("{} CoSetProxyBlanket failed: hr={:#x}", kLogPrefix, static_cast<uint32_t>(hr));
            return false;
        }

        return true;
    }

    template <typename Callback>
    [[nodiscard]] bool ForEach(std::wstring_view query, Callback&& callback) const {
        if (m_services.Get() == nullptr) {
            return false;
        }

        ComPtr<IEnumWbemClassObject> enumerator;
        const HRESULT hr = m_services->ExecQuery(
            _bstr_t(L"WQL"),
            _bstr_t(query.data()),
            WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
            nullptr,
            enumerator.Put());

        if (FAILED(hr)) {
            Logger::Warn("{} WMI query failed: hr={:#x}", kLogPrefix, static_cast<uint32_t>(hr));
            return false;
        }

        while (true) {
            ComPtr<IWbemClassObject> object;
            ULONG returned = 0;
            const HRESULT nextHr = enumerator->Next(5000, 1, object.Put(), &returned);
            if (FAILED(nextHr) || returned == 0) {
                break;
            }

            callback(object.Get());
        }

        return true;
    }

private:
    ComApartment m_apartment;
    ComPtr<IWbemLocator> m_locator;
    ComPtr<IWbemServices> m_services;
};

[[nodiscard]] int64_t CurrentUnixTime() noexcept {
    return std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}

[[nodiscard]] std::string Narrow(std::wstring_view value) {
    return StringUtils::ToNarrow(value);
}

[[nodiscard]] std::wstring Trimmed(std::wstring value) {
    StringUtils::Trim(value);
    return value;
}

[[nodiscard]] std::wstring ReadRegistryStringValue(
    HKEY root,
    std::wstring_view subKey,
    std::wstring_view valueName,
    REGSAM sam = KEY_READ) {
    RegKeyHandle key;
    if (::RegOpenKeyExW(root, std::wstring(subKey).c_str(), 0, sam, key.Put()) != ERROR_SUCCESS) {
        return {};
    }

    DWORD valueType = 0;
    DWORD bytes = 0;
    if (::RegQueryValueExW(
            key.Get(),
            std::wstring(valueName).c_str(),
            nullptr,
            &valueType,
            nullptr,
            &bytes) != ERROR_SUCCESS ||
        (valueType != REG_SZ && valueType != REG_EXPAND_SZ) ||
        bytes == 0) {
        return {};
    }

    std::wstring buffer(bytes / sizeof(wchar_t), L'\0');
    DWORD bufferBytes = bytes;
    if (::RegQueryValueExW(
            key.Get(),
            std::wstring(valueName).c_str(),
            nullptr,
            &valueType,
            reinterpret_cast<LPBYTE>(buffer.data()),
            &bufferBytes) != ERROR_SUCCESS) {
        return {};
    }

    buffer.resize(wcsnlen(buffer.c_str(), buffer.size()));
    return Trimmed(std::move(buffer));
}

[[nodiscard]] std::wstring GetComputerNameValue(COMPUTER_NAME_FORMAT format) {
    DWORD size = 0;
    ::GetComputerNameExW(format, nullptr, &size);
    if (size == 0) {
        return {};
    }

    std::wstring value(size, L'\0');
    if (!::GetComputerNameExW(format, value.data(), &size)) {
        return {};
    }

    value.resize(size);
    return value;
}

[[nodiscard]] std::wstring GetCurrentUserName() {
    DWORD size = 0;
    ::GetUserNameW(nullptr, &size);
    if (size == 0) {
        return {};
    }

    std::wstring user(size, L'\0');
    if (!::GetUserNameW(user.data(), &size) || size == 0) {
        return {};
    }

    user.resize(size > 0 ? size - 1 : 0);
    return user;
}

[[nodiscard]] std::wstring GetMachineGuid() {
    return ReadRegistryStringValue(
        HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\Cryptography",
        L"MachineGuid",
        KEY_READ | KEY_WOW64_64KEY);
}

[[nodiscard]] std::wstring ResolveAccountSid(std::wstring_view accountName) {
    if (accountName.empty()) {
        return {};
    }

    const std::wstring account(accountName);
    DWORD sidSize = 0;
    DWORD domainSize = 0;
    SID_NAME_USE use = SidTypeUnknown;
    ::LookupAccountNameW(nullptr, account.c_str(), nullptr, &sidSize, nullptr, &domainSize, &use);
    if (sidSize == 0) {
        return {};
    }

    std::vector<BYTE> sidBuffer(sidSize);
    std::wstring domain(domainSize, L'\0');
    if (!::LookupAccountNameW(
            nullptr,
            account.c_str(),
            sidBuffer.data(),
            &sidSize,
            domain.data(),
            &domainSize,
            &use)) {
        return {};
    }

    LPWSTR sidText = nullptr;
    if (::ConvertSidToStringSidW(reinterpret_cast<PSID>(sidBuffer.data()), &sidText) == FALSE || sidText == nullptr) {
        return {};
    }

    std::wstring result = sidText;
    ::LocalFree(sidText);
    return result;
}

[[nodiscard]] std::string GetAssetId() {
    std::wstring machineGuid = GetMachineGuid();
    if (!machineGuid.empty()) {
        return Narrow(StringUtils::ToLowerCopy(machineGuid));
    }

    std::wstring computerName = GetComputerNameValue(ComputerNamePhysicalDnsHostname);
    if (!computerName.empty()) {
        return Narrow(StringUtils::ToLowerCopy(computerName));
    }

    return "unknown-endpoint";
}

[[nodiscard]] std::wstring ProcessorArchitectureToString(WORD architecture) {
    switch (architecture) {
    case PROCESSOR_ARCHITECTURE_AMD64:
        return L"x64";
    case PROCESSOR_ARCHITECTURE_INTEL:
        return L"x86";
    case PROCESSOR_ARCHITECTURE_ARM64:
        return L"ARM64";
    case PROCESSOR_ARCHITECTURE_ARM:
        return L"ARM";
    default:
        return L"Unknown";
    }
}

[[nodiscard]] std::wstring VariantToString(const VARIANT& value) {
    if ((value.vt == VT_BSTR || value.vt == (VT_BSTR | VT_BYREF)) && value.bstrVal != nullptr) {
        return std::wstring(value.bstrVal, ::SysStringLen(value.bstrVal));
    }

    if (value.vt == VT_UI4) {
        return std::to_wstring(value.ulVal);
    }

    if (value.vt == VT_I4) {
        return std::to_wstring(value.lVal);
    }

    if (value.vt == VT_UI8) {
        return std::to_wstring(value.ullVal);
    }

    if (value.vt == VT_I8) {
        return std::to_wstring(value.llVal);
    }

    return {};
}

[[nodiscard]] std::wstring GetWmiString(IWbemClassObject* object, const wchar_t* name) {
    if (object == nullptr || name == nullptr) {
        return {};
    }

    VariantGuard value;
    if (FAILED(object->Get(name, 0, value.Get(), nullptr, nullptr))) {
        return {};
    }

    return Trimmed(VariantToString(value.Value()));
}

[[nodiscard]] uint32_t GetWmiUInt32(IWbemClassObject* object, const wchar_t* name) {
    const std::wstring text = GetWmiString(object, name);
    if (text.empty()) {
        return 0;
    }

    try {
        return static_cast<uint32_t>(std::stoul(text));
    } catch (...) {
        return 0;
    }
}

[[nodiscard]] uint64_t GetWmiUInt64(IWbemClassObject* object, const wchar_t* name) {
    const std::wstring text = GetWmiString(object, name);
    if (text.empty()) {
        return 0;
    }

    try {
        return static_cast<uint64_t>(std::stoull(text));
    } catch (...) {
        return 0;
    }
}

[[nodiscard]] std::wstring FormatWmiDate(std::wstring_view value) {
    if (value.size() < 8) {
        return {};
    }

    return std::wstring(value.substr(0, 4)) + L"-" +
        std::wstring(value.substr(4, 2)) + L"-" +
        std::wstring(value.substr(6, 2));
}

void CollectNativeOsData(AssetRecord& record) {
    RTL_OSVERSIONINFOEXW osVersion{};
    osVersion.dwOSVersionInfoSize = sizeof(osVersion);

    using RtlGetVersionFn = LONG(WINAPI*)(PRTL_OSVERSIONINFOW);
    bool versionCaptured = false;

    if (HMODULE ntdll = ::GetModuleHandleW(L"ntdll.dll"); ntdll != nullptr) {
        const auto rtlGetVersion = reinterpret_cast<RtlGetVersionFn>(
            ::GetProcAddress(ntdll, "RtlGetVersion"));
        if (rtlGetVersion != nullptr &&
            rtlGetVersion(reinterpret_cast<PRTL_OSVERSIONINFOW>(&osVersion)) == 0) {
            versionCaptured = true;
        }
    }

    if (!versionCaptured) {
#pragma warning(push)
#pragma warning(disable: 4996)
        OSVERSIONINFOEXW fallback{};
        fallback.dwOSVersionInfoSize = sizeof(fallback);
        if (::GetVersionExW(reinterpret_cast<OSVERSIONINFOW*>(&fallback))) {
            osVersion.dwMajorVersion = fallback.dwMajorVersion;
            osVersion.dwMinorVersion = fallback.dwMinorVersion;
            osVersion.dwBuildNumber = fallback.dwBuildNumber;
        }
#pragma warning(pop)
    }

    if (record.osVersion.empty()) {
        record.osVersion = std::to_wstring(osVersion.dwMajorVersion) + L"." +
            std::to_wstring(osVersion.dwMinorVersion);
    }
    if (record.osBuild.empty()) {
        record.osBuild = std::to_wstring(osVersion.dwBuildNumber);
    }
    if (record.osName.empty()) {
        if (osVersion.dwMajorVersion == 10 && osVersion.dwMinorVersion == 0) {
            record.osName = osVersion.dwBuildNumber >= 22000 ? L"Windows 11" : L"Windows 10";
        } else {
            record.osName = L"Windows";
        }
    }
}

void CollectComputerIdentity(AssetRecord& record) {
    record.assetId = GetAssetId();
    record.computerName = GetComputerNameValue(ComputerNamePhysicalDnsHostname);
    record.fullyQualifiedDomainName = GetComputerNameValue(ComputerNamePhysicalDnsFullyQualified);
    record.domainName = GetComputerNameValue(ComputerNameDnsDomain);
    record.currentUser = GetCurrentUserName();
}

void CollectProcessorRegistryData(HardwareInventory& hardware) {
    hardware.cpuName = ReadRegistryStringValue(
        HKEY_LOCAL_MACHINE,
        L"HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0",
        L"ProcessorNameString");
    hardware.cpuVendor = ReadRegistryStringValue(
        HKEY_LOCAL_MACHINE,
        L"HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0",
        L"VendorIdentifier");
    hardware.processorIdentifier = ReadRegistryStringValue(
        HKEY_LOCAL_MACHINE,
        L"HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0",
        L"Identifier");
}

void CollectSystemInfo(HardwareInventory& hardware, AssetRecord& record) {
    SYSTEM_INFO systemInfo{};
    ::GetNativeSystemInfo(&systemInfo);

    hardware.cpuArchitecture = ProcessorArchitectureToString(systemInfo.wProcessorArchitecture);
    hardware.logicalProcessorCount = systemInfo.dwNumberOfProcessors;
    record.osArchitecture = hardware.cpuArchitecture;
    record.uptimeSeconds = static_cast<int64_t>(::GetTickCount64() / 1000ULL);

    MEMORYSTATUSEX memoryStatus{};
    memoryStatus.dwLength = sizeof(memoryStatus);
    if (::GlobalMemoryStatusEx(&memoryStatus)) {
        hardware.totalMemoryBytes = memoryStatus.ullTotalPhys;
    } else {
        Logger::Warn("{} GlobalMemoryStatusEx failed", kLogPrefix);
    }

    CollectProcessorRegistryData(hardware);
}

void CollectDiskVolumes(HardwareInventory& hardware) {
    const DWORD required = ::GetLogicalDriveStringsW(0, nullptr);
    if (required == 0) {
        Logger::Warn("{} GetLogicalDriveStringsW failed", kLogPrefix);
        return;
    }

    std::wstring driveBuffer(required + 1, L'\0');
    if (::GetLogicalDriveStringsW(required, driveBuffer.data()) == 0) {
        Logger::Warn("{} GetLogicalDriveStringsW returned no drive data", kLogPrefix);
        return;
    }

    for (const wchar_t* current = driveBuffer.c_str(); *current != L'\0'; current += wcslen(current) + 1) {
        DiskVolumeInfo volume{};
        volume.rootPath = current;
        volume.driveType = ::GetDriveTypeW(current);

        ULARGE_INTEGER freeBytes{};
        ULARGE_INTEGER totalBytes{};
        ULARGE_INTEGER totalFree{};
        if (::GetDiskFreeSpaceExW(current, &freeBytes, &totalBytes, &totalFree)) {
            volume.totalBytes = totalBytes.QuadPart;
            volume.freeBytes = totalFree.QuadPart;
            hardware.totalStorageBytes += totalBytes.QuadPart;
            if (hardware.systemDriveTotalBytes == 0 &&
                (current[0] == L'C' || current[0] == L'c')) {
                hardware.systemDriveTotalBytes = totalBytes.QuadPart;
                hardware.systemDriveFreeBytes = totalFree.QuadPart;
            }
        }

        wchar_t volumeLabel[MAX_PATH]{};
        wchar_t fileSystem[MAX_PATH]{};
        DWORD serialNumber = 0;
        DWORD maxComponentLength = 0;
        DWORD fileSystemFlags = 0;
        if (::GetVolumeInformationW(
                current,
                volumeLabel,
                static_cast<DWORD>(std::size(volumeLabel)),
                &serialNumber,
                &maxComponentLength,
                &fileSystemFlags,
                fileSystem,
                static_cast<DWORD>(std::size(fileSystem)))) {
            volume.volumeLabel = volumeLabel;
            volume.fileSystem = fileSystem;
        }

        hardware.diskVolumes.push_back(std::move(volume));
    }

    hardware.diskCount = static_cast<uint32_t>(hardware.diskVolumes.size());
}

void CollectNetworkAdapters(AssetRecord& record) {
    NetworkUtils::Error error{};
    std::vector<NetworkUtils::NetworkAdapterInfo> adapters;
    if (!NetworkUtils::GetNetworkAdapters(adapters, &error)) {
        Logger::Warn("{} network enumeration failed: {}", kLogPrefix, Narrow(error.message));
        return;
    }

    for (const auto& adapter : adapters) {
        NetworkAdapterInfo entry{};
        entry.friendlyName = adapter.friendlyName;
        entry.description = adapter.description;
        entry.macAddress = adapter.macAddress.ToString();
        entry.interfaceType = static_cast<uint32_t>(adapter.type);
        entry.operationalStatus = static_cast<uint32_t>(adapter.status);
        entry.mtu = adapter.mtu;
        entry.linkSpeedBitsPerSecond = adapter.speed;
        entry.dhcpEnabled = adapter.dhcpEnabled;
        entry.ipv4Enabled = adapter.ipv4Enabled;
        entry.ipv6Enabled = adapter.ipv6Enabled;
        entry.adapterId = std::to_wstring(adapter.interfaceIndex);

        for (const auto& address : adapter.ipAddresses) {
            const std::wstring text = address.ToString();
            if (text.empty()) {
                continue;
            }

            if (address.IsIPv4()) {
                entry.ipv4Addresses.push_back(text);
            } else if (address.IsIPv6()) {
                entry.ipv6Addresses.push_back(text);
            }
        }

        for (const auto& gateway : adapter.gatewayAddresses) {
            const std::wstring text = gateway.ToString();
            if (!text.empty()) {
                entry.gateways.push_back(text);
            }
        }

        for (const auto& dns : adapter.dnsServers) {
            const std::wstring text = dns.ToString();
            if (!text.empty()) {
                entry.dnsServers.push_back(text);
            }
        }

        record.networkAdapters.push_back(std::move(entry));
    }
}

void CollectLocalUsers(AssetRecord& record) {
    LPUSER_INFO_3 users = nullptr;
    DWORD entriesRead = 0;
    DWORD totalEntries = 0;
    DWORD resumeHandle = 0;

    do {
        const NET_API_STATUS status = ::NetUserEnum(
            nullptr,
            3,
            FILTER_NORMAL_ACCOUNT,
            reinterpret_cast<LPBYTE*>(&users),
            MAX_PREFERRED_LENGTH,
            &entriesRead,
            &totalEntries,
            &resumeHandle);

        if (status != NERR_Success && status != ERROR_MORE_DATA) {
            Logger::Warn("{} NetUserEnum failed: status={}", kLogPrefix, status);
            break;
        }

        for (DWORD index = 0; index < entriesRead; ++index) {
            const USER_INFO_3& raw = users[index];
            LocalUserInfo user{};
            user.accountName = raw.usri3_name != nullptr ? raw.usri3_name : L"";
            user.fullName = raw.usri3_full_name != nullptr ? raw.usri3_full_name : L"";
            user.comment = raw.usri3_comment != nullptr ? raw.usri3_comment : L"";
            user.homeDirectory = raw.usri3_home_dir != nullptr ? raw.usri3_home_dir : L"";
            user.scriptPath = raw.usri3_script_path != nullptr ? raw.usri3_script_path : L"";
            user.flags = raw.usri3_flags;
            user.privilegeLevel = raw.usri3_priv;
            user.enabled = (raw.usri3_flags & UF_ACCOUNTDISABLE) == 0;
            user.locked = (raw.usri3_flags & UF_LOCKOUT) != 0;
            user.passwordRequired = (raw.usri3_flags & UF_PASSWD_NOTREQD) == 0;
            user.passwordNeverExpires = (raw.usri3_flags & UF_DONT_EXPIRE_PASSWD) != 0;
            user.lastLogonUnixSeconds = static_cast<int64_t>(raw.usri3_last_logon);

            user.sid = ResolveAccountSid(user.accountName);

            record.localUsers.push_back(std::move(user));
        }

        if (users != nullptr) {
            ::NetApiBufferFree(users);
            users = nullptr;
        }

        if (status != ERROR_MORE_DATA) {
            break;
        }
    } while (true);
}

void CollectWmiComputerSystem(const WmiSession& wmi, AssetRecord& record) {
    (void)wmi.ForEach(L"SELECT Manufacturer, Model, Domain, SystemFamily, SystemSKUNumber FROM Win32_ComputerSystem",
        [&record](IWbemClassObject* object) {
            if (record.hardware.manufacturer.empty()) {
                record.hardware.manufacturer = GetWmiString(object, L"Manufacturer");
            }
            if (record.hardware.model.empty()) {
                record.hardware.model = GetWmiString(object, L"Model");
            }
            if (record.domainName.empty()) {
                record.domainName = GetWmiString(object, L"Domain");
            }
            if (record.hardware.systemFamily.empty()) {
                record.hardware.systemFamily = GetWmiString(object, L"SystemFamily");
            }
            if (record.hardware.systemSku.empty()) {
                record.hardware.systemSku = GetWmiString(object, L"SystemSKUNumber");
            }
        });
}

void CollectWmiOperatingSystem(const WmiSession& wmi, AssetRecord& record) {
    (void)wmi.ForEach(L"SELECT Caption, Version, BuildNumber, InstallDate FROM Win32_OperatingSystem",
        [&record](IWbemClassObject* object) {
            if (record.osName.empty()) {
                record.osName = GetWmiString(object, L"Caption");
            }
            if (record.osVersion.empty()) {
                record.osVersion = GetWmiString(object, L"Version");
            }
            if (record.osBuild.empty()) {
                record.osBuild = GetWmiString(object, L"BuildNumber");
            }
            if (record.osInstallDate.empty()) {
                record.osInstallDate = FormatWmiDate(GetWmiString(object, L"InstallDate"));
            }
        });
}

void CollectWmiProcessor(const WmiSession& wmi, HardwareInventory& hardware) {
    (void)wmi.ForEach(L"SELECT Name, Manufacturer, NumberOfCores, NumberOfLogicalProcessors FROM Win32_Processor",
        [&hardware](IWbemClassObject* object) {
            if (hardware.cpuName.empty()) {
                hardware.cpuName = GetWmiString(object, L"Name");
            }
            if (hardware.cpuVendor.empty()) {
                hardware.cpuVendor = GetWmiString(object, L"Manufacturer");
            }
            hardware.physicalCoreCount += GetWmiUInt32(object, L"NumberOfCores");
            hardware.logicalProcessorCount = std::max(
                hardware.logicalProcessorCount,
                GetWmiUInt32(object, L"NumberOfLogicalProcessors"));
            ++hardware.processorCount;
        });
}

void CollectWmiMemory(const WmiSession& wmi, HardwareInventory& hardware) {
    (void)wmi.ForEach(L"SELECT Capacity FROM Win32_PhysicalMemory",
        [&hardware](IWbemClassObject* object) {
            const uint64_t capacity = GetWmiUInt64(object, L"Capacity");
            if (capacity != 0) {
                ++hardware.memoryModuleCount;
            }
        });
}

void CollectWmiDiskData(const WmiSession& wmi, HardwareInventory& hardware) {
    uint32_t physicalDiskCount = 0;
    (void)wmi.ForEach(L"SELECT Model FROM Win32_DiskDrive",
        [&physicalDiskCount](IWbemClassObject* object) {
            const std::wstring model = GetWmiString(object, L"Model");
            if (!model.empty()) {
                ++physicalDiskCount;
            }
        });
    hardware.diskCount = std::max(hardware.diskCount, physicalDiskCount);
}

void CollectWmiPatches(const WmiSession& wmi, AssetRecord& record) {
    (void)wmi.ForEach(L"SELECT HotFixID, Description, InstalledBy, InstalledOn FROM Win32_QuickFixEngineering",
        [&record](IWbemClassObject* object) {
            PatchInfo patch{};
            patch.hotfixId = GetWmiString(object, L"HotFixID");
            patch.description = GetWmiString(object, L"Description");
            patch.installedBy = GetWmiString(object, L"InstalledBy");
            patch.installedOn = GetWmiString(object, L"InstalledOn");
            if (!patch.hotfixId.empty() || !patch.description.empty()) {
                record.patches.push_back(std::move(patch));
            }
        });
}

[[nodiscard]] AssetRecord CollectAssetRecord() {
    AssetRecord record{};
    record.discoveredAtUnixSeconds = CurrentUnixTime();

    CollectComputerIdentity(record);
    CollectNativeOsData(record);
    CollectSystemInfo(record.hardware, record);
    CollectDiskVolumes(record.hardware);
    CollectNetworkAdapters(record);
    CollectLocalUsers(record);

    WmiSession wmi;
    if (wmi.Connect()) {
        CollectWmiOperatingSystem(wmi, record);
        CollectWmiComputerSystem(wmi, record);
        CollectWmiProcessor(wmi, record.hardware);
        CollectWmiMemory(wmi, record.hardware);
        CollectWmiDiskData(wmi, record.hardware);
        CollectWmiPatches(wmi, record);
    } else {
        Logger::Warn("{} WMI session unavailable; continuing with native discovery only", kLogPrefix);
    }

    if (record.hardware.processorCount == 0) {
        record.hardware.processorCount = record.hardware.logicalProcessorCount > 0 ? 1U : 0U;
    }
    if (record.hardware.physicalCoreCount == 0) {
        record.hardware.physicalCoreCount = record.hardware.logicalProcessorCount;
    }

    std::ranges::sort(record.networkAdapters, [](const NetworkAdapterInfo& left, const NetworkAdapterInfo& right) {
        return left.friendlyName < right.friendlyName;
    });
    std::ranges::sort(record.localUsers, [](const LocalUserInfo& left, const LocalUserInfo& right) {
        return left.accountName < right.accountName;
    });
    std::ranges::sort(record.patches, [](const PatchInfo& left, const PatchInfo& right) {
        return left.hotfixId < right.hotfixId;
    });

    return record;
}

} // namespace

class AssetDiscoveryImpl final {
public:
    std::atomic<bool> initialized{ false };
    std::atomic<bool> shutdownRequested{ false };
    mutable std::shared_mutex stateMutex;
    std::mutex workerMutex;
    std::condition_variable workerCv;
    std::thread workerThread;
    std::chrono::minutes rediscoveryInterval{ 60 };
    std::optional<AssetRecord> cachedRecord;
};

AssetDiscovery& AssetDiscovery::Instance() {
    static AssetDiscovery instance;
    return instance;
}

AssetDiscovery::AssetDiscovery()
    : m_impl(std::make_unique<AssetDiscoveryImpl>()) {
}

AssetDiscovery::~AssetDiscovery() = default;

bool AssetDiscovery::Initialize() {
    if (m_impl->initialized.load(std::memory_order_acquire)) {
        return true;
    }

    std::unique_lock stateLock(m_impl->stateMutex);
    if (m_impl->initialized.load(std::memory_order_relaxed)) {
        return true;
    }

    if (!AssetDatabase::Instance().Initialize()) {
        Logger::Error("{} failed to initialize AssetDatabase", kLogPrefix);
        return false;
    }
    if (!SoftwareInventory::Instance().Initialize()) {
        Logger::Error("{} failed to initialize SoftwareInventory", kLogPrefix);
        return false;
    }

    m_impl->shutdownRequested.store(false, std::memory_order_release);
    m_impl->initialized.store(true, std::memory_order_release);
    stateLock.unlock();

    if (auto initial = DiscoverNow(); !initial.has_value()) {
        Logger::Warn("{} initial discovery did not persist a record", kLogPrefix);
    }

    m_impl->workerThread = std::thread([this]() {
        while (!m_impl->shutdownRequested.load(std::memory_order_acquire)) {
            std::unique_lock workerLock(m_impl->workerMutex);
            const auto interval = m_impl->rediscoveryInterval;
            const bool stopping = m_impl->workerCv.wait_for(workerLock, interval, [this]() {
                return m_impl->shutdownRequested.load(std::memory_order_acquire);
            });
            workerLock.unlock();

            if (stopping || m_impl->shutdownRequested.load(std::memory_order_acquire)) {
                break;
            }

            if (auto record = DiscoverNow(); !record.has_value()) {
                Logger::Warn("{} scheduled discovery cycle completed with no persisted record", kLogPrefix);
            }
        }
    });

    Logger::Info("{} initialized", kLogPrefix);
    return true;
}

void AssetDiscovery::Shutdown() {
    if (!m_impl->initialized.load(std::memory_order_acquire)) {
        return;
    }

    m_impl->shutdownRequested.store(true, std::memory_order_release);
    m_impl->workerCv.notify_all();

    if (m_impl->workerThread.joinable()) {
        m_impl->workerThread.join();
    }

    std::unique_lock lock(m_impl->stateMutex);
    m_impl->cachedRecord.reset();
    m_impl->initialized.store(false, std::memory_order_release);

    Logger::Info("{} shutdown complete", kLogPrefix);
}

bool AssetDiscovery::IsInitialized() const noexcept {
    return m_impl->initialized.load(std::memory_order_acquire);
}

std::optional<AssetRecord> AssetDiscovery::DiscoverNow() {
    if (!AssetDatabase::Instance().Initialize()) {
        Logger::Error("{} discovery aborted because AssetDatabase initialization failed", kLogPrefix);
        return std::nullopt;
    }

    if (!SoftwareInventory::Instance().Initialize()) {
        Logger::Error("{} discovery aborted because SoftwareInventory initialization failed", kLogPrefix);
        return std::nullopt;
    }

    AssetRecord record = CollectAssetRecord();
    record.installedSoftware = SoftwareInventory::Instance().EnumerateInstalledSoftware();

    if (!AssetDatabase::Instance().UpsertAssetRecord(record)) {
        Logger::Error("{} failed to persist asset record for asset={}", kLogPrefix, record.assetId);
        return std::nullopt;
    }

    if (!SoftwareInventory::Instance().PersistInventory(record.assetId, record.installedSoftware)) {
        Logger::Error("{} failed to persist software inventory for asset={}", kLogPrefix, record.assetId);
    }

    {
        std::unique_lock lock(m_impl->stateMutex);
        m_impl->cachedRecord = record;
    }

    Logger::Info("{} discovery completed for asset={}", kLogPrefix, record.assetId);
    return record;
}

std::optional<AssetRecord> AssetDiscovery::GetCachedRecord() const {
    std::shared_lock lock(m_impl->stateMutex);
    return m_impl->cachedRecord;
}

void AssetDiscovery::SetRediscoveryInterval(std::chrono::minutes interval) {
    if (interval < std::chrono::minutes{ 5 }) {
        interval = std::chrono::minutes{ 5 };
    }

    {
        std::unique_lock lock(m_impl->stateMutex);
        m_impl->rediscoveryInterval = interval;
    }

    m_impl->workerCv.notify_all();
}

std::chrono::minutes AssetDiscovery::GetRediscoveryInterval() const {
    std::shared_lock lock(m_impl->stateMutex);
    return m_impl->rediscoveryInterval;
}

} // namespace ShadowStrike::Products::PhantomEDR::AssetInventory
