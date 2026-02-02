/**
 * ============================================================================
 * ShadowStrike NGAV - SYSTEM INFO IMPLEMENTATION
 * ============================================================================
 *
 * @file SystemInfo.cpp
 * @brief Enterprise-grade system information and environment detection implementation.
 *
 * Production-level implementation competing with CPU-Z, GPU-Z, and enterprise
 * asset management solutions. Provides comprehensive system telemetry, hardware
 * detection, virtualization/sandbox/debugger detection, and machine fingerprinting
 * with full security validation.
 *
 * IMPLEMENTATION FEATURES:
 * ========================
 *
 * - PIMPL pattern for ABI stability
 * - Thread-safe with std::shared_mutex
 * - OS version detection via RtlGetVersion
 * - CPU feature detection via CPUID instruction
 * - Memory/storage/network enumeration
 * - Virtualization detection (hypervisor bit, VM artifacts)
 * - Sandbox detection (Cuckoo/Joe/Any.Run/Windows Sandbox)
 * - Debugger detection (user-mode + kernel-mode)
 * - Machine fingerprinting (BIOS, motherboard, MAC, disks)
 * - Security settings detection (registry-based)
 * - Boot mode and power state detection
 * - Comprehensive statistics (4 atomic counters)
 * - Export functionality (system snapshot)
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @date 2026
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 *
 * LICENSE: Proprietary - ShadowStrike Enterprise License
 * ============================================================================
 */

#include "pch.h"
#include "SystemInfo.hpp"
#include "../../Utils/SystemUtils.hpp"
#include "../../Utils/RegistryUtils.hpp"
#include "../../Utils/NetworkUtils.hpp"
#include "../../Utils/ProcessUtils.hpp"
#include "../../Utils/FileUtils.hpp"
#include "../../Utils/CryptoUtils.hpp"
#include "../../Utils/StringUtils.hpp"
#include "../../Utils/HashUtils.hpp"
#include "../../Utils/Logger.hpp"

#include <Windows.h>
#include <winternl.h>
#include <intrin.h>
#include <powrprof.h>
#include <iphlpapi.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <algorithm>
#include <sstream>
#include <iomanip>
#include <fstream>
#include <filesystem>

#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "powrprof.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

namespace ShadowStrike {
namespace Core {
namespace System {

namespace fs = std::filesystem;

// Log category for this module
static constexpr wchar_t LOG_CATEGORY[] = L"SystemInfo";

// ============================================================================
// NAMESPACE CONSTANTS
// ============================================================================

namespace SystemInfoConstants {
    constexpr uint32_t VERSION_MAJOR = 3;
    constexpr uint32_t VERSION_MINOR = 1;
    constexpr uint32_t VERSION_PATCH = 0;

    // CPUID leaves
    constexpr uint32_t CPUID_VENDOR = 0x00000000;
    constexpr uint32_t CPUID_FEATURES = 0x00000001;
    constexpr uint32_t CPUID_EXTENDED_FEATURES = 0x00000007;
    constexpr uint32_t CPUID_TOPOLOGY = 0x0000000B;
    constexpr uint32_t CPUID_CACHE_INFO = 0x00000004;
    constexpr uint32_t CPUID_BRAND_STRING_1 = 0x80000002;
    constexpr uint32_t CPUID_BRAND_STRING_2 = 0x80000003;
    constexpr uint32_t CPUID_BRAND_STRING_3 = 0x80000004;
    constexpr uint32_t CPUID_HYPERVISOR_VENDOR = 0x40000000;

    // Buffer size limits for security
    constexpr size_t MAX_REG_VALUE_SIZE = 32768;  // 32KB max registry value
    constexpr size_t MAX_PATH_BUFFER = 4096;
    
    // Cloud VM detection endpoints (metadata services)
    constexpr wchar_t AWS_METADATA_IP[] = L"169.254.169.254";
    constexpr wchar_t AZURE_METADATA_IP[] = L"169.254.169.254";
    constexpr wchar_t GCP_METADATA_IP[] = L"169.254.169.254";

    // Virtualization artifacts
    constexpr wchar_t VM_REGISTRY_PATHS[][256] = {
        L"HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0",
        L"HARDWARE\\Description\\System",
        L"SYSTEM\\CurrentControlSet\\Services\\Disk\\Enum"
    };

    // Sandbox artifacts
    constexpr wchar_t SANDBOX_FILES[][256] = {
        L"C:\\analysis\\",
        L"C:\\cuckoosandbox\\",
        L"C:\\sample\\",
        L"C:\\virus\\",
        L"C:\\malware\\"
    };
    
    // Known cloud VM indicators in BIOS/SMBIOS
    constexpr wchar_t CLOUD_BIOS_INDICATORS[][64] = {
        L"amazon", L"aws", L"ec2",
        L"microsoft corporation", L"azure", L"virtual machine",
        L"google", L"googlecloud", L"gce"
    };
}  // namespace SystemInfoConstants

// ============================================================================
// RAII HANDLE WRAPPER
// ============================================================================

/// @brief RAII wrapper for Windows HANDLE
class HandleGuard {
public:
    explicit HandleGuard(HANDLE h = nullptr) noexcept : m_handle(h) {}
    ~HandleGuard() { if (m_handle && m_handle != INVALID_HANDLE_VALUE) CloseHandle(m_handle); }
    
    HandleGuard(const HandleGuard&) = delete;
    HandleGuard& operator=(const HandleGuard&) = delete;
    HandleGuard(HandleGuard&& other) noexcept : m_handle(other.m_handle) { other.m_handle = nullptr; }
    HandleGuard& operator=(HandleGuard&& other) noexcept {
        if (this != &other) {
            if (m_handle && m_handle != INVALID_HANDLE_VALUE) CloseHandle(m_handle);
            m_handle = other.m_handle;
            other.m_handle = nullptr;
        }
        return *this;
    }
    
    [[nodiscard]] HANDLE get() const noexcept { return m_handle; }
    [[nodiscard]] bool valid() const noexcept { return m_handle && m_handle != INVALID_HANDLE_VALUE; }
    [[nodiscard]] explicit operator bool() const noexcept { return valid(); }
    HANDLE release() noexcept { HANDLE h = m_handle; m_handle = nullptr; return h; }
    
private:
    HANDLE m_handle;
};

/// @brief RAII wrapper for registry key HKEY
class RegKeyGuard {
public:
    explicit RegKeyGuard(HKEY h = nullptr) noexcept : m_key(h) {}
    ~RegKeyGuard() { if (m_key) RegCloseKey(m_key); }
    
    RegKeyGuard(const RegKeyGuard&) = delete;
    RegKeyGuard& operator=(const RegKeyGuard&) = delete;
    RegKeyGuard(RegKeyGuard&& other) noexcept : m_key(other.m_key) { other.m_key = nullptr; }
    
    [[nodiscard]] HKEY get() const noexcept { return m_key; }
    [[nodiscard]] explicit operator bool() const noexcept { return m_key != nullptr; }
    HKEY* addressof() noexcept { return &m_key; }
    
private:
    HKEY m_key;
};

// ============================================================================
// NATIVE STRUCTURES (not in public headers)
// ============================================================================

struct SYSTEM_KERNEL_DEBUGGER_INFORMATION {
    BOOLEAN KernelDebuggerEnabled;
    BOOLEAN KernelDebuggerNotPresent;
};

// Storage property query structures (from ntddstor.h)
#ifndef IOCTL_STORAGE_QUERY_PROPERTY
typedef enum _STORAGE_PROPERTY_ID {
    StorageDeviceProperty = 0,
    StorageAdapterProperty,
    StorageDeviceIdProperty,
    StorageDeviceUniqueIdProperty,
    StorageDeviceWriteCacheProperty,
    StorageMiniportProperty,
    StorageAccessAlignmentProperty,
    StorageDeviceSeekPenaltyProperty,
    StorageDeviceTrimProperty
} STORAGE_PROPERTY_ID;

typedef enum _STORAGE_QUERY_TYPE {
    PropertyStandardQuery = 0,
    PropertyExistsQuery,
    PropertyMaskQuery,
    PropertyQueryMaxDefined
} STORAGE_QUERY_TYPE;

typedef struct _STORAGE_PROPERTY_QUERY {
    STORAGE_PROPERTY_ID PropertyId;
    STORAGE_QUERY_TYPE QueryType;
    BYTE AdditionalParameters[1];
} STORAGE_PROPERTY_QUERY;

typedef struct _DEVICE_SEEK_PENALTY_DESCRIPTOR {
    DWORD Version;
    DWORD Size;
    BOOLEAN IncursSeekPenalty;
} DEVICE_SEEK_PENALTY_DESCRIPTOR;

typedef struct _DEVICE_TRIM_DESCRIPTOR {
    DWORD Version;
    DWORD Size;
    BOOLEAN TrimEnabled;
} DEVICE_TRIM_DESCRIPTOR;

// Define storage IOCTL constants if not already defined
#ifndef IOCTL_STORAGE_BASE
#define IOCTL_STORAGE_BASE FILE_DEVICE_MASS_STORAGE
#endif

#ifndef METHOD_BUFFERED
#define METHOD_BUFFERED 0
#endif

#ifndef FILE_ANY_ACCESS
#define FILE_ANY_ACCESS 0
#endif

#ifndef FILE_DEVICE_MASS_STORAGE
#define FILE_DEVICE_MASS_STORAGE 0x0000002d
#endif

#ifndef CTL_CODE
#define CTL_CODE(DeviceType, Function, Method, Access) \
    (((DeviceType) << 16) | ((Access) << 14) | ((Function) << 2) | (Method))
#endif

#define IOCTL_STORAGE_QUERY_PROPERTY CTL_CODE(IOCTL_STORAGE_BASE, 0x0500, METHOD_BUFFERED, FILE_ANY_ACCESS)
#endif

// ============================================================================
// SAFE REGISTRY STRING EXTRACTION
// ============================================================================

/// @brief Safely extract a null-terminated string from registry data
/// @param buffer Raw registry data buffer
/// @param bufferSize Size of buffer in bytes (as returned by RegQueryValueEx)
/// @return Safe, null-terminated wide string
[[nodiscard]] static std::wstring SafeExtractRegString(const BYTE* buffer, DWORD bufferSize) {
    if (!buffer || bufferSize == 0) return {};
    
    // Calculate max characters (bufferSize is in bytes, wchar_t is 2 bytes)
    size_t maxChars = bufferSize / sizeof(wchar_t);
    if (maxChars == 0) return {};
    
    const wchar_t* wstr = reinterpret_cast<const wchar_t*>(buffer);
    
    // Find actual string length (registry strings may not be null-terminated!)
    size_t actualLen = 0;
    for (size_t i = 0; i < maxChars; ++i) {
        if (wstr[i] == L'\0') break;
        actualLen++;
    }
    
    return std::wstring(wstr, actualLen);
}

// ============================================================================
// STATISTICS METHODS
// ============================================================================

void SystemInfoStatistics::Reset() noexcept {
    queriesExecuted.store(0, std::memory_order_relaxed);
    vmDetections.store(0, std::memory_order_relaxed);
    sandboxDetections.store(0, std::memory_order_relaxed);
    debuggerDetections.store(0, std::memory_order_relaxed);
}

// ============================================================================
// EXTERNAL FUNCTION DECLARATIONS
// ============================================================================

extern "C" {
    NTSYSAPI NTSTATUS NTAPI RtlGetVersion(PRTL_OSVERSIONINFOW lpVersionInformation);
}

// ============================================================================
// PIMPL IMPLEMENTATION
// ============================================================================

struct SystemInfo::SystemInfoImpl {
    // Thread synchronization
    mutable std::shared_mutex m_mutex;

    // State
    std::atomic<bool> m_initialized{false};

    // Cached data (static information)
    OSVersion m_osVersion;
    CPUInfo m_cpuInfo;
    MachineFingerprint m_fingerprint;
    mutable std::shared_mutex m_cacheMutex;

    // Statistics (mutable for const methods to update)
    mutable SystemInfoStatistics m_statistics;

    // Constructor
    SystemInfoImpl() = default;

    // ========================================================================
    // OS VERSION DETECTION
    // ========================================================================

    OSVersion DetectOSVersion() {
        OSVersion version;

        try {
            // Use RtlGetVersion for accurate version (bypasses compatibility shims)
            RTL_OSVERSIONINFOEXW osInfo{};
            osInfo.dwOSVersionInfoSize = sizeof(RTL_OSVERSIONINFOEXW);

            if (RtlGetVersion(reinterpret_cast<PRTL_OSVERSIONINFOW>(&osInfo)) == 0) {
                version.majorVersion = osInfo.dwMajorVersion;
                version.minorVersion = osInfo.dwMinorVersion;
                version.buildNumber = osInfo.dwBuildNumber;

                // Determine Windows version
                if (version.majorVersion == 10 && version.minorVersion == 0) {
                    if (version.buildNumber >= 22000) {
                        version.productName = L"Windows 11";
                    } else {
                        version.productName = L"Windows 10";
                    }
                } else if (version.majorVersion == 6 && version.minorVersion == 3) {
                    version.productName = L"Windows 8.1";
                } else if (version.majorVersion == 6 && version.minorVersion == 2) {
                    version.productName = L"Windows 8";
                } else if (version.majorVersion == 6 && version.minorVersion == 1) {
                    version.productName = L"Windows 7";
                }

                version.isServer = (osInfo.wProductType != VER_NT_WORKSTATION);
                version.isWorkstation = !version.isServer;
            }

            // Get display version from registry with RAII and safe string extraction
            RegKeyGuard hKey;
            if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                            L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
                            0, KEY_READ, hKey.addressof()) == ERROR_SUCCESS) {
                BYTE buffer[512];
                DWORD bufferSize = sizeof(buffer);

                if (RegQueryValueExW(hKey.get(), L"DisplayVersion", nullptr, nullptr,
                                    buffer, &bufferSize) == ERROR_SUCCESS) {
                    version.displayVersion = SafeExtractRegString(buffer, bufferSize);
                }

                bufferSize = sizeof(buffer);
                if (RegQueryValueExW(hKey.get(), L"EditionID", nullptr, nullptr,
                                    buffer, &bufferSize) == ERROR_SUCCESS) {
                    version.edition = SafeExtractRegString(buffer, bufferSize);
                }

                // UBR (Update Build Revision)
                DWORD ubr = 0;
                bufferSize = sizeof(ubr);
                if (RegQueryValueExW(hKey.get(), L"UBR", nullptr, nullptr,
                                    reinterpret_cast<LPBYTE>(&ubr),
                                    &bufferSize) == ERROR_SUCCESS) {
                    version.revisionNumber = ubr;
                }
            }

        } catch (const std::exception& e) {
            SS_LOG_ERROR(LOG_CATEGORY, L"OS version detection failed - %hs", e.what());
        }

        return version;
    }

    // ========================================================================
    // CPU DETECTION
    // ========================================================================

    CPUInfo DetectCPU() {
        CPUInfo cpu;

        try {
            int cpuInfo[4] = {0};

            // Get vendor string
            __cpuid(cpuInfo, SystemInfoConstants::CPUID_VENDOR);
            char vendor[13] = {0};
            *reinterpret_cast<int*>(vendor) = cpuInfo[1];
            *reinterpret_cast<int*>(vendor + 4) = cpuInfo[3];
            *reinterpret_cast<int*>(vendor + 8) = cpuInfo[2];
            cpu.vendor = Utils::StringUtils::ToWide(vendor);

            // Get brand string (3 CPUID calls)
            char brand[49] = {0};
            __cpuid(cpuInfo, SystemInfoConstants::CPUID_BRAND_STRING_1);
            memcpy(brand, cpuInfo, sizeof(cpuInfo));
            __cpuid(cpuInfo, SystemInfoConstants::CPUID_BRAND_STRING_2);
            memcpy(brand + 16, cpuInfo, sizeof(cpuInfo));
            __cpuid(cpuInfo, SystemInfoConstants::CPUID_BRAND_STRING_3);
            memcpy(brand + 32, cpuInfo, sizeof(cpuInfo));
            cpu.brand = Utils::StringUtils::ToWide(brand);

            // Get feature flags
            __cpuid(cpuInfo, SystemInfoConstants::CPUID_FEATURES);
            cpu.hasSSE42 = (cpuInfo[2] & (1 << 20)) != 0;
            cpu.hasAESNI = (cpuInfo[2] & (1 << 25)) != 0;
            cpu.hasAVX = (cpuInfo[2] & (1 << 28)) != 0;
            cpu.hasVirtualization = (cpuInfo[2] & (1 << 5)) != 0;  // VMX/SVM
            cpu.hasHypervisorBit = (cpuInfo[2] & (1 << 31)) != 0;  // Hypervisor present

            // Extended features
            __cpuidex(cpuInfo, SystemInfoConstants::CPUID_EXTENDED_FEATURES, 0);
            cpu.hasAVX2 = (cpuInfo[1] & (1 << 5)) != 0;
            cpu.hasAVX512 = (cpuInfo[1] & (1 << 16)) != 0;
            cpu.hasSHA = (cpuInfo[1] & (1 << 29)) != 0;

            // Get core counts using GetLogicalProcessorInformation for accuracy
            SYSTEM_INFO sysInfo;
            GetSystemInfo(&sysInfo);
            cpu.logicalCores = sysInfo.dwNumberOfProcessors;

            // Use GetLogicalProcessorInformation for accurate physical core count
            DWORD bufferSize = 0;
            GetLogicalProcessorInformation(nullptr, &bufferSize);
            if (GetLastError() == ERROR_INSUFFICIENT_BUFFER && bufferSize > 0) {
                std::vector<SYSTEM_LOGICAL_PROCESSOR_INFORMATION> buffer(
                    bufferSize / sizeof(SYSTEM_LOGICAL_PROCESSOR_INFORMATION));
                
                if (GetLogicalProcessorInformation(buffer.data(), &bufferSize)) {
                    uint32_t physicalCores = 0;
                    uint32_t cacheL1 = 0, cacheL2 = 0, cacheL3 = 0;
                    
                    for (const auto& info : buffer) {
                        switch (info.Relationship) {
                            case RelationProcessorCore:
                                physicalCores++;
                                break;
                            case RelationCache:
                                if (info.Cache.Level == 1 && info.Cache.Type == CacheData) {
                                    cacheL1 = info.Cache.Size / 1024;
                                } else if (info.Cache.Level == 2) {
                                    cacheL2 = info.Cache.Size / 1024;
                                } else if (info.Cache.Level == 3) {
                                    cacheL3 = info.Cache.Size / 1024;
                                }
                                break;
                            default:
                                break;
                        }
                    }
                    
                    cpu.physicalCores = (physicalCores > 0) ? physicalCores : cpu.logicalCores;
                    cpu.cacheL1KB = cacheL1;
                    cpu.cacheL2KB = cacheL2;
                    cpu.cacheL3KB = cacheL3;
                }
            }
            
            // Fallback if GetLogicalProcessorInformation failed
            if (cpu.physicalCores == 0) {
                cpu.physicalCores = cpu.logicalCores;  // Conservative: assume no HT
            }

            // Determine architecture
            switch (sysInfo.wProcessorArchitecture) {
                case PROCESSOR_ARCHITECTURE_AMD64:
                    cpu.architecture = ProcessorArchitecture::X64;
                    break;
                case PROCESSOR_ARCHITECTURE_INTEL:
                    cpu.architecture = ProcessorArchitecture::X86;
                    break;
                case PROCESSOR_ARCHITECTURE_ARM:
                    cpu.architecture = ProcessorArchitecture::ARM;
                    break;
                case PROCESSOR_ARCHITECTURE_ARM64:
                    cpu.architecture = ProcessorArchitecture::ARM64;
                    break;
                default:
                    cpu.architecture = ProcessorArchitecture::Unknown;
            }

            // Get CPU frequency from registry with RAII
            RegKeyGuard hKey;
            if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                            L"HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0",
                            0, KEY_READ, hKey.addressof()) == ERROR_SUCCESS) {
                DWORD mhz = 0;
                DWORD size = sizeof(mhz);
                if (RegQueryValueExW(hKey.get(), L"~MHz", nullptr, nullptr,
                                    reinterpret_cast<LPBYTE>(&mhz),
                                    &size) == ERROR_SUCCESS) {
                    cpu.baseMHz = mhz;
                    cpu.maxMHz = mhz;
                }
            }

        } catch (const std::exception& e) {
            SS_LOG_ERROR(LOG_CATEGORY, L"CPU detection failed - %hs", e.what());
        }

        return cpu;
    }

    // ========================================================================
    // MEMORY DETECTION
    // ========================================================================

    MemoryInfo GetMemory() const {
        MemoryInfo memory;

        try {
            MEMORYSTATUSEX memStatus{};
            memStatus.dwLength = sizeof(MEMORYSTATUSEX);

            if (GlobalMemoryStatusEx(&memStatus)) {
                memory.totalPhysicalBytes = memStatus.ullTotalPhys;
                memory.availablePhysicalBytes = memStatus.ullAvailPhys;
                memory.totalVirtualBytes = memStatus.ullTotalVirtual;
                memory.availableVirtualBytes = memStatus.ullAvailVirtual;
                memory.totalPageFileBytes = memStatus.ullTotalPageFile;
                memory.availablePageFileBytes = memStatus.ullAvailPageFile;
                memory.memoryLoad = memStatus.dwMemoryLoad;
            }

        } catch (const std::exception& e) {
            SS_LOG_ERROR(LOG_CATEGORY, L"Memory detection failed - %hs", e.what());
        }

        return memory;
    }

    // ========================================================================
    // STORAGE DETECTION
    // ========================================================================

    // SSD detection using IOCTL_STORAGE_QUERY_PROPERTY (defined inline)
    bool DetectSSDForDrive(const std::wstring& drivePath) const {
        if (drivePath.length() < 2) return false;
        
        std::wstring physicalPath = L"\\\\.\\" + drivePath.substr(0, 2);
        
        HandleGuard hDrive(CreateFileW(physicalPath.c_str(), 0,
                                        FILE_SHARE_READ | FILE_SHARE_WRITE,
                                        nullptr, OPEN_EXISTING, 0, nullptr));
        
        if (!hDrive.valid()) {
            return false;
        }

        STORAGE_PROPERTY_QUERY query{};
        query.PropertyId = StorageDeviceSeekPenaltyProperty;
        query.QueryType = PropertyStandardQuery;

        DEVICE_SEEK_PENALTY_DESCRIPTOR seekPenalty{};
        DWORD bytesReturned = 0;

        if (DeviceIoControl(hDrive.get(), IOCTL_STORAGE_QUERY_PROPERTY,
                           &query, sizeof(query),
                           &seekPenalty, sizeof(seekPenalty),
                           &bytesReturned, nullptr)) {
            return !seekPenalty.IncursSeekPenalty;
        }

        // Fallback: check TRIM support
        query.PropertyId = StorageDeviceTrimProperty;
        DEVICE_TRIM_DESCRIPTOR trimDescriptor{};
        bytesReturned = 0;

        if (DeviceIoControl(hDrive.get(), IOCTL_STORAGE_QUERY_PROPERTY,
                           &query, sizeof(query),
                           &trimDescriptor, sizeof(trimDescriptor),
                           &bytesReturned, nullptr)) {
            return trimDescriptor.TrimEnabled;
        }

        return false;
    }

    std::vector<StorageInfo> GetStorage() const {
        std::vector<StorageInfo> storage;

        try {
            // Enumerate logical drives
            DWORD drives = GetLogicalDrives();

            for (int i = 0; i < 26; i++) {
                if (drives & (1 << i)) {
                    wchar_t driveLetter = L'A' + i;
                    std::wstring drivePath = std::wstring(1, driveLetter) + L":\\";

                    UINT driveType = GetDriveTypeW(drivePath.c_str());
                    if (driveType != DRIVE_FIXED && driveType != DRIVE_REMOVABLE) {
                        continue;
                    }

                    StorageInfo info;
                    info.devicePath = drivePath;
                    info.isRemovable = (driveType == DRIVE_REMOVABLE);
                    info.isSystemDrive = (driveLetter == L'C');

                    // Get capacity
                    ULARGE_INTEGER freeBytesAvailable, totalBytes, freeBytes;
                    if (GetDiskFreeSpaceExW(drivePath.c_str(), &freeBytesAvailable,
                                           &totalBytes, &freeBytes)) {
                        info.totalBytes = totalBytes.QuadPart;
                    }

                    // Real SSD detection using IOCTL
                    info.isSSD = DetectSSDForDrive(drivePath);

                    // Get volume information
                    wchar_t volumeNameBuffer[MAX_PATH + 1] = {0};
                    DWORD volumeSerialNumber = 0;
                    wchar_t fileSystemName[MAX_PATH + 1] = {0};
                    
                    if (GetVolumeInformationW(drivePath.c_str(), volumeNameBuffer, MAX_PATH + 1,
                                              &volumeSerialNumber, nullptr, nullptr,
                                              fileSystemName, MAX_PATH + 1)) {
                        info.model = volumeNameBuffer;
                        wchar_t serialBuf[32];
                        swprintf_s(serialBuf, L"%08X", volumeSerialNumber);
                        info.serialNumber = serialBuf;
                    }

                    storage.push_back(info);
                }
            }

        } catch (const std::exception& e) {
            SS_LOG_ERROR(LOG_CATEGORY, L"Storage detection failed - %hs", e.what());
        }

        return storage;
    }

    // ========================================================================
    // NETWORK DETECTION
    // ========================================================================

    std::vector<NetworkInterfaceInfo> GetNetwork() const {
        std::vector<NetworkInterfaceInfo> network;

        try {
            ULONG bufferSize = 15000;
            std::vector<BYTE> buffer(bufferSize);
            PIP_ADAPTER_ADDRESSES pAddresses = reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buffer.data());

            // First call to get required buffer size
            DWORD result = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX,
                                                nullptr, pAddresses, &bufferSize);
            
            if (result == ERROR_BUFFER_OVERFLOW) {
                buffer.resize(bufferSize);
                pAddresses = reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buffer.data());
                result = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX,
                                              nullptr, pAddresses, &bufferSize);
            }

            if (result == ERROR_SUCCESS) {
                for (auto pCurrAddresses = pAddresses; pCurrAddresses != nullptr;
                     pCurrAddresses = pCurrAddresses->Next) {

                    NetworkInterfaceInfo info;
                    // AdapterName is PCHAR (narrow string), convert to wide
                    info.name = Utils::StringUtils::ToWide(pCurrAddresses->AdapterName);
                    info.description = pCurrAddresses->Description;  // Already wide
                    info.isUp = (pCurrAddresses->OperStatus == IfOperStatusUp);
                    info.isLoopback = (pCurrAddresses->IfType == IF_TYPE_SOFTWARE_LOOPBACK);

                    // Detect virtual adapters
                    info.isVirtual = IsVirtualNetworkAdapter(pCurrAddresses);

                    // MAC address with proper formatting
                    if (pCurrAddresses->PhysicalAddressLength > 0) {
                        std::wstringstream macStream;
                        for (DWORD i = 0; i < pCurrAddresses->PhysicalAddressLength; i++) {
                            if (i > 0) macStream << L"-";
                            macStream << std::hex << std::uppercase << std::setw(2) << std::setfill(L'0')
                                     << static_cast<int>(pCurrAddresses->PhysicalAddress[i]);
                        }
                        info.macAddress = macStream.str();
                    }

                    // IP addresses
                    for (auto pUnicast = pCurrAddresses->FirstUnicastAddress;
                         pUnicast != nullptr; pUnicast = pUnicast->Next) {
                        wchar_t ipString[46];
                        DWORD ipStringLength = 46;

                        if (pUnicast->Address.lpSockaddr->sa_family == AF_INET) {
                            if (WSAAddressToStringW(pUnicast->Address.lpSockaddr,
                                                   pUnicast->Address.iSockaddrLength,
                                                   nullptr, ipString, &ipStringLength) == 0) {
                                info.ipv4Addresses.push_back(ipString);
                            }
                        } else if (pUnicast->Address.lpSockaddr->sa_family == AF_INET6) {
                            if (WSAAddressToStringW(pUnicast->Address.lpSockaddr,
                                                   pUnicast->Address.iSockaddrLength,
                                                   nullptr, ipString, &ipStringLength) == 0) {
                                info.ipv6Addresses.push_back(ipString);
                            }
                        }
                    }

                    // Speed
                    info.speedMbps = pCurrAddresses->TransmitLinkSpeed / 1000000;

                    network.push_back(info);
                }
            }

        } catch (const std::exception& e) {
            SS_LOG_ERROR(LOG_CATEGORY, L"Network detection failed - %hs", e.what());
        }

        return network;
    }

    // Detect virtual network adapters (VM, VPN, etc.)
    bool IsVirtualNetworkAdapter(PIP_ADAPTER_ADDRESSES adapter) const {
        if (!adapter) return false;

        // Check adapter description for known virtual adapter patterns
        std::wstring desc = adapter->Description;
        
        // Convert to lowercase for comparison
        std::transform(desc.begin(), desc.end(), desc.begin(), ::towlower);

        // VM adapter patterns
        static const wchar_t* virtualPatterns[] = {
            L"vmware", L"virtualbox", L"hyper-v", L"virtual",
            L"vnic", L"tap-", L"tunnel", L"vpn", L"veth",
            L"docker", L"podman", L"wsl"
        };

        for (const auto& pattern : virtualPatterns) {
            if (desc.find(pattern) != std::wstring::npos) {
                return true;
            }
        }

        // Check MAC address OUI for known virtual vendors
        if (adapter->PhysicalAddressLength >= 3) {
            // VMware: 00:50:56, 00:0C:29, 00:05:69
            // VirtualBox: 08:00:27
            // Hyper-V: 00:15:5D
            // Parallels: 00:1C:42
            const BYTE* mac = adapter->PhysicalAddress;
            
            if ((mac[0] == 0x00 && mac[1] == 0x50 && mac[2] == 0x56) ||  // VMware
                (mac[0] == 0x00 && mac[1] == 0x0C && mac[2] == 0x29) ||  // VMware
                (mac[0] == 0x00 && mac[1] == 0x05 && mac[2] == 0x69) ||  // VMware
                (mac[0] == 0x08 && mac[1] == 0x00 && mac[2] == 0x27) ||  // VirtualBox
                (mac[0] == 0x00 && mac[1] == 0x15 && mac[2] == 0x5D) ||  // Hyper-V
                (mac[0] == 0x00 && mac[1] == 0x1C && mac[2] == 0x42)) {  // Parallels
                return true;
            }
        }

        return false;
    }

    // ========================================================================
    // VIRTUALIZATION DETECTION
    // ========================================================================

    VirtualizationInfo DetectVirtualization() const {
        VirtualizationInfo info;

        try {
            double confidence = 0.0;
            std::vector<std::wstring> indicators;

            // Check hypervisor bit via CPUID
            int cpuInfo[4] = {0};
            __cpuid(cpuInfo, 1);
            bool hypervisorBit = (cpuInfo[2] & (1 << 31)) != 0;

            if (hypervisorBit) {
                indicators.push_back(L"CPUID hypervisor bit set");
                confidence += 0.8;

                // Get hypervisor vendor
                __cpuid(cpuInfo, 0x40000000);
                char vendor[13] = {0};
                *reinterpret_cast<int*>(vendor) = cpuInfo[1];
                *reinterpret_cast<int*>(vendor + 4) = cpuInfo[2];
                *reinterpret_cast<int*>(vendor + 8) = cpuInfo[3];

                std::string vendorStr = vendor;
                if (vendorStr.find("VMwareVMware") != std::string::npos) {
                    info.type = VirtualizationType::VMware;
                    info.hypervisorName = L"VMware";
                } else if (vendorStr.find("Microsoft Hv") != std::string::npos) {
                    info.type = VirtualizationType::HyperV;
                    info.hypervisorName = L"Hyper-V";
                } else if (vendorStr.find("KVMKVMKVM") != std::string::npos) {
                    info.type = VirtualizationType::KVM;
                    info.hypervisorName = L"KVM";
                } else if (vendorStr.find("XenVMMXenVMM") != std::string::npos) {
                    info.type = VirtualizationType::Xen;
                    info.hypervisorName = L"Xen";
                } else if (vendorStr.find("TCGTCGTCGTCG") != std::string::npos) {
                    info.type = VirtualizationType::QEMU;
                    info.hypervisorName = L"QEMU";
                }
            }

            // Check registry artifacts with RAII
            for (const auto& regPath : SystemInfoConstants::VM_REGISTRY_PATHS) {
                RegKeyGuard hKey;
                if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, regPath, 0, KEY_READ, hKey.addressof()) == ERROR_SUCCESS) {
                    BYTE buffer[512];
                    DWORD bufferSize = sizeof(buffer);

                    if (RegQueryValueExW(hKey.get(), L"Identifier", nullptr, nullptr,
                                        buffer, &bufferSize) == ERROR_SUCCESS) {
                        std::wstring identifier = SafeExtractRegString(buffer, bufferSize);
                        std::transform(identifier.begin(), identifier.end(),
                                     identifier.begin(), ::towlower);

                        if (identifier.find(L"vmware") != std::wstring::npos) {
                            info.type = VirtualizationType::VMware;
                            indicators.push_back(L"VMware registry artifact");
                            confidence += 0.3;
                        } else if (identifier.find(L"vbox") != std::wstring::npos ||
                                  identifier.find(L"virtualbox") != std::wstring::npos) {
                            info.type = VirtualizationType::VirtualBox;
                            indicators.push_back(L"VirtualBox registry artifact");
                            confidence += 0.3;
                        } else if (identifier.find(L"qemu") != std::wstring::npos) {
                            info.type = VirtualizationType::QEMU;
                            indicators.push_back(L"QEMU registry artifact");
                            confidence += 0.3;
                        }
                    }
                }
            }

            // Check for VM-specific files (use std::error_code to avoid exceptions)
            std::error_code ec;
            if (fs::exists(L"C:\\Windows\\System32\\drivers\\vmmouse.sys", ec) ||
                fs::exists(L"C:\\Windows\\System32\\drivers\\vmhgfs.sys", ec)) {
                info.type = VirtualizationType::VMware;
                indicators.push_back(L"VMware driver files");
                confidence += 0.2;
            }

            if (fs::exists(L"C:\\Windows\\System32\\drivers\\VBoxMouse.sys", ec) ||
                fs::exists(L"C:\\Windows\\System32\\drivers\\VBoxGuest.sys", ec)) {
                info.type = VirtualizationType::VirtualBox;
                indicators.push_back(L"VirtualBox driver files");
                confidence += 0.2;
            }

            // Cloud VM detection (AWS, Azure, GCP) - should NOT count as suspicious
            CloudVMType cloudType = DetectCloudVMType();
            if (cloudType != CloudVMType::None) {
                info.isCloudVM = true;
                info.cloudType = cloudType;
                // Cloud VMs are legitimate - don't treat as evasion
                switch (cloudType) {
                    case CloudVMType::AWS:
                        indicators.push_back(L"AWS EC2 instance (legitimate cloud)");
                        break;
                    case CloudVMType::Azure:
                        indicators.push_back(L"Azure VM (legitimate cloud)");
                        break;
                    case CloudVMType::GCP:
                        indicators.push_back(L"Google Cloud VM (legitimate cloud)");
                        break;
                    default:
                        break;
                }
            }

            info.isVirtualized = (confidence >= 0.5);
            info.confidence = std::min(confidence, 1.0);
            info.indicators = indicators;

            if (info.isVirtualized && !info.isCloudVM) {
                m_statistics.vmDetections.fetch_add(1, std::memory_order_relaxed);
            }

        } catch (const std::exception& e) {
            SS_LOG_ERROR(LOG_CATEGORY, L"Virtualization detection failed - %hs", e.what());
        }

        return info;
    }

    // Detect cloud VM type (AWS, Azure, GCP)
    CloudVMType DetectCloudVMType() const {
        // Check BIOS/SMBIOS strings for cloud vendor signatures
        RegKeyGuard hKey;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                         L"HARDWARE\\DESCRIPTION\\System\\BIOS",
                         0, KEY_READ, hKey.addressof()) == ERROR_SUCCESS) {
            BYTE buffer[512];
            DWORD bufferSize = sizeof(buffer);
            
            // Check SystemManufacturer
            if (RegQueryValueExW(hKey.get(), L"SystemManufacturer", nullptr, nullptr,
                                buffer, &bufferSize) == ERROR_SUCCESS) {
                std::wstring manufacturer = SafeExtractRegString(buffer, bufferSize);
                std::transform(manufacturer.begin(), manufacturer.end(),
                             manufacturer.begin(), ::towlower);
                
                if (manufacturer.find(L"amazon") != std::wstring::npos ||
                    manufacturer.find(L"aws") != std::wstring::npos) {
                    return CloudVMType::AWS;
                }
                if (manufacturer.find(L"microsoft") != std::wstring::npos) {
                    // Check if Azure specifically
                    bufferSize = sizeof(buffer);
                    if (RegQueryValueExW(hKey.get(), L"SystemProductName", nullptr, nullptr,
                                        buffer, &bufferSize) == ERROR_SUCCESS) {
                        std::wstring product = SafeExtractRegString(buffer, bufferSize);
                        std::transform(product.begin(), product.end(),
                                     product.begin(), ::towlower);
                        if (product.find(L"virtual machine") != std::wstring::npos) {
                            return CloudVMType::Azure;
                        }
                    }
                }
                if (manufacturer.find(L"google") != std::wstring::npos) {
                    return CloudVMType::GCP;
                }
            }
        }

        // Check for cloud-specific services/files
        std::error_code ec;
        if (fs::exists(L"C:\\Program Files\\Amazon\\SSM", ec)) {
            return CloudVMType::AWS;
        }
        if (fs::exists(L"C:\\WindowsAzure", ec)) {
            return CloudVMType::Azure;
        }
        if (fs::exists(L"C:\\Program Files\\Google\\Compute Engine", ec)) {
            return CloudVMType::GCP;
        }

        return CloudVMType::None;
    }

    // ========================================================================
    // SANDBOX DETECTION
    // ========================================================================

    SandboxInfo DetectSandbox() const {
        SandboxInfo info;

        try {
            double confidence = 0.0;
            std::vector<std::wstring> indicators;
            std::error_code ec;

            // Check for sandbox-specific files
            for (const auto& path : SystemInfoConstants::SANDBOX_FILES) {
                if (fs::exists(path, ec)) {
                    indicators.push_back(L"Sandbox directory found: " + std::wstring(path));
                    confidence += 0.4;
                }
            }

            // Check for Cuckoo Sandbox
            if (fs::exists(L"C:\\cuckoo\\", ec) || fs::exists(L"C:\\analysis\\", ec)) {
                info.type = SandboxType::CuckooSandbox;
                indicators.push_back(L"Cuckoo Sandbox artifacts");
                confidence += 0.5;
            }

            // Check for Joe Sandbox with RAII
            RegKeyGuard hKey;
            if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                            L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion",
                            0, KEY_READ, hKey.addressof()) == ERROR_SUCCESS) {
                BYTE buffer[512];
                DWORD bufferSize = sizeof(buffer);
                if (RegQueryValueExW(hKey.get(), L"ProductId", nullptr, nullptr,
                                    buffer, &bufferSize) == ERROR_SUCCESS) {
                    std::wstring productId = SafeExtractRegString(buffer, bufferSize);
                    if (productId.find(L"55274-640-2673064-23950") != std::wstring::npos) {
                        info.type = SandboxType::JoeSandbox;
                        indicators.push_back(L"Joe Sandbox product ID");
                        confidence += 0.6;
                    }
                }
            }

            // Check for Windows Sandbox
            if (fs::exists(L"C:\\ProgramData\\Microsoft\\Windows\\Containers", ec)) {
                info.type = SandboxType::WindowsSandbox;
                indicators.push_back(L"Windows Sandbox container path");
                confidence += 0.3;
            }

            // Timing attack detection with adjustable threshold
            // Use multiple samples to reduce false positives
            static constexpr int TIMING_SAMPLES = 3;
            static constexpr int64_t SLEEP_MS = 100;
            static constexpr int64_t MIN_THRESHOLD = 70;  // 30% tolerance below
            static constexpr int64_t MAX_THRESHOLD = 150; // 50% tolerance above

            int timingAnomalies = 0;
            for (int i = 0; i < TIMING_SAMPLES; ++i) {
                auto start = std::chrono::high_resolution_clock::now();
                Sleep(static_cast<DWORD>(SLEEP_MS));
                auto end = std::chrono::high_resolution_clock::now();
                auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();

                if (elapsed < MIN_THRESHOLD || elapsed > MAX_THRESHOLD) {
                    timingAnomalies++;
                }
            }

            // Only flag if majority of samples are anomalous (reduces FP from system load)
            if (timingAnomalies >= 2) {
                indicators.push_back(L"Abnormal timing detected");
                confidence += 0.2;
            }

            // Check for low uptime (use higher threshold - 30 min to reduce FP)
            static constexpr ULONGLONG LOW_UPTIME_THRESHOLD_MS = 30 * 60 * 1000; // 30 minutes
            ULONGLONG uptime = GetTickCount64();
            if (uptime < LOW_UPTIME_THRESHOLD_MS) {
                // Could be fresh boot or sandbox - low weight
                indicators.push_back(L"Low system uptime (possible fresh boot)");
                confidence += 0.05;  // Reduced weight - fresh boot is common
            }

            info.isSandboxed = (confidence >= 0.4);
            info.confidence = std::min(confidence, 1.0);
            info.indicators = indicators;

            if (info.isSandboxed) {
                m_statistics.sandboxDetections.fetch_add(1, std::memory_order_relaxed);
            }

        } catch (const std::exception& e) {
            SS_LOG_ERROR(LOG_CATEGORY, L"Sandbox detection failed - %hs", e.what());
        }

        return info;
    }

    // ========================================================================
    // DEBUGGER DETECTION
    // ========================================================================

    DebuggerInfo DetectDebugger() const {
        DebuggerInfo info;

        try {
            // User-mode debugger - use :: prefix for Windows API to avoid ambiguity
            info.isDebuggerPresent = (::IsDebuggerPresent() != 0);

            // Remote debugger
            BOOL remoteDebugger = FALSE;
            CheckRemoteDebuggerPresent(GetCurrentProcess(), &remoteDebugger);
            info.isRemoteDebuggerPresent = (remoteDebugger != 0);

            // Kernel debugger (via NtQuerySystemInformation)
            typedef NTSTATUS (NTAPI *NtQuerySystemInformation_t)(
                ULONG SystemInformationClass,
                PVOID SystemInformation,
                ULONG SystemInformationLength,
                PULONG ReturnLength
            );

            HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
            if (hNtdll) {
                auto NtQuerySystemInformation = reinterpret_cast<NtQuerySystemInformation_t>(
                    GetProcAddress(hNtdll, "NtQuerySystemInformation"));

                if (NtQuerySystemInformation) {
                    SYSTEM_KERNEL_DEBUGGER_INFORMATION kernelDebugInfo{};
                    ULONG returnLength = 0;

                    if (NtQuerySystemInformation(35, &kernelDebugInfo,
                                                sizeof(kernelDebugInfo),
                                                &returnLength) == 0) {
                        info.isKernelDebuggerPresent = kernelDebugInfo.KernelDebuggerEnabled != 0;
                    }
                }
            }

            if (info.isDebuggerPresent || info.isRemoteDebuggerPresent ||
                info.isKernelDebuggerPresent) {
                m_statistics.debuggerDetections.fetch_add(1, std::memory_order_relaxed);
            }

        } catch (const std::exception& e) {
            SS_LOG_ERROR(LOG_CATEGORY, L"Debugger detection failed - %hs", e.what());
        }

        return info;
    }

    // ========================================================================
    // MACHINE FINGERPRINTING
    // ========================================================================

    MachineFingerprint GenerateFingerprint() {
        MachineFingerprint fingerprint;

        try {
            // Get BIOS serial from registry with RAII
            RegKeyGuard hKey;
            if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                            L"HARDWARE\\DESCRIPTION\\System\\BIOS",
                            0, KEY_READ, hKey.addressof()) == ERROR_SUCCESS) {
                BYTE buffer[512];
                DWORD bufferSize = sizeof(buffer);
                if (RegQueryValueExW(hKey.get(), L"SystemSerialNumber", nullptr, nullptr,
                                    buffer, &bufferSize) == ERROR_SUCCESS) {
                    fingerprint.biosSerial = SafeExtractRegString(buffer, bufferSize);
                }

                bufferSize = sizeof(buffer);
                if (RegQueryValueExW(hKey.get(), L"BaseBoardSerialNumber", nullptr, nullptr,
                                    buffer, &bufferSize) == ERROR_SUCCESS) {
                    fingerprint.motherboardSerial = SafeExtractRegString(buffer, bufferSize);
                }
            }

            // Get MAC addresses and disk serials
            auto network = GetNetwork();
            for (const auto& iface : network) {
                if (!iface.macAddress.empty() && !iface.isLoopback && !iface.isVirtual) {
                    fingerprint.macAddresses.push_back(iface.macAddress);
                }
            }

            // Get disk serials
            auto storage = GetStorage();
            for (const auto& disk : storage) {
                if (!disk.serialNumber.empty()) {
                    fingerprint.diskSerials.push_back(disk.serialNumber);
                }
            }

            // Get installation ID
            RegKeyGuard hCryptoKey;
            if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                            L"SOFTWARE\\Microsoft\\Cryptography",
                            0, KEY_READ, hCryptoKey.addressof()) == ERROR_SUCCESS) {
                BYTE buffer[512];
                DWORD bufferSize = sizeof(buffer);
                if (RegQueryValueExW(hCryptoKey.get(), L"MachineGuid", nullptr, nullptr,
                                    buffer, &bufferSize) == ERROR_SUCCESS) {
                    fingerprint.installationId = SafeExtractRegString(buffer, bufferSize);
                    fingerprint.machineId = fingerprint.installationId;
                }
            }

            // Generate hardware fingerprint hash using SHA-256
            std::wstring combinedData = fingerprint.biosSerial +
                                       fingerprint.motherboardSerial +
                                       fingerprint.installationId;
            for (const auto& mac : fingerprint.macAddresses) {
                combinedData += mac;
            }
            for (const auto& serial : fingerprint.diskSerials) {
                combinedData += serial;
            }

            // Use SHA-256 via Hasher class for cryptographically secure fingerprint
            std::string narrowCombined = Utils::StringUtils::ToNarrow(combinedData);
            
            Utils::HashUtils::Hasher hasher(Utils::HashUtils::Algorithm::SHA256);
            if (hasher.Init()) {
                if (hasher.Update(narrowCombined.data(), narrowCombined.size())) {
                    std::string hexHash;
                    if (hasher.FinalHex(hexHash, false)) {
                        fingerprint.hardwareFingerprint = Utils::StringUtils::ToWide(hexHash);
                    }
                }
            }
            
            // Fallback if hashing fails - use std::hash (less secure but functional)
            if (fingerprint.hardwareFingerprint.empty()) {
                size_t hash = std::hash<std::wstring>{}(combinedData);
                std::wstringstream hashStream;
                hashStream << std::hex << hash;
                fingerprint.hardwareFingerprint = hashStream.str();
            }

        } catch (const std::exception& e) {
            SS_LOG_ERROR(LOG_CATEGORY, L"Fingerprinting failed - %hs", e.what());
        }

        return fingerprint;
    }

    // ========================================================================
    // SECURITY SETTINGS
    // ========================================================================

    SecuritySettings GetSecuritySettings() const {
        SecuritySettings settings;

        try {
            // Secure Boot with RAII
            RegKeyGuard hSecureBootKey;
            if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                            L"SYSTEM\\CurrentControlSet\\Control\\SecureBoot\\State",
                            0, KEY_READ, hSecureBootKey.addressof()) == ERROR_SUCCESS) {
                DWORD secureBootEnabled = 0;
                DWORD size = sizeof(secureBootEnabled);
                if (RegQueryValueExW(hSecureBootKey.get(), L"UEFISecureBootEnabled", nullptr, nullptr,
                                    reinterpret_cast<LPBYTE>(&secureBootEnabled),
                                    &size) == ERROR_SUCCESS) {
                    settings.isSecureBoot = (secureBootEnabled != 0);
                }
            }

            // BitLocker
            RegKeyGuard hBitLockerKey;
            if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                            L"SYSTEM\\CurrentControlSet\\Control\\BitLockerStatus",
                            0, KEY_READ, hBitLockerKey.addressof()) == ERROR_SUCCESS) {
                settings.isBitLockerEnabled = true;
            }

            // UAC
            RegKeyGuard hPoliciesKey;
            if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                            L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
                            0, KEY_READ, hPoliciesKey.addressof()) == ERROR_SUCCESS) {
                DWORD enableLUA = 0;
                DWORD size = sizeof(enableLUA);
                if (RegQueryValueExW(hPoliciesKey.get(), L"EnableLUA", nullptr, nullptr,
                                    reinterpret_cast<LPBYTE>(&enableLUA),
                                    &size) == ERROR_SUCCESS) {
                    settings.isUACEnabled = (enableLUA != 0);
                }

                DWORD consentPromptBehaviorAdmin = 0;
                size = sizeof(consentPromptBehaviorAdmin);
                if (RegQueryValueExW(hPoliciesKey.get(), L"ConsentPromptBehaviorAdmin", nullptr, nullptr,
                                    reinterpret_cast<LPBYTE>(&consentPromptBehaviorAdmin),
                                    &size) == ERROR_SUCCESS) {
                    settings.uacLevel = consentPromptBehaviorAdmin;
                }
            }

            // DEP (Data Execution Prevention) - GetSystemDEPPolicy returns DEP_SYSTEM_POLICY_TYPE
            // OptIn (2) means DEP is enabled for system components only
            // OptOut (3) means DEP is enabled for all applications except those with opt-out
            // AlwaysOn (1) means DEP is always enabled
            // GetSystemDEPPolicy returns the Windows DEP_SYSTEM_POLICY_TYPE (different namespace)
            auto depPolicy = static_cast<int>(GetSystemDEPPolicy());
            settings.isDEPEnabled = (depPolicy != 0);  // 0 = AlwaysOff

            // ASLR detection - check kernel memory layout randomization
            settings.isASLREnabled = DetectASLREnabled();

            // SMEP detection - Supervisor Mode Execution Prevention
            settings.isSMEPEnabled = DetectSMEPEnabled();

            // Windows Defender
            RegKeyGuard hDefenderKey;
            if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                            L"SOFTWARE\\Microsoft\\Windows Defender",
                            0, KEY_READ, hDefenderKey.addressof()) == ERROR_SUCCESS) {
                DWORD disableAntiSpyware = 1;
                DWORD size = sizeof(disableAntiSpyware);
                if (RegQueryValueExW(hDefenderKey.get(), L"DisableAntiSpyware", nullptr, nullptr,
                                    reinterpret_cast<LPBYTE>(&disableAntiSpyware),
                                    &size) == ERROR_SUCCESS) {
                    settings.isDefenderEnabled = (disableAntiSpyware == 0);
                } else {
                    settings.isDefenderEnabled = true;  // Enabled by default
                }
            }

            // Firewall
            RegKeyGuard hFirewallKey;
            if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                            L"SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\StandardProfile",
                            0, KEY_READ, hFirewallKey.addressof()) == ERROR_SUCCESS) {
                DWORD enableFirewall = 0;
                DWORD size = sizeof(enableFirewall);
                if (RegQueryValueExW(hFirewallKey.get(), L"EnableFirewall", nullptr, nullptr,
                                    reinterpret_cast<LPBYTE>(&enableFirewall),
                                    &size) == ERROR_SUCCESS) {
                    settings.isFirewallEnabled = (enableFirewall != 0);
                }
            }

            // Credential Guard
            RegKeyGuard hLsaKey;
            if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                            L"SYSTEM\\CurrentControlSet\\Control\\Lsa",
                            0, KEY_READ, hLsaKey.addressof()) == ERROR_SUCCESS) {
                DWORD lsaCfgFlags = 0;
                DWORD size = sizeof(lsaCfgFlags);
                if (RegQueryValueExW(hLsaKey.get(), L"LsaCfgFlags", nullptr, nullptr,
                                    reinterpret_cast<LPBYTE>(&lsaCfgFlags),
                                    &size) == ERROR_SUCCESS) {
                    settings.isCredentialGuard = ((lsaCfgFlags & 0x1) != 0);
                }
            }

        } catch (const std::exception& e) {
            SS_LOG_ERROR(LOG_CATEGORY, L"Security settings detection failed - %hs", e.what());
        }

        return settings;
    }

    // ASLR detection - check if ASLR is enabled via NtQuerySystemInformation
    bool DetectASLREnabled() const {
        // On modern Windows (8+), ASLR is always enabled at the system level
        // Check individual process mitigation policies
        
        typedef BOOL (WINAPI *GetProcessMitigationPolicy_t)(
            HANDLE, PROCESS_MITIGATION_POLICY, PVOID, SIZE_T);
        
        HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
        if (!hKernel32) return true;  // Assume enabled on modern Windows
        
        auto pGetProcessMitigationPolicy = reinterpret_cast<GetProcessMitigationPolicy_t>(
            GetProcAddress(hKernel32, "GetProcessMitigationPolicy"));
        
        if (!pGetProcessMitigationPolicy) {
            // API not available (pre-Windows 8) - check registry fallback
            RegKeyGuard hKey;
            if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                            L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management",
                            0, KEY_READ, hKey.addressof()) == ERROR_SUCCESS) {
                DWORD moveImages = 0;
                DWORD size = sizeof(moveImages);
                if (RegQueryValueExW(hKey.get(), L"MoveImages", nullptr, nullptr,
                                    reinterpret_cast<LPBYTE>(&moveImages),
                                    &size) == ERROR_SUCCESS) {
                    // 0xFFFFFFFF = always on, 0 = opt-in, -1 = always off
                    return (moveImages != 0);
                }
            }
            return true;  // Default enabled
        }
        
        // Check ASLR policy for current process
        PROCESS_MITIGATION_ASLR_POLICY aslrPolicy{};
        if (pGetProcessMitigationPolicy(GetCurrentProcess(), 
                                        ProcessASLRPolicy, 
                                        &aslrPolicy, 
                                        sizeof(aslrPolicy))) {
            return aslrPolicy.EnableBottomUpRandomization || 
                   aslrPolicy.EnableHighEntropy;
        }
        
        return true;  // Assume enabled by default on modern Windows
    }

    // SMEP detection via CPUID
    bool DetectSMEPEnabled() const {
        // SMEP is indicated by CPUID leaf 7, EBX bit 7
        // However, OS must also enable it (CR4.SMEP)
        
        int cpuInfo[4] = {0};
        __cpuidex(cpuInfo, 7, 0);
        
        bool cpuSupportsSmep = (cpuInfo[1] & (1 << 7)) != 0;
        
        if (!cpuSupportsSmep) {
            return false;  // CPU doesn't support SMEP
        }
        
        // If CPU supports it, Windows 8+ enables it by default
        // We can't directly read CR4 from user mode, but we can infer
        // from OS version
        
        RTL_OSVERSIONINFOEXW osInfo{};
        osInfo.dwOSVersionInfoSize = sizeof(RTL_OSVERSIONINFOEXW);
        if (RtlGetVersion(reinterpret_cast<PRTL_OSVERSIONINFOW>(&osInfo)) == 0) {
            // Windows 8+ (6.2+) enables SMEP if supported
            if (osInfo.dwMajorVersion > 6 || 
                (osInfo.dwMajorVersion == 6 && osInfo.dwMinorVersion >= 2)) {
                return true;
            }
        }
        
        return false;
    }

    // ========================================================================
    // BOOT MODE & POWER STATE
    // ========================================================================

    BootMode GetBootMode() const {
        try {
            // Check Safe Mode via GetSystemMetrics
            int bootMode = GetSystemMetrics(SM_CLEANBOOT);
            if (bootMode) {
                switch (bootMode) {
                    case 1: return BootMode::SafeMode;
                    case 2: return BootMode::SafeModeWithNetworking;
                    default: return BootMode::Normal;
                }
            }
        } catch (const std::exception& e) {
            SS_LOG_ERROR(LOG_CATEGORY, L"Boot mode detection failed - %hs", e.what());
        }

        return BootMode::Normal;
    }

    PowerState GetPowerState() const {
        try {
            SYSTEM_POWER_STATUS powerStatus;
            if (GetSystemPowerStatus(&powerStatus)) {
                if (powerStatus.ACLineStatus == 1) {
                    return PowerState::ACPower;
                } else if (powerStatus.ACLineStatus == 0) {
                    if (powerStatus.BatteryFlag & 8) {
                        return PowerState::BatteryCritical;
                    } else if (powerStatus.BatteryLifePercent < 20) {
                        return PowerState::BatteryLow;
                    } else {
                        return PowerState::Battery;
                    }
                }
            }
        } catch (const std::exception& e) {
            SS_LOG_ERROR(LOG_CATEGORY, L"Power state detection failed - %hs", e.what());
        }

        return PowerState::Unknown;
    }
};

// ============================================================================
// SINGLETON IMPLEMENTATION
// ============================================================================

std::atomic<bool> SystemInfo::s_instanceCreated{false};

SystemInfo& SystemInfo::Instance() noexcept {
    static SystemInfo instance;
    s_instanceCreated.store(true, std::memory_order_release);
    return instance;
}

bool SystemInfo::HasInstance() noexcept {
    return s_instanceCreated.load(std::memory_order_acquire);
}

// ============================================================================
// LIFECYCLE
// ============================================================================

SystemInfo::SystemInfo()
    : m_impl(std::make_unique<SystemInfoImpl>())
{
    SS_LOG_INFO(LOG_CATEGORY, L"Constructor called");
}

SystemInfo::~SystemInfo() {
    Shutdown();
    SS_LOG_INFO(LOG_CATEGORY, L"Destructor called");
}

bool SystemInfo::Initialize() {
    std::unique_lock<std::shared_mutex> lock(m_impl->m_mutex);

    if (m_impl->m_initialized.load(std::memory_order_acquire)) {
        SS_LOG_WARN(LOG_CATEGORY, L"Already initialized");
        return true;
    }

    try {
        // Cache static information
        {
            std::unique_lock<std::shared_mutex> cacheLock(m_impl->m_cacheMutex);
            m_impl->m_osVersion = m_impl->DetectOSVersion();
            m_impl->m_cpuInfo = m_impl->DetectCPU();
            m_impl->m_fingerprint = m_impl->GenerateFingerprint();
        }

        m_impl->m_initialized.store(true, std::memory_order_release);

        SS_LOG_INFO(LOG_CATEGORY, L"Initialized successfully - OS: %ls, CPU: %ls, Cores: %u",
                   m_impl->m_osVersion.productName.c_str(),
                   m_impl->m_cpuInfo.brand.c_str(),
                   m_impl->m_cpuInfo.logicalCores);
        return true;

    } catch (const std::exception& e) {
        SS_LOG_ERROR(LOG_CATEGORY, L"Initialization failed - %hs", e.what());
        return false;
    }
}

void SystemInfo::Shutdown() noexcept {
    std::unique_lock<std::shared_mutex> lock(m_impl->m_mutex);

    if (!m_impl->m_initialized.load(std::memory_order_acquire)) {
        return;
    }

    try {
        m_impl->m_initialized.store(false, std::memory_order_release);
        SS_LOG_INFO(LOG_CATEGORY, L"Shutdown complete");

    } catch (const std::exception& e) {
        SS_LOG_ERROR(LOG_CATEGORY, L"Shutdown error - %hs", e.what());
    }
}

bool SystemInfo::IsInitialized() const noexcept {
    return m_impl->m_initialized.load(std::memory_order_acquire);
}

void SystemInfo::Refresh() {
    std::unique_lock<std::shared_mutex> lock(m_impl->m_mutex);
    
    if (!m_impl->m_initialized.load(std::memory_order_acquire)) {
        SS_LOG_WARN(LOG_CATEGORY, L"Refresh called before initialization");
        return;
    }

    try {
        // Refresh all cached data
        {
            std::unique_lock<std::shared_mutex> cacheLock(m_impl->m_cacheMutex);
            m_impl->m_osVersion = m_impl->DetectOSVersion();
            m_impl->m_cpuInfo = m_impl->DetectCPU();
            m_impl->m_fingerprint = m_impl->GenerateFingerprint();
        }

        m_impl->m_statistics.queriesExecuted.fetch_add(1, std::memory_order_relaxed);
        SS_LOG_DEBUG(LOG_CATEGORY, L"System information refreshed");

    } catch (const std::exception& e) {
        SS_LOG_ERROR(LOG_CATEGORY, L"Refresh failed - %hs", e.what());
    }
}

// ============================================================================
// BASIC SYSTEM INFORMATION
// ============================================================================

const OSVersion& SystemInfo::GetOSVersion() const noexcept {
    std::shared_lock<std::shared_mutex> lock(m_impl->m_cacheMutex);
    return m_impl->m_osVersion;
}

const CPUInfo& SystemInfo::GetCPUInfo() const noexcept {
    std::shared_lock<std::shared_mutex> lock(m_impl->m_cacheMutex);
    return m_impl->m_cpuInfo;
}

MemoryInfo SystemInfo::GetMemoryInfo() const {
    m_impl->m_statistics.queriesExecuted.fetch_add(1, std::memory_order_relaxed);
    return m_impl->GetMemory();
}

std::vector<StorageInfo> SystemInfo::GetStorageInfo() const {
    m_impl->m_statistics.queriesExecuted.fetch_add(1, std::memory_order_relaxed);
    return m_impl->GetStorage();
}

std::vector<NetworkInterfaceInfo> SystemInfo::GetNetworkInfo() const {
    m_impl->m_statistics.queriesExecuted.fetch_add(1, std::memory_order_relaxed);
    return m_impl->GetNetwork();
}

// ============================================================================
// ENVIRONMENT DETECTION
// ============================================================================

VirtualizationInfo SystemInfo::DetectVirtualization() const {
    m_impl->m_statistics.queriesExecuted.fetch_add(1, std::memory_order_relaxed);
    return m_impl->DetectVirtualization();
}

bool SystemInfo::IsVirtualMachine() const {
    auto vmInfo = m_impl->DetectVirtualization();
    return vmInfo.isVirtualized;
}

SandboxInfo SystemInfo::DetectSandbox() const {
    m_impl->m_statistics.queriesExecuted.fetch_add(1, std::memory_order_relaxed);
    return m_impl->DetectSandbox();
}

bool SystemInfo::IsSandboxed() const {
    auto sandboxInfo = m_impl->DetectSandbox();
    return sandboxInfo.isSandboxed;
}

DebuggerInfo SystemInfo::DetectDebugger() const {
    m_impl->m_statistics.queriesExecuted.fetch_add(1, std::memory_order_relaxed);
    return m_impl->DetectDebugger();
}

bool SystemInfo::IsDebuggerPresent() const {
    auto debuggerInfo = m_impl->DetectDebugger();
    return debuggerInfo.isDebuggerPresent || debuggerInfo.isRemoteDebuggerPresent ||
           debuggerInfo.isKernelDebuggerPresent;
}

BootMode SystemInfo::GetBootMode() const {
    return m_impl->GetBootMode();
}

bool SystemInfo::IsSafeMode() const {
    return m_impl->GetBootMode() == BootMode::SafeMode ||
           m_impl->GetBootMode() == BootMode::SafeModeWithNetworking;
}

// ============================================================================
// MACHINE IDENTIFICATION
// ============================================================================

MachineFingerprint SystemInfo::GetMachineFingerprint() const {
    std::shared_lock<std::shared_mutex> lock(m_impl->m_cacheMutex);
    return m_impl->m_fingerprint;
}

std::wstring SystemInfo::GetMachineId() const {
    std::shared_lock<std::shared_mutex> lock(m_impl->m_cacheMutex);
    return m_impl->m_fingerprint.machineId;
}

std::wstring SystemInfo::GetHardwareFingerprint() const {
    std::shared_lock<std::shared_mutex> lock(m_impl->m_cacheMutex);
    return m_impl->m_fingerprint.hardwareFingerprint;
}

// ============================================================================
// SECURITY STATUS
// ============================================================================

SecuritySettings SystemInfo::GetSecuritySettings() const {
    m_impl->m_statistics.queriesExecuted.fetch_add(1, std::memory_order_relaxed);
    return m_impl->GetSecuritySettings();
}

bool SystemInfo::IsElevated() const {
    BOOL elevated = FALSE;
    
    // Use RAII to ensure handle is closed
    HandleGuard hToken(nullptr);
    HANDLE rawToken = nullptr;
    
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &rawToken)) {
        hToken = HandleGuard(rawToken);
        
        TOKEN_ELEVATION elevation{};
        DWORD size = sizeof(TOKEN_ELEVATION);

        if (GetTokenInformation(hToken.get(), TokenElevation, &elevation, sizeof(elevation), &size)) {
            elevated = elevation.TokenIsElevated;
        }
    }

    return (elevated != FALSE);
}

std::chrono::milliseconds SystemInfo::GetUptime() const {
    return std::chrono::milliseconds(GetTickCount64());
}

std::chrono::system_clock::time_point SystemInfo::GetBootTime() const {
    auto uptime = GetTickCount64();
    auto now = std::chrono::system_clock::now();
    return now - std::chrono::milliseconds(uptime);
}

PowerState SystemInfo::GetPowerState() const {
    return m_impl->GetPowerState();
}

// ============================================================================
// COMPLETE SNAPSHOT
// ============================================================================

SystemSnapshot SystemInfo::GetSnapshot() const {
    SystemSnapshot snapshot;

    try {
        snapshot.os = GetOSVersion();
        snapshot.cpu = GetCPUInfo();
        snapshot.memory = GetMemoryInfo();
        snapshot.storage = GetStorageInfo();
        snapshot.network = GetNetworkInfo();
        snapshot.virtualization = DetectVirtualization();
        snapshot.sandbox = DetectSandbox();
        snapshot.debugger = DetectDebugger();
        snapshot.fingerprint = GetMachineFingerprint();
        snapshot.security = GetSecuritySettings();
        snapshot.bootMode = GetBootMode();
        snapshot.powerState = GetPowerState();
        snapshot.bootTime = GetBootTime();
        snapshot.snapshotTime = std::chrono::system_clock::now();

    } catch (const std::exception& e) {
        SS_LOG_ERROR(LOG_CATEGORY, L"Snapshot creation failed - %hs", e.what());
    }

    return snapshot;
}

// ============================================================================
// STATISTICS & DIAGNOSTICS
// ============================================================================

const SystemInfoStatistics& SystemInfo::GetStatistics() const noexcept {
    return m_impl->m_statistics;
}

void SystemInfo::ResetStatistics() noexcept {
    m_impl->m_statistics.Reset();
    SS_LOG_INFO(LOG_CATEGORY, L"Statistics reset");
}

std::string SystemInfo::GetVersionString() noexcept {
    return std::to_string(SystemInfoConstants::VERSION_MAJOR) + "." +
           std::to_string(SystemInfoConstants::VERSION_MINOR) + "." +
           std::to_string(SystemInfoConstants::VERSION_PATCH);
}

bool SystemInfo::SelfTest() {
    try {
        SS_LOG_INFO(LOG_CATEGORY, L"Starting self-test");

        // Test OS version detection
        auto osVersion = m_impl->DetectOSVersion();
        if (osVersion.majorVersion == 0) {
            SS_LOG_ERROR(LOG_CATEGORY, L"OS version detection failed");
            return false;
        }

        // Test CPU detection
        auto cpuInfo = m_impl->DetectCPU();
        if (cpuInfo.vendor.empty()) {
            SS_LOG_ERROR(LOG_CATEGORY, L"CPU detection failed");
            return false;
        }

        // Test memory detection
        auto memInfo = m_impl->GetMemory();
        if (memInfo.totalPhysicalBytes == 0) {
            SS_LOG_ERROR(LOG_CATEGORY, L"Memory detection failed");
            return false;
        }

        // Test virtualization detection
        auto vmInfo = m_impl->DetectVirtualization();
        // VM detection doesn't need to pass specific values

        // Test sandbox detection
        auto sandboxInfo = m_impl->DetectSandbox();
        // Sandbox detection doesn't need to pass specific values

        // Test debugger detection
        auto debuggerInfo = m_impl->DetectDebugger();
        // Debugger detection doesn't need to pass specific values

        SS_LOG_INFO(LOG_CATEGORY, L"Self-test passed");
        return true;

    } catch (const std::exception& e) {
        SS_LOG_ERROR(LOG_CATEGORY, L"Self-test failed - %hs", e.what());
        return false;
    }
}

std::vector<std::wstring> SystemInfo::RunDiagnostics() const {
    std::vector<std::wstring> diagnostics;

    diagnostics.push_back(L"SystemInfo Diagnostics");
    diagnostics.push_back(L"======================");
    diagnostics.push_back(L"Initialized: " + std::wstring(IsInitialized() ? L"Yes" : L"No"));
    diagnostics.push_back(L"Queries Executed: " + std::to_wstring(m_impl->m_statistics.queriesExecuted.load()));
    diagnostics.push_back(L"VM Detections: " + std::to_wstring(m_impl->m_statistics.vmDetections.load()));
    diagnostics.push_back(L"Sandbox Detections: " + std::to_wstring(m_impl->m_statistics.sandboxDetections.load()));
    diagnostics.push_back(L"Debugger Detections: " + std::to_wstring(m_impl->m_statistics.debuggerDetections.load()));

    auto osVersion = GetOSVersion();
    diagnostics.push_back(L"OS: " + osVersion.productName + L" " + osVersion.displayVersion);

    auto cpuInfo = GetCPUInfo();
    diagnostics.push_back(L"CPU: " + cpuInfo.brand);
    diagnostics.push_back(L"Cores: " + std::to_wstring(cpuInfo.logicalCores));

    auto memInfo = GetMemoryInfo();
    diagnostics.push_back(L"Memory: " + std::to_wstring(memInfo.totalPhysicalBytes / (1024 * 1024 * 1024)) + L" GB");

    auto vmInfo = DetectVirtualization();
    diagnostics.push_back(L"Virtualized: " + std::wstring(vmInfo.isVirtualized ? L"Yes" : L"No"));

    auto sandboxInfo = DetectSandbox();
    diagnostics.push_back(L"Sandboxed: " + std::wstring(sandboxInfo.isSandboxed ? L"Yes" : L"No"));

    return diagnostics;
}

// ============================================================================
// EXPORT
// ============================================================================

bool SystemInfo::ExportSnapshot(const std::wstring& outputPath) const {
    try {
        std::wofstream file(outputPath);
        if (!file.is_open()) {
            return false;
        }

        auto snapshot = GetSnapshot();

        file << L"SystemInfo Snapshot\n";
        file << L"===================\n\n";

        // OS Information
        file << L"Operating System:\n";
        file << L"  Product: " << snapshot.os.productName << L"\n";
        file << L"  Version: " << snapshot.os.majorVersion << L"."
             << snapshot.os.minorVersion << L"." << snapshot.os.buildNumber << L"\n";
        file << L"  Edition: " << snapshot.os.edition << L"\n";
        file << L"  Display Version: " << snapshot.os.displayVersion << L"\n\n";

        // CPU Information
        file << L"CPU:\n";
        file << L"  Brand: " << snapshot.cpu.brand << L"\n";
        file << L"  Vendor: " << snapshot.cpu.vendor << L"\n";
        file << L"  Cores: " << snapshot.cpu.logicalCores << L" logical, "
             << snapshot.cpu.physicalCores << L" physical\n";
        file << L"  Features: ";
        if (snapshot.cpu.hasAVX) file << L"AVX ";
        if (snapshot.cpu.hasAVX2) file << L"AVX2 ";
        if (snapshot.cpu.hasAVX512) file << L"AVX512 ";
        if (snapshot.cpu.hasAESNI) file << L"AES-NI ";
        file << L"\n\n";

        // Memory
        file << L"Memory:\n";
        file << L"  Total: " << (snapshot.memory.totalPhysicalBytes / (1024 * 1024 * 1024)) << L" GB\n";
        file << L"  Available: " << (snapshot.memory.availablePhysicalBytes / (1024 * 1024 * 1024)) << L" GB\n";
        file << L"  Load: " << snapshot.memory.memoryLoad << L"%\n\n";

        // Virtualization
        file << L"Virtualization:\n";
        file << L"  Status: " << (snapshot.virtualization.isVirtualized ? L"Virtualized" : L"Physical") << L"\n";
        if (snapshot.virtualization.isVirtualized) {
            file << L"  Type: " << GetVirtualizationTypeName(snapshot.virtualization.type).data() << L"\n";
            file << L"  Confidence: " << (snapshot.virtualization.confidence * 100.0) << L"%\n";
        }
        file << L"\n";

        // Sandbox
        file << L"Sandbox:\n";
        file << L"  Status: " << (snapshot.sandbox.isSandboxed ? L"Sandboxed" : L"Normal") << L"\n";
        if (snapshot.sandbox.isSandboxed) {
            file << L"  Type: " << GetSandboxTypeName(snapshot.sandbox.type).data() << L"\n";
            file << L"  Confidence: " << (snapshot.sandbox.confidence * 100.0) << L"%\n";
        }
        file << L"\n";

        // Security
        file << L"Security Settings:\n";
        file << L"  Secure Boot: " << (snapshot.security.isSecureBoot ? L"Enabled" : L"Disabled") << L"\n";
        file << L"  BitLocker: " << (snapshot.security.isBitLockerEnabled ? L"Enabled" : L"Disabled") << L"\n";
        file << L"  UAC: " << (snapshot.security.isUACEnabled ? L"Enabled" : L"Disabled") << L"\n";
        file << L"  Windows Defender: " << (snapshot.security.isDefenderEnabled ? L"Enabled" : L"Disabled") << L"\n";
        file << L"  Firewall: " << (snapshot.security.isFirewallEnabled ? L"Enabled" : L"Disabled") << L"\n";
        file << L"\n";

        // Machine ID
        file << L"Machine Identification:\n";
        file << L"  Machine ID: " << snapshot.fingerprint.machineId << L"\n";
        file << L"  Hardware Fingerprint: " << snapshot.fingerprint.hardwareFingerprint << L"\n";

        file.close();
        return true;

    } catch (...) {
        return false;
    }
}

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

std::string_view GetVirtualizationTypeName(VirtualizationType type) noexcept {
    switch (type) {
        case VirtualizationType::None: return "None";
        case VirtualizationType::VMware: return "VMware";
        case VirtualizationType::VirtualBox: return "VirtualBox";
        case VirtualizationType::HyperV: return "Hyper-V";
        case VirtualizationType::QEMU: return "QEMU";
        case VirtualizationType::KVM: return "KVM";
        case VirtualizationType::Xen: return "Xen";
        case VirtualizationType::Parallels: return "Parallels";
        case VirtualizationType::AmazonEC2: return "Amazon EC2";
        case VirtualizationType::AzureVM: return "Azure VM";
        case VirtualizationType::GoogleCloud: return "Google Cloud";
        case VirtualizationType::Unknown: return "Unknown";
        default: return "Unknown";
    }
}

std::string_view GetSandboxTypeName(SandboxType type) noexcept {
    switch (type) {
        case SandboxType::None: return "None";
        case SandboxType::CuckooSandbox: return "Cuckoo Sandbox";
        case SandboxType::JoeSandbox: return "Joe Sandbox";
        case SandboxType::AnyRun: return "Any.Run";
        case SandboxType::HybridAnalysis: return "Hybrid Analysis";
        case SandboxType::WindowsSandbox: return "Windows Sandbox";
        case SandboxType::Generic: return "Generic";
        default: return "Unknown";
    }
}

std::string_view GetBootModeName(BootMode mode) noexcept {
    switch (mode) {
        case BootMode::Normal: return "Normal";
        case BootMode::SafeMode: return "Safe Mode";
        case BootMode::SafeModeWithNetworking: return "Safe Mode with Networking";
        case BootMode::DirectoryServicesRepair: return "Directory Services Repair";
        case BootMode::WinRE: return "Windows Recovery Environment";
        default: return "Unknown";
    }
}

std::string_view GetProcessorArchitectureName(ProcessorArchitecture arch) noexcept {
    switch (arch) {
        case ProcessorArchitecture::Unknown: return "Unknown";
        case ProcessorArchitecture::X86: return "x86 (32-bit)";
        case ProcessorArchitecture::X64: return "x64 (64-bit)";
        case ProcessorArchitecture::ARM: return "ARM";
        case ProcessorArchitecture::ARM64: return "ARM64";
        default: return "Unknown";
    }
}

std::string_view GetPowerStateName(PowerState state) noexcept {
    switch (state) {
        case PowerState::Unknown: return "Unknown";
        case PowerState::ACPower: return "AC Power";
        case PowerState::Battery: return "Battery";
        case PowerState::BatteryLow: return "Battery Low";
        case PowerState::BatteryCritical: return "Battery Critical";
        default: return "Unknown";
    }
}

}  // namespace System
}  // namespace Core
}  // namespace ShadowStrike
