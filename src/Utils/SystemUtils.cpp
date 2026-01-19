// This is an open source non-commercial project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++, C#, and Java: https://pvs-studio.com


#include"pch.h"
/**
 * @file SystemUtils.cpp
 * @brief Implementation of system-level utility functions for Windows platform
 *
 * This file contains the implementation of various system information retrieval
 * functions, including OS version detection, CPU topology enumeration,
 * memory statistics, security information, and path utilities.
 *
 * @note All functions include proper error handling, RAII resource management,
 *       and defensive programming practices suitable for security-critical applications.
 *
 * @copyright ShadowStrike Security Suite
 */

#include "SystemUtils.hpp"

#include <vector>
#include <string>
#include <cwchar>
#include <cstring>
#include <tlhelp32.h>
#include <intrin.h>
#include <VersionHelpers.h>
#include <winternl.h>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "user32.lib")

namespace ShadowStrike {
namespace Utils {
namespace SystemUtils {

    //=============================================================================
    // Internal Constants
    //=============================================================================

    namespace {
        /** Maximum number of iterations for buffer growth loops to prevent infinite loops */
        constexpr size_t kMaxBufferGrowthIterations = 16;

        /** Maximum buffer size for path expansion (32KB) */
        constexpr size_t kMaxExpandedPathSize = 32768;

        /** CPUID brand string buffer size */
        constexpr size_t kCpuBrandBufferSize = 49;

        /** Registry key path for Windows version information */
        constexpr const wchar_t* kWindowsVersionRegKey = L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion";
    } // anonymous namespace

    //=============================================================================
    // RAII Handle Wrappers
    //=============================================================================

    /**
     * @brief RAII wrapper for Windows HANDLE resources
     */
    class ScopedHandle {
    public:
        explicit ScopedHandle(HANDLE h = nullptr) noexcept : m_handle(h) {}
        ~ScopedHandle() noexcept { Close(); }

        // Non-copyable
        ScopedHandle(const ScopedHandle&) = delete;
        ScopedHandle& operator=(const ScopedHandle&) = delete;

        // Movable
        ScopedHandle(ScopedHandle&& other) noexcept : m_handle(other.m_handle) {
            other.m_handle = nullptr;
        }
        ScopedHandle& operator=(ScopedHandle&& other) noexcept {
            if (this != &other) {
                Close();
                m_handle = other.m_handle;
                other.m_handle = nullptr;
            }
            return *this;
        }

        [[nodiscard]] HANDLE Get() const noexcept { return m_handle; }
        [[nodiscard]] bool IsValid() const noexcept {
            return m_handle != nullptr && m_handle != INVALID_HANDLE_VALUE;
        }
        [[nodiscard]] explicit operator bool() const noexcept { return IsValid(); }

        void Close() noexcept {
            if (IsValid()) {
                ::CloseHandle(m_handle);
                m_handle = nullptr;
            }
        }

        HANDLE Release() noexcept {
            HANDLE h = m_handle;
            m_handle = nullptr;
            return h;
        }

    private:
        HANDLE m_handle;
    };

    /**
     * @brief RAII wrapper for Windows Registry HKEY handles
     */
    class ScopedRegKey {
    public:
        explicit ScopedRegKey(HKEY h = nullptr) noexcept : m_key(h) {}
        ~ScopedRegKey() noexcept { Close(); }

        // Non-copyable
        ScopedRegKey(const ScopedRegKey&) = delete;
        ScopedRegKey& operator=(const ScopedRegKey&) = delete;

        // Movable
        ScopedRegKey(ScopedRegKey&& other) noexcept : m_key(other.m_key) {
            other.m_key = nullptr;
        }
        ScopedRegKey& operator=(ScopedRegKey&& other) noexcept {
            if (this != &other) {
                Close();
                m_key = other.m_key;
                other.m_key = nullptr;
            }
            return *this;
        }

        [[nodiscard]] HKEY Get() const noexcept { return m_key; }
        [[nodiscard]] bool IsValid() const noexcept { return m_key != nullptr; }
        [[nodiscard]] explicit operator bool() const noexcept { return IsValid(); }

        HKEY* GetAddressOf() noexcept { return &m_key; }

        void Close() noexcept {
            if (m_key != nullptr) {
                ::RegCloseKey(m_key);
                m_key = nullptr;
            }
        }

    private:
        HKEY m_key;
    };

    //=============================================================================
    // Internal Helper Functions
    //=============================================================================

    namespace {
        /**
         * @brief Converts wstring_view to wstring safely
         * @param sv Input string view
         * @return Copy as wstring
         */
        [[nodiscard]] std::wstring ToWString(std::wstring_view sv) noexcept {
            try {
                return std::wstring(sv.data(), sv.size());
            } catch (...) {
                return std::wstring();
            }
        }

        /**
         * @brief Converts processor architecture WORD to string
         * @param arch Processor architecture value from SYSTEM_INFO
         * @return Human-readable architecture name
         */
        [[nodiscard]] std::wstring ArchitectureToString(WORD arch) noexcept {
            switch (arch) {
            case PROCESSOR_ARCHITECTURE_AMD64: return L"x64";
            case PROCESSOR_ARCHITECTURE_INTEL: return L"x86";
            case PROCESSOR_ARCHITECTURE_ARM64: return L"ARM64";
            case PROCESSOR_ARCHITECTURE_ARM:   return L"ARM";
            case PROCESSOR_ARCHITECTURE_IA64:  return L"IA64";
            default: return L"Unknown";
            }
        }

        /**
         * @brief Converts integrity RID to human-readable name
         * @param rid Integrity level RID
         * @return Integrity level name
         */
        [[nodiscard]] std::wstring IntegrityRidToName(DWORD rid) noexcept {
            switch (rid) {
            case SECURITY_MANDATORY_UNTRUSTED_RID:        return L"Untrusted";
            case SECURITY_MANDATORY_LOW_RID:              return L"Low";
            case SECURITY_MANDATORY_MEDIUM_RID:           return L"Medium";
            case SECURITY_MANDATORY_MEDIUM_PLUS_RID:      return L"MediumPlus";
            case SECURITY_MANDATORY_HIGH_RID:             return L"High";
            case SECURITY_MANDATORY_SYSTEM_RID:           return L"System";
            case SECURITY_MANDATORY_PROTECTED_PROCESS_RID:return L"Protected";
            default: return L"Unknown";
            }
        }

        /**
         * @brief Safely checks if current process is running under WOW64
         * @param[out] isWow64 Set to true if running under WOW64
         * @param[out] processMachine Set to process machine type
         * @return true on success
         */
        [[nodiscard]] bool IsWow64Process2Safe(bool& isWow64, USHORT& processMachine) noexcept {
#ifdef _WIN32
            isWow64 = false;
            processMachine = 0;

            // Try IsWow64Process2 first (Windows 10 1511+)
            using IsWow64Process2_t = BOOL(WINAPI*)(HANDLE, USHORT*, USHORT*);
            HMODULE hKernel = ::GetModuleHandleW(L"kernel32.dll");
            if (hKernel != nullptr) {
                auto pIsWow64Process2 = reinterpret_cast<IsWow64Process2_t>(
                    ::GetProcAddress(hKernel, "IsWow64Process2"));
                if (pIsWow64Process2 != nullptr) {
                    USHORT nativeMachine = 0;
                    if (pIsWow64Process2(::GetCurrentProcess(), &processMachine, &nativeMachine)) {
                        isWow64 = (processMachine != IMAGE_FILE_MACHINE_UNKNOWN);
                        return true;
                    }
                }
            }

            // Fallback to IsWow64Process (Windows XP SP2+)
            BOOL wow = FALSE;
            if (::IsWow64Process(::GetCurrentProcess(), &wow)) {
                isWow64 = (wow != FALSE);
                return true;
            }
#else
            (void)isWow64;
            (void)processMachine;
#endif
            return false;
        }

        /**
         * @brief Reads a registry string value with proper bounds checking
         * @param hKey Open registry key handle
         * @param valueName Name of the value to read
         * @param[out] result String to receive the value
         * @return true on success
         */
        [[nodiscard]] bool ReadRegistryString(HKEY hKey, const wchar_t* valueName, std::wstring& result) noexcept {
            if (hKey == nullptr || valueName == nullptr) {
                return false;
            }

            wchar_t buffer[kMaxRegistryValueSize] = {};
            DWORD bufferSize = sizeof(buffer);
            DWORD valueType = 0;

            LSTATUS status = ::RegQueryValueExW(
                hKey,
                valueName,
                nullptr,
                &valueType,
                reinterpret_cast<LPBYTE>(buffer),
                &bufferSize
            );

            if (status != ERROR_SUCCESS) {
                return false;
            }

            // Validate type is string
            if (valueType != REG_SZ && valueType != REG_EXPAND_SZ) {
                return false;
            }

            // Calculate string length (bufferSize includes null terminator, is in bytes)
            size_t charCount = bufferSize / sizeof(wchar_t);
            if (charCount > 0 && buffer[charCount - 1] == L'\0') {
                charCount--;
            }

            // Bounds check
            if (charCount >= kMaxRegistryValueSize) {
                charCount = kMaxRegistryValueSize - 1;
            }

            try {
                result.assign(buffer, charCount);
                return true;
            } catch (...) {
                return false;
            }
        }

    } // anonymous namespace

    //=============================================================================
    // Time Functions Implementation
    //=============================================================================

    uint64_t NowFileTime100nsUTC() noexcept {
#ifdef _WIN32
        FILETIME ft{};

        // Prefer GetSystemTimePreciseAsFileTime for higher precision (Win8+)
        HMODULE hKernel = ::GetModuleHandleW(L"kernel32.dll");
        if (hKernel != nullptr) {
            using GetSystemTimePreciseAsFileTime_t = VOID(WINAPI*)(LPFILETIME);
            auto pPrecise = reinterpret_cast<GetSystemTimePreciseAsFileTime_t>(
                ::GetProcAddress(hKernel, "GetSystemTimePreciseAsFileTime"));
            if (pPrecise != nullptr) {
                pPrecise(&ft);
            } else {
                ::GetSystemTimeAsFileTime(&ft);
            }
        } else {
            ::GetSystemTimeAsFileTime(&ft);
        }

        // Convert FILETIME to uint64_t
        ULARGE_INTEGER uli{};
        uli.LowPart = ft.dwLowDateTime;
        uli.HighPart = ft.dwHighDateTime;
        return uli.QuadPart;
#else
        return 0;
#endif
    }

    uint64_t UptimeMilliseconds() noexcept {
#ifdef _WIN32
        // GetTickCount64 doesn't overflow and is available since Vista
        return static_cast<uint64_t>(::GetTickCount64());
#else
        return 0;
#endif
    }

    //=============================================================================
    // System Information Functions Implementation
    //=============================================================================

    bool GetBasicSystemInfo(SYSTEM_INFO& out) noexcept {
#ifdef _WIN32
        // Zero-initialize output
        std::memset(&out, 0, sizeof(out));

        // Use GetNativeSystemInfo when available for accurate info on WOW64
        if (::IsWindowsXPOrGreater()) {
            ::GetNativeSystemInfo(&out);
        } else {
            ::GetSystemInfo(&out);
        }
        return true;
#else
        (void)out;
        return false;
#endif
    }

    bool QueryOSVersion(OSVersion& out) noexcept {
#ifdef _WIN32
        // Clear output structure
        out.Clear();

        // Use RtlGetVersion for accurate version detection (bypasses compatibility shim)
        using RtlGetVersion_t = LONG(WINAPI*)(PRTL_OSVERSIONINFOW);
        RTL_OSVERSIONINFOW versionInfo{};
        versionInfo.dwOSVersionInfoSize = sizeof(versionInfo);

        bool versionObtained = false;
        HMODULE hNtdll = ::GetModuleHandleW(L"ntdll.dll");
        if (hNtdll != nullptr) {
            auto pRtlGetVersion = reinterpret_cast<RtlGetVersion_t>(
                ::GetProcAddress(hNtdll, "RtlGetVersion"));
            if (pRtlGetVersion != nullptr) {
                if (pRtlGetVersion(&versionInfo) == 0) { // STATUS_SUCCESS
                    versionObtained = true;
                }
            }
        }

        // Fallback to GetVersionEx (deprecated but works)
        if (!versionObtained) {
            OSVERSIONINFOW osvi{};
            osvi.dwOSVersionInfoSize = sizeof(osvi);
#pragma warning(push)
#pragma warning(disable: 4996) // GetVersionExW deprecated
            if (!::GetVersionExW(&osvi)) {
                SS_LOG_LAST_ERROR(L"SystemUtils", L"GetVersionExW failed");
                return false;
            }
#pragma warning(pop)
            versionInfo.dwMajorVersion = osvi.dwMajorVersion;
            versionInfo.dwMinorVersion = osvi.dwMinorVersion;
            versionInfo.dwBuildNumber = osvi.dwBuildNumber;
            versionInfo.dwPlatformId = osvi.dwPlatformId;
        }

        // Populate output structure
        out.major = versionInfo.dwMajorVersion;
        out.minor = versionInfo.dwMinorVersion;
        out.build = versionInfo.dwBuildNumber;
        out.platformId = versionInfo.dwPlatformId;

        // Determine 64-bit OS and WOW64 status
        bool isWow64 = false;
        USHORT processMachine = 0;
        if(!IsWow64Process2Safe(isWow64, processMachine)){
            SS_LOG_ERROR(L"SystemUtils", L"IsWow64Process2Safe failed");
            return false;
		}
        out.isWow64Process = isWow64;

        SYSTEM_INFO sysInfo{};
        GetBasicSystemInfo(sysInfo);
        out.is64BitOS = (sysInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64 ||
                         sysInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_ARM64 ||
                         sysInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_IA64);

        // Read additional information from registry using RAII
        ScopedRegKey regKey;
        if (::RegOpenKeyExW(HKEY_LOCAL_MACHINE, kWindowsVersionRegKey,
                           0, KEY_READ | KEY_WOW64_64KEY, regKey.GetAddressOf()) == ERROR_SUCCESS) {
            if (!ReadRegistryString(regKey.Get(), L"ProductName", out.productName)) {
				SS_LOG_ERROR(L"SystemUtils", L"Failed to read ProductName from registry");
            }
            if (!ReadRegistryString(regKey.Get(), L"ReleaseId", out.releaseId)) {
                SS_LOG_ERROR(L"SystemUtils", L"Failed to read ReleaseId from registry");
            }
            if (!ReadRegistryString(regKey.Get(), L"DisplayVersion", out.displayVersion)) {
                SS_LOG_ERROR(L"SystemUtils", L"Failed to read DisplayVersion from registry");
            }
            if (!ReadRegistryString(regKey.Get(), L"EditionID", out.editionId)) {
                SS_LOG_ERROR(L"SystemUtils", L"Failed to read EditionID from registry");
            }
            if (!ReadRegistryString(regKey.Get(), L"CurrentBuild", out.currentBuild)) {
                SS_LOG_ERROR(L"SystemUtils", L"Failed to read CurrentBuild from registry");
            }
        }

        // Check if Windows Server
        out.isServer = ::IsWindowsServer() != FALSE;

        return true;
#else
        (void)out;
        return false;
#endif
    }

    bool QueryCpuInfo(CpuInfo& out) noexcept {
#ifdef _WIN32
        // Clear output structure
        out.Clear();

        // Get basic system info for architecture
        SYSTEM_INFO sysInfo{};
        GetBasicSystemInfo(sysInfo);
        out.architecture = ArchitectureToString(sysInfo.wProcessorArchitecture);

        // Query processor topology using GetLogicalProcessorInformationEx
        DWORD bufferLength = 0;
        if (!::GetLogicalProcessorInformationEx(RelationAll, nullptr, &bufferLength) &&
            ::GetLastError() == ERROR_INSUFFICIENT_BUFFER && bufferLength > 0) {

            // Allocate buffer for topology information
            std::vector<uint8_t> buffer;
            try {
                buffer.resize(bufferLength);
            } catch (...) {
                SS_LOG_ERROR(L"SystemUtils", L"Failed to allocate buffer for processor topology");
                out.logicalProcessorCount = sysInfo.dwNumberOfProcessors;
                return true;
            }

            if (::GetLogicalProcessorInformationEx(
                    RelationAll,
                    reinterpret_cast<PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX>(buffer.data()),
                    &bufferLength)) {

                // Parse topology information
                const uint8_t* ptr = buffer.data();
                const uint8_t* end = ptr + bufferLength;

                while (ptr < end) {
                    auto* info = reinterpret_cast<const SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX*>(ptr);

                    // Validate structure size to prevent buffer overrun
                    if (info->Size == 0 || ptr + info->Size > end) {
                        SS_LOG_WARN(L"SystemUtils", L"Invalid processor information structure size");
                        break;
                    }

                    switch (info->Relationship) {
                    case RelationProcessorCore:
                        out.coreCount++;
                        // Count logical processors (threads) for this core
                        for (WORD groupIdx = 0; groupIdx < info->Processor.GroupCount; ++groupIdx) {
                            KAFFINITY mask = info->Processor.GroupMask[groupIdx].Mask;
#if defined(_WIN64)
                            out.logicalProcessorCount += static_cast<DWORD>(__popcnt64(mask));
#else
                            // Handle 64-bit mask on 32-bit builds
                            DWORD low = static_cast<DWORD>(mask & 0xFFFFFFFFULL);
                            DWORD high = static_cast<DWORD>((mask >> 32) & 0xFFFFFFFFULL);
                            out.logicalProcessorCount += __popcnt(low) + __popcnt(high);
#endif
                        }
                        break;

                    case RelationProcessorPackage:
                        out.packageCount++;
                        break;

                    case RelationNumaNode:
                        out.numaNodeCount++;
                        break;

                    default:
                        // Ignore other relationship types
                        break;
                    }

                    ptr += info->Size;
                }

                // Fallback if topology parsing failed
                if (out.logicalProcessorCount == 0) {
                    out.logicalProcessorCount = sysInfo.dwNumberOfProcessors;
                }
            } else {
                SS_LOG_LAST_ERROR(L"SystemUtils", L"GetLogicalProcessorInformationEx failed");
                out.logicalProcessorCount = sysInfo.dwNumberOfProcessors;
            }
        } else {
            out.logicalProcessorCount = sysInfo.dwNumberOfProcessors;
        }

        // Query CPU brand and features using CPUID (x86/x64 only)
#if defined(_M_IX86) || defined(_M_X64)
        // Get extended CPUID support level
        int cpuInfo[4] = {0};
        __cpuid(cpuInfo, 0x80000000);
        unsigned int maxExtendedId = static_cast<unsigned int>(cpuInfo[0]);

        // Read CPU brand string (requires extended functions 0x80000002-0x80000004)
        if (maxExtendedId >= 0x80000004) {
            char brandBuffer[kCpuBrandBufferSize] = {};

            __cpuid(cpuInfo, 0x80000002);
            std::memcpy(brandBuffer + 0, cpuInfo, sizeof(cpuInfo));

            __cpuid(cpuInfo, 0x80000003);
            std::memcpy(brandBuffer + 16, cpuInfo, sizeof(cpuInfo));

            __cpuid(cpuInfo, 0x80000004);
            std::memcpy(brandBuffer + 32, cpuInfo, sizeof(cpuInfo));

            // Ensure null termination
            brandBuffer[kCpuBrandBufferSize - 1] = '\0';

            // Convert to wide string
            size_t brandLen = ::strnlen(brandBuffer, kCpuBrandBufferSize - 1);
            if (brandLen > 0) {
                try {
                    out.brand.resize(brandLen);
                    int result = ::MultiByteToWideChar(
                        CP_ACP, 0,
                        brandBuffer, static_cast<int>(brandLen),
                        out.brand.data(), static_cast<int>(out.brand.size())
                    );
                    if (result <= 0) {
                        out.brand.clear();
                    }
                } catch (...) {
                    out.brand.clear();
                }
            }
        }

        // Query CPU feature flags
        int featureInfo1[4] = {0};
        int featureInfo7[4] = {0};

        __cpuid(featureInfo1, 1);
        __cpuidex(featureInfo7, 7, 0);

        // EDX register (featureInfo1[3]) features
        out.hasSSE2 = (featureInfo1[3] & (1 << 26)) != 0;

        // ECX register (featureInfo1[2]) features
        out.hasSSE3  = (featureInfo1[2] & (1 << 0)) != 0;
        out.hasSSSE3 = (featureInfo1[2] & (1 << 9)) != 0;
        out.hasSSE41 = (featureInfo1[2] & (1 << 19)) != 0;
        out.hasSSE42 = (featureInfo1[2] & (1 << 20)) != 0;
        out.hasAVX   = (featureInfo1[2] & (1 << 28)) != 0;

        // EBX register (featureInfo7[1]) features
        out.hasAVX2  = (featureInfo7[1] & (1 << 5)) != 0;
#else
        // Non-x86/x64 architecture - no CPUID available
        out.brand.clear();
#endif

        return true;
#else
        (void)out;
        return false;
#endif
    }

    //=============================================================================
    // Memory Information Functions Implementation
    //=============================================================================

    bool QueryMemoryInfo(MemoryInfo& out) noexcept {
#ifdef _WIN32
        // Clear output structure
        out.Clear();

        // Query memory status
        MEMORYSTATUSEX memStatus{};
        memStatus.dwLength = sizeof(memStatus);

        if (!::GlobalMemoryStatusEx(&memStatus)) {
            SS_LOG_LAST_ERROR(L"SystemUtils", L"GlobalMemoryStatusEx failed");
            return false;
        }

        // Populate output structure
        out.totalPhys = memStatus.ullTotalPhys;
        out.availPhys = memStatus.ullAvailPhys;
        out.totalPageFile = memStatus.ullTotalPageFile;
        out.availPageFile = memStatus.ullAvailPageFile;
        out.totalVirtual = memStatus.ullTotalVirtual;
        out.availVirtual = memStatus.ullAvailVirtual;

        // Query physically installed memory (may be larger than usable memory)
        ULONGLONG installedKB = 0;
        if (::GetPhysicallyInstalledSystemMemory(&installedKB)) {
            out.physInstalledKB = installedKB;
        }
        // Note: GetPhysicallyInstalledSystemMemory may fail on some systems,
        // which is acceptable - we just won't have this information

        return true;
#else
        (void)out;
        return false;
#endif
    }

    //=============================================================================
    // Security Functions Implementation
    //=============================================================================

    bool GetSecurityInfo(SecurityInfo& out) noexcept {
#ifdef _WIN32
        // Clear output structure
        out.Clear();

        // Open process token with RAII
        HANDLE hTokenRaw = nullptr;
        if (!::OpenProcessToken(::GetCurrentProcess(), TOKEN_QUERY, &hTokenRaw)) {
            SS_LOG_LAST_ERROR(L"SystemUtils", L"OpenProcessToken failed");
            return false;
        }
        ScopedHandle hToken(hTokenRaw);

        // Query elevation status
        TOKEN_ELEVATION elevation{};
        DWORD returnLength = 0;
        if (::GetTokenInformation(hToken.Get(), TokenElevation,
                                  &elevation, sizeof(elevation), &returnLength)) {
            out.isElevated = (elevation.TokenIsElevated != 0);
        } else {
            SS_LOG_LAST_ERROR(L"SystemUtils", L"GetTokenInformation(TokenElevation) failed");
            // Continue - elevation status is not critical
        }

        // Query integrity level
        DWORD integrityBufferSize = 0;
        ::GetTokenInformation(hToken.Get(), TokenIntegrityLevel, nullptr, 0, &integrityBufferSize);

        if (::GetLastError() == ERROR_INSUFFICIENT_BUFFER && integrityBufferSize > 0) {
            // Allocate buffer for integrity level
            std::vector<BYTE> integrityBuffer;
            try {
                integrityBuffer.resize(integrityBufferSize);
            } catch (...) {
                SS_LOG_ERROR(L"SystemUtils", L"Failed to allocate integrity level buffer");
                return true; // Partial success - elevation was queried
            }

            if (::GetTokenInformation(hToken.Get(), TokenIntegrityLevel,
                                      integrityBuffer.data(), integrityBufferSize, &returnLength)) {
                auto* pLabel = reinterpret_cast<TOKEN_MANDATORY_LABEL*>(integrityBuffer.data());

                // Validate SID before accessing
                if (pLabel != nullptr && pLabel->Label.Sid != nullptr) {
                    PUCHAR subAuthCount = ::GetSidSubAuthorityCount(pLabel->Label.Sid);
                    if (subAuthCount != nullptr && *subAuthCount > 0) {
                        PDWORD pRid = ::GetSidSubAuthority(
                            pLabel->Label.Sid,
                            static_cast<DWORD>(*subAuthCount - 1)
                        );
                        if (pRid != nullptr) {
                            out.integrityRid = *pRid;
                            out.integrityName = IntegrityRidToName(*pRid);
                        }
                    }
                }
            } else {
                SS_LOG_LAST_ERROR(L"SystemUtils", L"GetTokenInformation(TokenIntegrityLevel) failed");
            }
        }

        return true;
#else
        (void)out;
        return false;
#endif
    }

    bool EnablePrivilege(const wchar_t* privName, bool enable) noexcept {
#ifdef _WIN32
        // Validate input
        if (privName == nullptr || privName[0] == L'\0') {
            SS_LOG_ERROR(L"SystemUtils", L"EnablePrivilege: null or empty privilege name");
            return false;
        }

        // Open process token with RAII
        HANDLE hTokenRaw = nullptr;
        if (!::OpenProcessToken(::GetCurrentProcess(),
                               TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hTokenRaw)) {
            SS_LOG_LAST_ERROR(L"SystemUtils", L"OpenProcessToken failed");
            return false;
        }
        ScopedHandle hToken(hTokenRaw);

        // Lookup privilege LUID
        LUID luid{};
        if (!::LookupPrivilegeValueW(nullptr, privName, &luid)) {
            SS_LOG_LAST_ERROR(L"SystemUtils", L"LookupPrivilegeValueW failed for: %s", privName);
            return false;
        }

        // Prepare privilege structure
        TOKEN_PRIVILEGES tokenPrivileges{};
        tokenPrivileges.PrivilegeCount = 1;
        tokenPrivileges.Privileges[0].Luid = luid;
        tokenPrivileges.Privileges[0].Attributes = enable ? SE_PRIVILEGE_ENABLED : 0;

        // Adjust privileges
        if (!::AdjustTokenPrivileges(hToken.Get(), FALSE, &tokenPrivileges,
                                     sizeof(tokenPrivileges), nullptr, nullptr)) {
            SS_LOG_LAST_ERROR(L"SystemUtils", L"AdjustTokenPrivileges failed for: %s", privName);
            return false;
        }

        // Check if the operation was actually successful
        // AdjustTokenPrivileges returns TRUE even if it couldn't adjust the privilege
        DWORD lastError = ::GetLastError();
        if (lastError == ERROR_NOT_ALL_ASSIGNED) {
            SS_LOG_WARN(L"SystemUtils", L"Privilege not held or could not be adjusted: %s", privName);
            return false;
        }

        return (lastError == ERROR_SUCCESS);
#else
        (void)privName;
        (void)enable;
        return false;
#endif
    }

    bool IsDebuggerPresentSafe() noexcept {
#ifdef _WIN32
        return ::IsDebuggerPresent() != FALSE;
#else
        return false;
#endif
    }

    //=============================================================================
    // Process Information Functions Implementation
    //=============================================================================

    DWORD CurrentProcessId() noexcept {
#ifdef _WIN32
        return ::GetCurrentProcessId();
#else
        return 0;
#endif
    }

    std::optional<DWORD> GetParentProcessId(DWORD pid) noexcept {
#ifdef _WIN32
        // Use current process ID if not specified
        if (pid == 0) {
            pid = ::GetCurrentProcessId();
        }

        // Create process snapshot with RAII
        HANDLE hSnapRaw = ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapRaw == INVALID_HANDLE_VALUE) {
            SS_LOG_LAST_ERROR(L"SystemUtils", L"CreateToolhelp32Snapshot failed");
            return std::nullopt;
        }
        ScopedHandle hSnapshot(hSnapRaw);

        // Initialize process entry structure
        PROCESSENTRY32W processEntry{};
        processEntry.dwSize = sizeof(processEntry);

        // Iterate through processes
        if (!::Process32FirstW(hSnapshot.Get(), &processEntry)) {
            SS_LOG_LAST_ERROR(L"SystemUtils", L"Process32FirstW failed");
            return std::nullopt;
        }

        do {
            if (processEntry.th32ProcessID == pid) {
                DWORD parentPid = processEntry.th32ParentProcessID;
                // Return nullopt for PID 0 (System Idle Process has no parent)
                return (parentPid != 0) ? std::optional<DWORD>(parentPid) : std::nullopt;
            }
        } while (::Process32NextW(hSnapshot.Get(), &processEntry));

        // Process not found
        return std::nullopt;
#else
        (void)pid;
        return std::nullopt;
#endif
    }

    //=============================================================================
    // Path Functions Implementation
    //=============================================================================

    std::wstring GetExecutablePath() noexcept {
#ifdef _WIN32
        // Start with a reasonable buffer size
        std::wstring path;
        try {
            path.resize(kInitialPathBufferSize);
        } catch (...) {
            SS_LOG_ERROR(L"SystemUtils", L"Failed to allocate path buffer");
            return L"";
        }

        // Grow buffer until path fits or we hit the limit
        for (size_t iteration = 0; iteration < kMaxBufferGrowthIterations; ++iteration) {
            DWORD length = ::GetModuleFileNameW(
                nullptr,
                path.data(),
                static_cast<DWORD>(path.size())
            );

            if (length == 0) {
                SS_LOG_LAST_ERROR(L"SystemUtils", L"GetModuleFileNameW failed");
                return L"";
            }

            // Check if buffer was large enough
            if (length < path.size() - 1) {
                path.resize(length);
                return path;
            }

            // Buffer too small - grow it
            size_t newSize = path.size() * 2;
            if (newSize > kMaxExpandedPathSize) {
                SS_LOG_ERROR(L"SystemUtils", L"Executable path exceeds maximum length");
                return L"";
            }

            try {
                path.resize(newSize);
            } catch (...) {
                SS_LOG_ERROR(L"SystemUtils", L"Failed to grow path buffer");
                return L"";
            }
        }

        SS_LOG_ERROR(L"SystemUtils", L"GetExecutablePath: too many iterations");
        return L"";
#else
        return L"";
#endif
    }

    std::wstring GetModulePath(HMODULE mod) noexcept {
#ifdef _WIN32
        // Start with a reasonable buffer size
        std::wstring path;
        try {
            path.resize(kInitialPathBufferSize);
        } catch (...) {
            SS_LOG_ERROR(L"SystemUtils", L"Failed to allocate module path buffer");
            return L"";
        }

        // Grow buffer until path fits or we hit the limit
        for (size_t iteration = 0; iteration < kMaxBufferGrowthIterations; ++iteration) {
            DWORD length = ::GetModuleFileNameW(
                mod,
                path.data(),
                static_cast<DWORD>(path.size())
            );

            if (length == 0) {
                SS_LOG_LAST_ERROR(L"SystemUtils", L"GetModuleFileNameW(mod) failed");
                return L"";
            }

            // Check if buffer was large enough
            if (length < path.size() - 1) {
                path.resize(length);
                return path;
            }

            // Buffer too small - grow it
            size_t newSize = path.size() * 2;
            if (newSize > kMaxExpandedPathSize) {
                SS_LOG_ERROR(L"SystemUtils", L"Module path exceeds maximum length");
                return L"";
            }

            try {
                path.resize(newSize);
            } catch (...) {
                SS_LOG_ERROR(L"SystemUtils", L"Failed to grow module path buffer");
                return L"";
            }
        }

        SS_LOG_ERROR(L"SystemUtils", L"GetModulePath: too many iterations");
        return L"";
#else
        (void)mod;
        return L"";
#endif
    }

    std::wstring GetSystemDirectoryPath() noexcept {
#ifdef _WIN32
        wchar_t buffer[MAX_PATH] = {};
        UINT length = ::GetSystemDirectoryW(buffer, MAX_PATH);

        if (length == 0) {
            SS_LOG_LAST_ERROR(L"SystemUtils", L"GetSystemDirectoryW failed");
            return L"";
        }

        if (length >= MAX_PATH) {
            SS_LOG_ERROR(L"SystemUtils", L"System directory path too long");
            return L"";
        }

        try {
            return std::wstring(buffer, length);
        } catch (...) {
            return L"";
        }
#else
        return L"";
#endif
    }

    std::wstring GetWindowsDirectoryPath() noexcept {
#ifdef _WIN32
        wchar_t buffer[MAX_PATH] = {};
        UINT length = ::GetWindowsDirectoryW(buffer, MAX_PATH);

        if (length == 0) {
            SS_LOG_LAST_ERROR(L"SystemUtils", L"GetWindowsDirectoryW failed");
            return L"";
        }

        if (length >= MAX_PATH) {
            SS_LOG_ERROR(L"SystemUtils", L"Windows directory path too long");
            return L"";
        }

        try {
            return std::wstring(buffer, length);
        } catch (...) {
            return L"";
        }
#else
        return L"";
#endif
    }

    std::wstring ExpandEnv(std::wstring_view s) noexcept {
#ifdef _WIN32
        // Handle empty input
        if (s.empty()) {
            return L"";
        }

        // Convert to wstring for API call
        std::wstring input = ToWString(s);
        if (input.empty() && !s.empty()) {
            // Allocation failed, return original
            try {
                return std::wstring(s);
            } catch (...) {
                return L"";
            }
        }

        // Query required buffer size
        DWORD requiredSize = ::ExpandEnvironmentStringsW(input.c_str(), nullptr, 0);

        // Check for failure or empty result
        if (requiredSize == 0) {
            SS_LOG_LAST_ERROR(L"SystemUtils", L"ExpandEnvironmentStringsW size query failed");
            return input;
        }

        if (requiredSize == 1) {
            // Result is empty string (just null terminator)
            return L"";
        }

        // Validate size is reasonable
        if (requiredSize > kMaxExpandedPathSize) {
            SS_LOG_ERROR(L"SystemUtils", L"Expanded environment string too large");
            return input;
        }

        // Allocate output buffer
        std::wstring output;
        try {
            output.resize(requiredSize);
        } catch (...) {
            SS_LOG_ERROR(L"SystemUtils", L"Failed to allocate expansion buffer");
            return input;
        }

        // Expand environment strings
        DWORD resultLength = ::ExpandEnvironmentStringsW(input.c_str(), output.data(), requiredSize);

        if (resultLength == 0) {
            SS_LOG_LAST_ERROR(L"SystemUtils", L"ExpandEnvironmentStringsW failed");
            return input;
        }

        // Remove trailing null terminator if present
        if (!output.empty() && output.back() == L'\0') {
            output.pop_back();
        }

        // Additional safety: resize to actual length
        if (resultLength > 0 && resultLength <= output.size()) {
            output.resize(resultLength - 1); // -1 for null terminator
        }

        return output;
#else
        return ToWString(s);
#endif
    }

    //=============================================================================
    // Computer Name Functions Implementation
    //=============================================================================

    std::wstring GetComputerNameDnsFullyQualified() noexcept {
#ifdef _WIN32
        // Query required buffer size
        DWORD bufferSize = 0;
        ::GetComputerNameExW(ComputerNameDnsFullyQualified, nullptr, &bufferSize);

        // Check for valid size
        if (bufferSize == 0 || bufferSize == 1) {
            SS_LOG_LAST_ERROR(L"SystemUtils", L"GetComputerNameExW(FQDN) size query failed");
            return L"";
        }

        // Validate size is reasonable
        if (bufferSize > kMaxRegistryValueSize) {
            SS_LOG_ERROR(L"SystemUtils", L"Computer name too long");
            return L"";
        }

        // Allocate buffer
        std::wstring name;
        try {
            name.resize(bufferSize);
        } catch (...) {
            SS_LOG_ERROR(L"SystemUtils", L"Failed to allocate computer name buffer");
            return L"";
        }

        // Get the name
        if (!::GetComputerNameExW(ComputerNameDnsFullyQualified, name.data(), &bufferSize)) {
            SS_LOG_LAST_ERROR(L"SystemUtils", L"GetComputerNameExW(FQDN) failed");
            return L"";
        }

        // Remove trailing null if present
        if (!name.empty() && name.back() == L'\0') {
            name.pop_back();
        }

        // Resize to actual length
        name.resize(bufferSize);

        return name;
#else
        return L"";
#endif
    }

    std::wstring GetComputerNameDnsHostname() noexcept {
#ifdef _WIN32
        // Query required buffer size
        DWORD bufferSize = 0;
        ::GetComputerNameExW(ComputerNameDnsHostname, nullptr, &bufferSize);

        // Check for valid size
        if (bufferSize == 0 || bufferSize == 1) {
            SS_LOG_LAST_ERROR(L"SystemUtils", L"GetComputerNameExW(Host) size query failed");
            return L"";
        }

        // Validate size is reasonable
        if (bufferSize > kMaxRegistryValueSize) {
            SS_LOG_ERROR(L"SystemUtils", L"Hostname too long");
            return L"";
        }

        // Allocate buffer
        std::wstring name;
        try {
            name.resize(bufferSize);
        } catch (...) {
            SS_LOG_ERROR(L"SystemUtils", L"Failed to allocate hostname buffer");
            return L"";
        }

        // Get the name
        if (!::GetComputerNameExW(ComputerNameDnsHostname, name.data(), &bufferSize)) {
            SS_LOG_LAST_ERROR(L"SystemUtils", L"GetComputerNameExW(Host) failed");
            return L"";
        }

        // Remove trailing null if present
        if (!name.empty() && name.back() == L'\0') {
            name.pop_back();
        }

        // Resize to actual length
        name.resize(bufferSize);

        return name;
#else
        return L"";
#endif
    }

    //=============================================================================
    // DPI Awareness Functions Implementation
    //=============================================================================

    bool SetProcessDpiAwarePerMonitorV2() noexcept {
#ifdef _WIN32
        // Load user32.dll - use LoadLibraryW for explicit loading
        HMODULE hUser32 = ::LoadLibraryW(L"user32.dll");
        if (hUser32 == nullptr) {
            SS_LOG_LAST_ERROR(L"SystemUtils", L"LoadLibraryW(user32.dll) failed");
            return false;
        }

        // RAII wrapper for FreeLibrary
        struct ModuleGuard {
            HMODULE m_module;
            explicit ModuleGuard(HMODULE m) noexcept : m_module(m) {}
            ~ModuleGuard() noexcept { if (m_module) ::FreeLibrary(m_module); }
            ModuleGuard(const ModuleGuard&) = delete;
            ModuleGuard& operator=(const ModuleGuard&) = delete;
        };
        ModuleGuard moduleGuard(hUser32);

        // Try SetProcessDpiAwarenessContext (Windows 10 1703+)
        using SetProcessDpiAwarenessContext_t = BOOL(WINAPI*)(DPI_AWARENESS_CONTEXT);
        auto pSetContext = reinterpret_cast<SetProcessDpiAwarenessContext_t>(
            ::GetProcAddress(hUser32, "SetProcessDpiAwarenessContext"));

        if (pSetContext != nullptr) {
            // Define DPI_AWARENESS_CONTEXT values if not available
#ifndef DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2
            const DPI_AWARENESS_CONTEXT kDpiContextPerMonitorV2 =
                reinterpret_cast<DPI_AWARENESS_CONTEXT>(static_cast<intptr_t>(-4));
#else
            const DPI_AWARENESS_CONTEXT kDpiContextPerMonitorV2 = DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2;
#endif

#ifndef DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE
            const DPI_AWARENESS_CONTEXT kDpiContextPerMonitor =
                reinterpret_cast<DPI_AWARENESS_CONTEXT>(static_cast<intptr_t>(-3));
#else
            const DPI_AWARENESS_CONTEXT kDpiContextPerMonitor = DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE;
#endif

#ifndef DPI_AWARENESS_CONTEXT_SYSTEM_AWARE
            const DPI_AWARENESS_CONTEXT kDpiContextSystemAware =
                reinterpret_cast<DPI_AWARENESS_CONTEXT>(static_cast<intptr_t>(-2));
#else
            const DPI_AWARENESS_CONTEXT kDpiContextSystemAware = DPI_AWARENESS_CONTEXT_SYSTEM_AWARE;
#endif

            // Try Per-Monitor V2 first (best for Windows 10 1703+)
            if (pSetContext(kDpiContextPerMonitorV2)) {
                return true;
            }

            // Fallback to Per-Monitor V1
            if (pSetContext(kDpiContextPerMonitor)) {
                return true;
            }

            // Fallback to System Aware
            if (pSetContext(kDpiContextSystemAware)) {
                return true;
            }
        }

        // Legacy fallback - SetProcessDPIAware (Windows Vista+)
        using SetProcessDPIAware_t = BOOL(WINAPI*)();
        auto pSetDpiAware = reinterpret_cast<SetProcessDPIAware_t>(
            ::GetProcAddress(hUser32, "SetProcessDPIAware"));

        if (pSetDpiAware != nullptr && pSetDpiAware()) {
            return true;
        }

        SS_LOG_WARN(L"SystemUtils", L"DPI awareness could not be enabled");
        return false;
#else
        return false;
#endif
    }

    //=============================================================================
    // Process Priority Functions Implementation
    //=============================================================================

    bool SetProcessPriorityHigh() noexcept {
#ifdef _WIN32
        if (!::SetPriorityClass(::GetCurrentProcess(), HIGH_PRIORITY_CLASS)) {
            SS_LOG_LAST_ERROR(L"SystemUtils", L"SetPriorityClass(HIGH_PRIORITY_CLASS) failed");
            return false;
        }
        return true;
#else
        return false;
#endif
    }

    bool SetCurrentThreadPriority(int priority) noexcept {
#ifdef _WIN32
        // Validate priority is within valid range
        if (priority < THREAD_PRIORITY_IDLE || priority > THREAD_PRIORITY_TIME_CRITICAL) {
            // Allow THREAD_BASE_PRIORITY_LOWRT and similar special values
            if (priority != THREAD_PRIORITY_IDLE &&
                priority != THREAD_PRIORITY_LOWEST &&
                priority != THREAD_PRIORITY_BELOW_NORMAL &&
                priority != THREAD_PRIORITY_NORMAL &&
                priority != THREAD_PRIORITY_ABOVE_NORMAL &&
                priority != THREAD_PRIORITY_HIGHEST &&
                priority != THREAD_PRIORITY_TIME_CRITICAL) {
                SS_LOG_WARN(L"SystemUtils", L"SetCurrentThreadPriority: unusual priority value %d", priority);
            }
        }

        if (!::SetThreadPriority(::GetCurrentThread(), priority)) {
            SS_LOG_LAST_ERROR(L"SystemUtils", L"SetThreadPriority failed");
            return false;
        }
        return true;
#else
        (void)priority;
        return false;
#endif
    }

    //=============================================================================
    // Boot Time Functions Implementation
    //=============================================================================

    bool QueryBootTime(FILETIME& bootTimeUtc) noexcept {
#ifdef _WIN32
        // Get current system time in UTC
        FILETIME currentTime{};

        // Prefer GetSystemTimePreciseAsFileTime for higher precision (Win8+)
        HMODULE hKernel = ::GetModuleHandleW(L"kernel32.dll");
        if (hKernel != nullptr) {
            using GetSystemTimePreciseAsFileTime_t = VOID(WINAPI*)(LPFILETIME);
            auto pPrecise = reinterpret_cast<GetSystemTimePreciseAsFileTime_t>(
                ::GetProcAddress(hKernel, "GetSystemTimePreciseAsFileTime"));
            if (pPrecise != nullptr) {
                pPrecise(&currentTime);
            } else {
                ::GetSystemTimeAsFileTime(&currentTime);
            }
        } else {
            ::GetSystemTimeAsFileTime(&currentTime);
        }

        // Convert to ULARGE_INTEGER for arithmetic
        ULARGE_INTEGER currentTimeValue{};
        currentTimeValue.LowPart = currentTime.dwLowDateTime;
        currentTimeValue.HighPart = currentTime.dwHighDateTime;

        // Get system uptime in milliseconds and convert to 100-nanosecond intervals
        ULONGLONG uptimeMs = ::GetTickCount64();
        ULONGLONG uptime100ns = uptimeMs * 10000ULL;

        // Calculate boot time (current time - uptime)
        // Handle potential underflow (shouldn't happen, but defensive programming)
        ULARGE_INTEGER bootTimeValue{};
        if (currentTimeValue.QuadPart >= uptime100ns) {
            bootTimeValue.QuadPart = currentTimeValue.QuadPart - uptime100ns;
        } else {
            // This shouldn't happen, but set to 0 if it does
            bootTimeValue.QuadPart = 0;
            SS_LOG_WARN(L"SystemUtils", L"QueryBootTime: uptime exceeds current time (clock skew?)");
        }

        // Convert back to FILETIME
        bootTimeUtc.dwLowDateTime = bootTimeValue.LowPart;
        bootTimeUtc.dwHighDateTime = bootTimeValue.HighPart;

        return true;
#else
        (void)bootTimeUtc;
        return false;
#endif
    }

} // namespace SystemUtils
} // namespace Utils
} // namespace ShadowStrike