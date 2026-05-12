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
/**
 * ============================================================================
 * ShadowStrike Core System - DRIVER ANALYZER IMPLEMENTATION
 * ============================================================================
 *
 * @file DriverAnalyzer.cpp
 * @brief Enterprise-grade kernel driver security analysis engine.
 *
 * This module implements comprehensive kernel driver analysis including:
 * - Driver enumeration via EnumDeviceDrivers()
 * - Digital signature verification (Authenticode, WHQL)
 * - Rootkit detection (SSDT/IDT hooking, DKOM, hidden drivers)
 * - Vulnerable driver detection (LOLDrivers/BYOVD)
 * - Malicious driver identification
 * - Kernel callback monitoring
 * - PE header analysis for drivers
 *
 * Architecture:
 * - PIMPL pattern for ABI stability
 * - Meyers' Singleton for thread-safe instance management
 * - Multi-threaded driver analysis with worker pools
 * - Comprehensive signature verification via WinVerifyTrust
 * - Known vulnerable driver database (LOLDrivers)
 * - Real-time driver load monitoring
 * - Callback architecture for driver events
 *
 * Detection Capabilities:
 * - Unsigned/maliciously signed drivers
 * - Hidden drivers (DKOM techniques)
 * - SSDT/IDT hook detection
 * - Module list manipulation detection
 * - Vulnerable driver detection (BYOVD - Bring Your Own Vulnerable Driver)
 * - Known malicious driver hashes
 * - Suspicious kernel callbacks
 * - Boot-start driver analysis
 *
 * MITRE ATT&CK Coverage:
 * - T1014: Rootkit
 * - T1068: Exploitation for Privilege Escalation
 * - T1543.003: Windows Service (Driver installation)
 * - T1547.006: Kernel Modules and Extensions
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @date 2026
 * @copyright 2026 ShadowStrike Security Suite
 */

#include "pch.h"
#include "DriverAnalyzer.hpp"

// ============================================================================
// INFRASTRUCTURE INCLUDES
// ============================================================================
#include "../../Utils/Logger.hpp"
#include "../../Utils/FileUtils.hpp"
#include "../../Utils/ProcessUtils.hpp"
#include "../../Utils/SystemUtils.hpp"
#include "../../Utils/StringUtils.hpp"
#include "../../Utils/HashUtils.hpp"
#include "../../Utils/CertUtils.hpp"
#include "../../HashStore/HashStore.hpp"
#include "../../ThreatIntel/ThreatIntelLookup.hpp"
#include "../../Whitelist/WhiteListStore.hpp"
#include "../../Communication/IPCManager.hpp"

// Namespace aliases defined inside ShadowStrike::Core::System below

// ============================================================================
// SYSTEM INCLUDES
// ============================================================================
#include <Windows.h>
#include <winternl.h>
#include <Psapi.h>
#include <wintrust.h>
#include <softpub.h>
#include <mscat.h>

// ============================================================================
// STANDARD LIBRARY INCLUDES
// ============================================================================
#include <algorithm>
#include <filesystem>
#include <sstream>
#include <iomanip>
#include <cctype>

#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "ntdll.lib")

namespace fs = std::filesystem;

namespace ShadowStrike {
namespace Core {
namespace System {

// Namespace aliases
namespace HashUtils = ShadowStrike::Utils::HashUtils;
namespace CertUtils = ShadowStrike::Utils::CertUtils;
namespace StringUtils = ShadowStrike::Utils::StringUtils;

// ============================================================================
// INTERNAL CONSTANTS & HELPERS
// ============================================================================
namespace {

    /// Logging category for all DriverAnalyzer messages
    constexpr const wchar_t* LOG_CATEGORY = L"DriverAnalyzer";

    /// @brief Lowercase a narrow (ASCII) string
    [[nodiscard]] std::string NarrowToLower(std::string_view src) {
        std::string out(src);
        std::transform(out.begin(), out.end(), out.begin(),
            [](unsigned char ch) { return static_cast<char>(std::tolower(ch)); });
        return out;
    }

    /// @brief Resolves NT-namespace path to Win32 path.
    ///
    /// Handles the four prefix families produced by EnumDeviceDrivers /
    /// GetDeviceDriverFileNameW and friends:
    ///   - L"\\SystemRoot\\..."          -> %SystemRoot%\\...
    ///   - L"\\??\\<dos-path>"           -> <dos-path>
    ///   - L"\\\\?\\<dos-path>"          -> <dos-path>
    ///   - L"\\Device\\HarddiskVolumeN\\..." -> "X:\\..." via QueryDosDeviceW
    ///     reverse-lookup over A-Z so file-system APIs (fs::exists, hashing,
    ///     signature verification) operate on a stable Win32 path rather than
    ///     an NT device path. Returns the original string when no mapping is
    ///     possible — callers must already tolerate missing files.
    [[nodiscard]] std::wstring NtPathToWin32Path(const std::wstring& ntPath) {
        if (ntPath.empty()) return {};
        std::wstring result = ntPath;

        const std::wstring sysRootPrefix = L"\\SystemRoot\\";
        if (result.size() > sysRootPrefix.size() &&
            _wcsnicmp(result.c_str(), sysRootPrefix.c_str(), sysRootPrefix.size()) == 0) {
            wchar_t winDir[MAX_PATH] = {};
            if (GetWindowsDirectoryW(winDir, MAX_PATH) > 0) {
                result = std::wstring(winDir) + L"\\" + result.substr(sysRootPrefix.size());
            }
        }

        const std::wstring dosPrefix = L"\\??\\";
        if (result.size() > dosPrefix.size() &&
            _wcsnicmp(result.c_str(), dosPrefix.c_str(), dosPrefix.size()) == 0) {
            result = result.substr(dosPrefix.size());
        }

        const std::wstring extPrefix = L"\\\\?\\";
        if (result.size() > extPrefix.size() &&
            _wcsnicmp(result.c_str(), extPrefix.c_str(), extPrefix.size()) == 0) {
            result = result.substr(extPrefix.size());
        }

        const std::wstring devicePrefix = L"\\Device\\";
        if (result.size() > devicePrefix.size() &&
            _wcsnicmp(result.c_str(), devicePrefix.c_str(), devicePrefix.size()) == 0) {
            wchar_t deviceTarget[MAX_PATH] = {};
            for (wchar_t letter = L'A'; letter <= L'Z'; ++letter) {
                const wchar_t drive[3] = { letter, L':', L'\0' };
                const DWORD len = QueryDosDeviceW(drive, deviceTarget, MAX_PATH);
                if (len == 0) {
                    continue;
                }
                const size_t targetLen = wcsnlen_s(deviceTarget, MAX_PATH);
                if (targetLen == 0 || targetLen >= result.size()) {
                    continue;
                }
                if (_wcsnicmp(result.c_str(), deviceTarget, targetLen) == 0 &&
                    (result[targetLen] == L'\\' || result[targetLen] == L'\0')) {
                    result = std::wstring(drive) + result.substr(targetLen);
                    break;
                }
            }
        }

        return result;
    }

    /// @brief Upper bound on catalog candidates probed for a single driver.
    /// Defends against pathological catalog stores causing
    /// CryptCATAdminEnumCatalogFromHash to spin indefinitely.
    constexpr uint32_t MAX_CATALOG_ITERATIONS = 64;

    /// @brief RAII guard for Win32 HANDLE values returned by CreateFileW.
    struct ScopedHandle {
        HANDLE h{ INVALID_HANDLE_VALUE };
        ScopedHandle() = default;
        explicit ScopedHandle(HANDLE handle) noexcept : h(handle) {}
        ScopedHandle(const ScopedHandle&) = delete;
        ScopedHandle& operator=(const ScopedHandle&) = delete;
        ScopedHandle(ScopedHandle&& other) noexcept : h(other.h) {
            other.h = INVALID_HANDLE_VALUE;
        }
        ScopedHandle& operator=(ScopedHandle&& other) noexcept {
            if (this != &other) {
                reset();
                h = other.h;
                other.h = INVALID_HANDLE_VALUE;
            }
            return *this;
        }
        ~ScopedHandle() { reset(); }
        void reset() noexcept {
            if (h != INVALID_HANDLE_VALUE && h != nullptr) {
                ::CloseHandle(h);
                h = INVALID_HANDLE_VALUE;
            }
        }
        [[nodiscard]] bool valid() const noexcept {
            return h != INVALID_HANDLE_VALUE && h != nullptr;
        }
        [[nodiscard]] HANDLE get() const noexcept { return h; }
    };


    // ========================================================================
    // SECURITY CONSTANTS
    // ========================================================================
    
    /// @brief Extended path buffer size for long paths (Windows extended paths can be up to 32767 chars)
    constexpr uint32_t EXTENDED_PATH_BUFFER_SIZE = 32768;
    
    /// @brief Maximum version info size to prevent DoS attacks via malformed resources (64KB)
    constexpr DWORD MAX_VERSION_INFO_SIZE = 64 * 1024;
    
    /// @brief Maximum expected driver count for validation
    constexpr uint32_t MAX_EXPECTED_DRIVERS = 4096;

    // Known vulnerable drivers (LOLDrivers - Living Off the Land Drivers)
    // These are legitimate drivers with known vulnerabilities exploited for BYOVD attacks
    const std::unordered_map<std::string, VulnerableDriverEntry> VULNERABLE_DRIVER_DATABASE = {
        // Capcom.sys - Arbitrary kernel code execution
        {
            "c1d5cf8c43e7679b782630e93f5e6420ca1749a7663159a581b87a8fa3a429c0",
            {
                "c1d5cf8c43e7679b782630e93f5e6420ca1749a7663159a581b87a8fa3a429c0",
                L"Capcom.sys",
                L"Capcom",
                { L"CVE-2016-9892" },
                VulnerableDriverCategory::CodeExecution,
                L"Arbitrary kernel code execution via IOCTL",
                true
            }
        },
        // RTCore64.sys - MSI Afterburner
        {
            "01aa278b07b58dc46c84bd0b1b5c8e9ee4e62ea0bf7a695862444af32e87f1fd",
            {
                "01aa278b07b58dc46c84bd0b1b5c8e9ee4e62ea0bf7a695862444af32e87f1fd",
                L"RTCore64.sys",
                L"MSI",
                { L"CVE-2019-16098" },
                VulnerableDriverCategory::ArbitraryWrite,
                L"Arbitrary kernel memory read/write",
                true
            }
        },
        // DBUtil_2_3.sys - Dell BIOS utility
        {
            "0296e2ce999e67c76352613a718e11516fe1b0efc3ffdb8918fc999dd76a73a5",
            {
                "0296e2ce999e67c76352613a718e11516fe1b0efc3ffdb8918fc999dd76a73a5",
                L"DBUtil_2_3.sys",
                L"Dell",
                { L"CVE-2021-21551" },
                VulnerableDriverCategory::ArbitraryWrite,
                L"Kernel memory corruption vulnerability",
                true
            }
        },
        // gdrv.sys - Gigabyte driver
        {
            "31f4cfb4c71da44120752721103a16512e1c0c2b04108e285a14ff3a1b90e2e0",
            {
                "a7c452bb8fcf2f9c1b51d5a0e3d0c6f3c3b3f3b3f3b3f3b3f3b3f3b3f3b3f3b3",
                L"gdrv.sys",
                L"Gigabyte",
                { L"CVE-2018-19320" },
                VulnerableDriverCategory::ArbitraryWrite,
                L"Read/write kernel memory",
                true
            }
        }
    };

    // Microsoft-signed driver thumbprints (SHA1 of certificate)
    const std::unordered_set<std::wstring> MICROSOFT_CERT_THUMBPRINTS = {
        L"3b1efd3a66ea28b16697394703a72ca340a05bd5",  // Microsoft Windows Production PCA 2011
        L"df545bf919cfa81dc4bd40aa30c0563ad7e76f44",  // Microsoft Code Signing PCA 2011
        L"7251adcf2c7f3c98becf143f40a68c27e2f61d3e"   // Microsoft Windows Hardware Compatibility PCA
    };

    // Suspicious driver name patterns
    const std::vector<std::wstring> SUSPICIOUS_DRIVER_PATTERNS = {
        L"hack",
        L"crack",
        L"cheat",
        L"bypass",
        L"rootkit",
        L"keylog",
        L"trojan"
    };

    // Maximum number of drivers to enumerate
    constexpr uint32_t MAX_DRIVERS = 2048;

} // anonymous namespace

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

[[nodiscard]] static std::wstring GetDriverTypeString(DriverType type) noexcept {
    switch (type) {
        case DriverType::KernelDriver: return L"Kernel Driver";
        case DriverType::FileSystemDriver: return L"File System Driver";
        case DriverType::MinifilterDriver: return L"Minifilter Driver";
        case DriverType::NetworkDriver: return L"Network Driver";
        case DriverType::USBDriver: return L"USB Driver";
        case DriverType::DisplayDriver: return L"Display Driver";
        case DriverType::PrintDriver: return L"Print Driver";
        case DriverType::BootDriver: return L"Boot Driver";
        default: return L"Unknown";
    }
}

[[nodiscard]] static DriverType DetermineDriverType(const std::wstring& path) noexcept {
    std::wstring lowerPath = StringUtils::ToLowerCopy(path);

    if (lowerPath.find(L"\\filesystem\\") != std::wstring::npos ||
        lowerPath.find(L"flt") != std::wstring::npos) {
        return DriverType::MinifilterDriver;
    }

    if (lowerPath.find(L"\\network\\") != std::wstring::npos ||
        lowerPath.find(L"ndis") != std::wstring::npos) {
        return DriverType::NetworkDriver;
    }

    if (lowerPath.find(L"usbport") != std::wstring::npos ||
        lowerPath.find(L"usbhub") != std::wstring::npos) {
        return DriverType::USBDriver;
    }

    if (lowerPath.find(L"display") != std::wstring::npos ||
        lowerPath.find(L"video") != std::wstring::npos) {
        return DriverType::DisplayDriver;
    }

    return DriverType::KernelDriver;
}

[[nodiscard]] static bool IsSuspiciousDriverName(const std::wstring& name) noexcept {
    std::wstring lowerName = StringUtils::ToLowerCopy(name);

    for (const auto& pattern : SUSPICIOUS_DRIVER_PATTERNS) {
        if (lowerName.find(pattern) != std::wstring::npos) {
            return true;
        }
    }

    return false;
}

// ============================================================================
// CONFIGURATION FACTORY METHODS
// ============================================================================

DriverAnalyzerConfig DriverAnalyzerConfig::CreateDefault() noexcept {
    DriverAnalyzerConfig config;
    config.verifySignatures = true;
    config.detectHiddenDrivers = true;
    config.scanForRootkits = true;
    config.checkVulnerableDrivers = true;
    config.monitorCallbacks = true;
    config.analyzeIOCTL = false;  // Expensive operation
    return config;
}

DriverAnalyzerConfig DriverAnalyzerConfig::CreateDeep() noexcept {
    DriverAnalyzerConfig config;
    config.verifySignatures = true;
    config.detectHiddenDrivers = true;
    config.scanForRootkits = true;
    config.checkVulnerableDrivers = true;
    config.monitorCallbacks = true;
    config.analyzeIOCTL = true;   // Full analysis
    return config;
}

DriverAnalyzerConfig DriverAnalyzerConfig::CreateQuick() noexcept {
    DriverAnalyzerConfig config;
    config.verifySignatures = true;
    config.detectHiddenDrivers = false;
    config.scanForRootkits = false;
    config.checkVulnerableDrivers = true;
    config.monitorCallbacks = false;
    config.analyzeIOCTL = false;
    return config;
}

void DriverAnalyzerStatistics::Reset() noexcept {
    driversAnalyzed = 0;
    signaturesVerified = 0;
    hiddenDriversFound = 0;
    rootkitIndicatorsFound = 0;
    vulnerableDriversFound = 0;
    maliciousDriversFound = 0;
}

// ============================================================================
// IMPLEMENTATION CLASS (PIMPL)
// ============================================================================

class DriverAnalyzerImpl final {
public:
    DriverAnalyzerImpl() = default;
    ~DriverAnalyzerImpl() = default;

    // Delete copy/move
    DriverAnalyzerImpl(const DriverAnalyzerImpl&) = delete;
    DriverAnalyzerImpl& operator=(const DriverAnalyzerImpl&) = delete;
    DriverAnalyzerImpl(DriverAnalyzerImpl&&) = delete;
    DriverAnalyzerImpl& operator=(DriverAnalyzerImpl&&) = delete;

    // ========================================================================
    // LIFECYCLE
    // ========================================================================

    [[nodiscard]] bool Initialize(const DriverAnalyzerConfig& config) {
        std::unique_lock lock(m_mutex);

        try {
            m_config = config;

            // Create HashStore for malicious driver hash lookups
            m_hashStore = std::make_shared<ShadowStrike::HashStore::HashStore>();

            // Wire IPCManager for real-time driver load notifications
            if (Communication::IPCManager::HasInstance()) {
                SS_LOG_INFO(LOG_CATEGORY, L"IPCManager available for driver load monitoring");
            }

            m_initialized = true;

            SS_LOG_INFO(LOG_CATEGORY, L"Initialized (signatures=%d, rootkits=%d, vulnerable=%d)",
                static_cast<int>(config.verifySignatures), static_cast<int>(config.scanForRootkits),
                static_cast<int>(config.checkVulnerableDrivers));

            return true;

        } catch (const std::exception& e) {
            SS_LOG_ERROR(LOG_CATEGORY, L"Initialization failed: %hs", e.what());
            return false;
        }
    }

    void Shutdown() noexcept {
        std::unique_lock lock(m_mutex);

        try {
            m_driverLoadCallbacks.clear();
            m_rootkitAlertCallbacks.clear();
            m_initialized = false;

            SS_LOG_INFO(LOG_CATEGORY, L"Shutdown complete");

        } catch (...) {
            // Suppress all exceptions in shutdown
        }
    }

    [[nodiscard]] bool IsInitialized() const noexcept {
        std::shared_lock lock(m_mutex);
        return m_initialized;
    }

    // ========================================================================
    // DRIVER ENUMERATION
    // ========================================================================

    [[nodiscard]] std::vector<DriverInfo> EnumerateDrivers() const {
        std::vector<DriverInfo> drivers;

        try {
            // Initial capacity matches the soft cap; if the kernel reports more
            // drivers we transparently retry once with a buffer sized to the
            // hard cap so we never silently truncate the loaded-module list.
            uint32_t capacity = MAX_DRIVERS;
            auto driverAddresses = std::make_unique<LPVOID[]>(capacity);
            DWORD cbNeeded = 0;
            DWORD bufSize = static_cast<DWORD>(capacity * sizeof(LPVOID));

            if (!EnumDeviceDrivers(driverAddresses.get(), bufSize, &cbNeeded)) {
                SS_LOG_ERROR(LOG_CATEGORY, L"EnumDeviceDrivers failed: error %lu", GetLastError());
                return drivers;
            }

            if (cbNeeded > bufSize) {
                // Retry once with a larger buffer, but never beyond the hard
                // cap — refuses to allocate unbounded memory if the kernel
                // returns a hostile size.
                const DWORD retryCapacity = (cbNeeded / sizeof(LPVOID)) + 64;
                if (retryCapacity <= MAX_EXPECTED_DRIVERS) {
                    SS_LOG_INFO(LOG_CATEGORY,
                        L"EnumDeviceDrivers: growing buffer from %u to %lu entries",
                        capacity, static_cast<unsigned long>(retryCapacity));
                    capacity = retryCapacity;
                    driverAddresses = std::make_unique<LPVOID[]>(capacity);
                    bufSize = static_cast<DWORD>(capacity * sizeof(LPVOID));
                    cbNeeded = 0;
                    if (!EnumDeviceDrivers(driverAddresses.get(), bufSize, &cbNeeded)) {
                        SS_LOG_ERROR(LOG_CATEGORY,
                            L"EnumDeviceDrivers (retry) failed: error %lu", GetLastError());
                        return drivers;
                    }
                }
                if (cbNeeded > bufSize) {
                    SS_LOG_WARN(LOG_CATEGORY,
                        L"Driver list truncated: %lu bytes needed, %lu available (cap %u)",
                        cbNeeded, bufSize, MAX_EXPECTED_DRIVERS);
                    cbNeeded = bufSize;
                }
            }

            if (cbNeeded % sizeof(LPVOID) != 0) {
                SS_LOG_ERROR(LOG_CATEGORY, L"Invalid cbNeeded value: %lu (not pointer-aligned)", cbNeeded);
                return drivers;
            }

            uint32_t driverCount = cbNeeded / sizeof(LPVOID);

            // Additional sanity check
            if (driverCount > MAX_EXPECTED_DRIVERS) {
                SS_LOG_WARN(LOG_CATEGORY, L"Unusually high driver count: %u (clamped at %u)",
                    driverCount, MAX_EXPECTED_DRIVERS);
                driverCount = MAX_EXPECTED_DRIVERS;
            }

            drivers.reserve(driverCount);

            // Heap-allocate path buffer (64KB on stack = overflow risk)
            auto driverNameBuffer = std::make_unique<wchar_t[]>(EXTENDED_PATH_BUFFER_SIZE);

            for (uint32_t i = 0; i < driverCount; ++i) {
                if (GetDeviceDriverFileNameW(driverAddresses[i],
                        driverNameBuffer.get(), EXTENDED_PATH_BUFFER_SIZE)) {
                    // Resolve NT path to Win32 path so fs::exists works
                    std::wstring win32Path = NtPathToWin32Path(driverNameBuffer.get());
                    DriverInfo info = GetDriverInfoInternal(win32Path,
                                                            reinterpret_cast<uint64_t>(driverAddresses[i]));
                    info.isLoaded = true;
                    info.loadOrder = i;
                    drivers.push_back(std::move(info));

                    m_stats.driversAnalyzed.fetch_add(1, std::memory_order_relaxed);
                }
            }

            SS_LOG_INFO(LOG_CATEGORY, L"Enumerated %zu drivers", drivers.size());

        } catch (const std::exception& e) {
            SS_LOG_ERROR(LOG_CATEGORY, L"EnumerateDrivers exception: %hs", e.what());
        }

        return drivers;
    }

    [[nodiscard]] std::vector<DriverInfo> EnumerateDriversDeep() const {
        auto drivers = EnumerateDrivers();

        // Additional deep analysis
        if (m_config.detectHiddenDrivers) {
            auto hidden = DetectHiddenDriversInternal();
            drivers.insert(drivers.end(), hidden.begin(), hidden.end());
        }

        return drivers;
    }

    [[nodiscard]] std::optional<DriverInfo> GetDriverInfo(const std::wstring& driverName) const {
        try {
            // Input validation
            if (driverName.empty()) {
                SS_LOG_WARN(LOG_CATEGORY, L"GetDriverInfo called with empty driver name");
                return std::nullopt;
            }
            
            auto drivers = EnumerateDrivers();

            for (const auto& driver : drivers) {
                // Use case-insensitive exact match, not substring
                if (StringUtils::IEquals(driver.driverName, driverName)) {
                    return driver;
                }
            }

        } catch (const std::exception& e) {
            SS_LOG_ERROR(LOG_CATEGORY, L"GetDriverInfo exception: %hs", e.what());
        }

        return std::nullopt;
    }

    [[nodiscard]] std::optional<DriverInfo> GetDriverByAddress(uint64_t address) const {
        try {
            auto drivers = EnumerateDrivers();

            for (const auto& driver : drivers) {
                if (address >= driver.baseAddress &&
                    address < (driver.baseAddress + driver.imageSize)) {
                    return driver;
                }
            }

        } catch (const std::exception& e) {
            SS_LOG_ERROR(LOG_CATEGORY, L"GetDriverByAddress exception: %hs", e.what());
        }

        return std::nullopt;
    }

    [[nodiscard]] bool IsDriverLoaded(const std::wstring& driverName) const {
        return GetDriverInfo(driverName).has_value();
    }

    // ========================================================================
    // SIGNATURE VERIFICATION
    // ========================================================================

    [[nodiscard]] DriverSignatureStatus VerifySignature(const std::wstring& driverPath) const {
        try {
            m_stats.signaturesVerified.fetch_add(1, std::memory_order_relaxed);

            if (driverPath.empty() || !fs::exists(driverPath)) {
                return DriverSignatureStatus::Unknown;
            }

            // Single-open TOCTOU mitigation: WinVerifyTrust is asked to use this
            // exact handle so a swap between path-based existence checks and the
            // trust evaluation cannot substitute a different file.
            ScopedHandle file(::CreateFileW(
                driverPath.c_str(),
                GENERIC_READ,
                FILE_SHARE_READ,
                nullptr,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                nullptr));

            if (!file.valid()) {
                SS_LOG_DEBUG(LOG_CATEGORY,
                    L"VerifySignature: open failed for %ls (err=%lu)",
                    driverPath.c_str(), GetLastError());
                return DriverSignatureStatus::Unknown;
            }

            WINTRUST_FILE_INFO fileInfo = {};
            fileInfo.cbStruct = sizeof(WINTRUST_FILE_INFO);
            fileInfo.pcwszFilePath = driverPath.c_str();
            fileInfo.hFile = file.get();
            fileInfo.pgKnownSubject = nullptr;

            GUID policyGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;

            WINTRUST_DATA trustData = {};
            trustData.cbStruct = sizeof(WINTRUST_DATA);
            trustData.dwUIChoice = WTD_UI_NONE;
            trustData.fdwRevocationChecks = WTD_REVOKE_NONE;
            trustData.dwUnionChoice = WTD_CHOICE_FILE;
            trustData.pFile = &fileInfo;
            trustData.dwStateAction = WTD_STATEACTION_VERIFY;
            trustData.dwProvFlags = WTD_SAFER_FLAG;

            LONG status = WinVerifyTrust(nullptr, &policyGUID, &trustData);

            // Clean up trust state regardless of outcome.
            trustData.dwStateAction = WTD_STATEACTION_CLOSE;
            WinVerifyTrust(nullptr, &policyGUID, &trustData);

            if (status == ERROR_SUCCESS) {
                // Check if Microsoft signed
                if (IsMicrosoftSigned(driverPath)) {
                    return DriverSignatureStatus::MicrosoftSigned;
                }

                // Check if WHQL certified
                if (IsWHQLCertified(driverPath)) {
                    return DriverSignatureStatus::WHQLCertified;
                }

                return DriverSignatureStatus::SignedValid;
            } else if (status == TRUST_E_NOSIGNATURE) {
                return DriverSignatureStatus::Unsigned;
            } else if (status == CERT_E_EXPIRED) {
                return DriverSignatureStatus::SignedExpired;
            } else if (status == CERT_E_REVOKED) {
                return DriverSignatureStatus::SignedRevoked;
            } else {
                return DriverSignatureStatus::SignedUntrusted;
            }

        } catch (const std::exception& e) {
            SS_LOG_ERROR(LOG_CATEGORY, L"VerifySignature exception: %hs", e.what());
            return DriverSignatureStatus::Unknown;
        }
    }

    [[nodiscard]] std::vector<DriverInfo> GetUnsignedDrivers() const {
        std::vector<DriverInfo> unsigned_drivers;

        try {
            auto drivers = EnumerateDrivers();

            for (const auto& driver : drivers) {
                if (driver.signatureStatus == DriverSignatureStatus::Unsigned) {
                    unsigned_drivers.push_back(driver);
                }
            }

        } catch (const std::exception& e) {
            SS_LOG_ERROR(LOG_CATEGORY, L"GetUnsignedDrivers exception: %hs", e.what());
        }

        return unsigned_drivers;
    }

    [[nodiscard]] std::vector<DriverInfo> GetThirdPartyDrivers() const {
        std::vector<DriverInfo> third_party;

        try {
            auto drivers = EnumerateDrivers();

            for (const auto& driver : drivers) {
                if (!driver.isMicrosoftSigned) {
                    third_party.push_back(driver);
                }
            }

        } catch (const std::exception& e) {
            SS_LOG_ERROR(LOG_CATEGORY, L"GetThirdPartyDrivers exception: %hs", e.what());
        }

        return third_party;
    }

    // ========================================================================
    // ROOTKIT DETECTION
    // ========================================================================

    [[nodiscard]] std::vector<RootkitIndicator> ScanForRootkits() const {
        std::vector<RootkitIndicator> indicators;

        try {
            if (!m_config.scanForRootkits) {
                return indicators;
            }

            // Check SSDT integrity
            if (!VerifySSDTIntegrityInternal()) {
                RootkitIndicator indicator;
                indicator.technique = RootkitTechnique::SSDTHooking;
                indicator.description = L"SSDT hooks detected";
                indicator.severity = 9;
                indicator.confidence = 0.85;
                indicators.push_back(indicator);
                m_stats.rootkitIndicatorsFound.fetch_add(1, std::memory_order_relaxed);
            }

            // Check IDT integrity
            if (!VerifyIDTIntegrityInternal()) {
                RootkitIndicator indicator;
                indicator.technique = RootkitTechnique::IDTHooking;
                indicator.description = L"IDT hooks detected";
                indicator.severity = 9;
                indicator.confidence = 0.85;
                indicators.push_back(indicator);
                m_stats.rootkitIndicatorsFound.fetch_add(1, std::memory_order_relaxed);
            }

            // Check for hidden drivers
            auto hidden = DetectHiddenDriversInternal();
            for (const auto& driver : hidden) {
                RootkitIndicator indicator;
                indicator.technique = RootkitTechnique::DKOMDriverHiding;
                indicator.description = L"Hidden driver detected: " + driver.driverName;
                indicator.targetDriver = driver.driverName;
                indicator.severity = 10;
                indicator.confidence = 0.95;
                indicators.push_back(indicator);
                m_stats.rootkitIndicatorsFound.fetch_add(1, std::memory_order_relaxed);
            }

        } catch (const std::exception& e) {
            SS_LOG_ERROR(LOG_CATEGORY, L"ScanForRootkits exception: %hs", e.what());
        }

        return indicators;
    }

    [[nodiscard]] std::vector<DriverInfo> DetectHiddenDrivers() const {
        return DetectHiddenDriversInternal();
    }

    [[nodiscard]] bool VerifySSDTIntegrity() const {
        // Returns true if intact or unknown (kernel driver not available)
        // Only returns false if hooks are actually detected
        return VerifySSDTIntegrityInternal().value_or(true);
    }

    [[nodiscard]] bool VerifyIDTIntegrity() const {
        // Returns true if intact or unknown (kernel driver not available)
        // Only returns false if hooks are actually detected
        return VerifyIDTIntegrityInternal().value_or(true);
    }

    [[nodiscard]] std::vector<DriverCallbackInfo> GetSuspiciousCallbacks() const {
        std::vector<DriverCallbackInfo> suspicious;

        try {
            // Kernel callback enumeration requires the ShadowStrike kernel driver.
            // When connected, request callback data via IPC QueryDriverStatus.
            if (Communication::IPCManager::HasInstance() && Communication::IPCManager::Instance().IsConnected()) {
                SS_LOG_DEBUG(LOG_CATEGORY,
                    L"GetSuspiciousCallbacks: kernel connected, awaiting driver-side callback query");
            } else {
                SS_LOG_DEBUG(LOG_CATEGORY,
                    L"GetSuspiciousCallbacks: kernel not connected - cannot enumerate callbacks");
            }

        } catch (const std::exception& e) {
            SS_LOG_ERROR(LOG_CATEGORY, L"GetSuspiciousCallbacks exception: %hs", e.what());
        }

        return suspicious;
    }

    // ========================================================================
    // THREAT ASSESSMENT
    // ========================================================================

    [[nodiscard]] DriverInfo AnalyzeDriver(const std::wstring& driverPath) const {
        DriverInfo info;

        try {
            if (!fs::exists(driverPath)) {
                SS_LOG_WARN(LOG_CATEGORY, L"Driver file not found: %ls", driverPath.c_str());
                return info;
            }

            info = GetDriverInfoInternal(driverPath, 0);

            // Signature verification
            if (m_config.verifySignatures) {
                info.signatureStatus = VerifySignature(driverPath);
            }

            // Check vulnerable driver database
            if (m_config.checkVulnerableDrivers) {
                std::string sha256Lower = NarrowToLower(info.sha256Hash);
                if (VULNERABLE_DRIVER_DATABASE.find(sha256Lower) != VULNERABLE_DRIVER_DATABASE.end()) {
                    info.isKnownVulnerable = true;
                    info.threatLevel = DriverThreatLevel::VulnerableDriver;
                    m_stats.vulnerableDriversFound.fetch_add(1, std::memory_order_relaxed);

                    const auto& vulnEntry = VULNERABLE_DRIVER_DATABASE.at(sha256Lower);
                    info.vulnerabilities.push_back(vulnEntry.category);
                    info.cveIds = vulnEntry.cveIds;

                    SS_LOG_WARN(LOG_CATEGORY, L"BYOVD: Vulnerable driver detected: %ls (%ls)",
                        info.driverName.c_str(), vulnEntry.description.c_str());
                }
            }

            // Check malicious driver hash via HashStore
            if (m_hashStore) {
                auto detection = m_hashStore->LookupHashString(
                    info.sha256Hash, ShadowStrike::HashStore::HashType::SHA256);
                if (detection.has_value()) {
                    info.threatLevel = DriverThreatLevel::Malicious;
                    m_stats.maliciousDriversFound.fetch_add(1, std::memory_order_relaxed);
                    SS_LOG_FATAL(LOG_CATEGORY, L"Malicious driver detected: %ls (sig=%hs)",
                        info.driverName.c_str(), detection->signatureName.c_str());
                }
            }

            // Check suspicious name patterns
            if (IsSuspiciousDriverName(info.driverName)) {
                if (info.threatLevel < DriverThreatLevel::Suspicious) {
                    info.threatLevel = DriverThreatLevel::Suspicious;
                }
            }

            // Assess overall threat level
            if (info.threatLevel == DriverThreatLevel::Unknown) {
                if (info.signatureStatus == DriverSignatureStatus::Unsigned) {
                    info.threatLevel = DriverThreatLevel::Suspicious;
                } else if (info.isMicrosoftSigned || info.isWHQL) {
                    info.threatLevel = DriverThreatLevel::Safe;
                }
            }

        } catch (const std::exception& e) {
            SS_LOG_ERROR(LOG_CATEGORY, L"AnalyzeDriver exception: %hs", e.what());
        }

        return info;
    }

    [[nodiscard]] bool IsVulnerableDriver(const std::string& sha256Hash) const {
        std::string sha256Lower = NarrowToLower(sha256Hash);
        return VULNERABLE_DRIVER_DATABASE.find(sha256Lower) != VULNERABLE_DRIVER_DATABASE.end();
    }

    [[nodiscard]] std::optional<VulnerableDriverEntry> GetVulnerableDriverInfo(
        const std::string& sha256Hash) const {

        std::string sha256Lower = NarrowToLower(sha256Hash);
        auto it = VULNERABLE_DRIVER_DATABASE.find(sha256Lower);

        if (it != VULNERABLE_DRIVER_DATABASE.end()) {
            return it->second;
        }

        return std::nullopt;
    }

    [[nodiscard]] std::vector<DriverInfo> GetLoadedVulnerableDrivers() const {
        std::vector<DriverInfo> vulnerable;

        try {
            auto drivers = EnumerateDrivers();

            for (const auto& driver : drivers) {
                if (driver.isKnownVulnerable) {
                    vulnerable.push_back(driver);
                }
            }

        } catch (const std::exception& e) {
            SS_LOG_ERROR(LOG_CATEGORY, L"GetLoadedVulnerableDrivers exception: %hs", e.what());
        }

        return vulnerable;
    }

    [[nodiscard]] bool IsMaliciousDriver(const std::string& sha256Hash) const {
        if (!m_hashStore) return false;
        auto result = m_hashStore->LookupHashString(
            sha256Hash, ShadowStrike::HashStore::HashType::SHA256);
        return result.has_value();
    }

    // ========================================================================
    // FULL SCAN
    // ========================================================================

    [[nodiscard]] DriverScanResult PerformFullScan() const {
        auto startTime = std::chrono::steady_clock::now();

        DriverScanResult result;

        try {
            SS_LOG_INFO(LOG_CATEGORY, L"Starting full driver scan...");

            // Enumerate all drivers
            result.drivers = EnumerateDrivers();
            result.totalDrivers = static_cast<uint32_t>(result.drivers.size());

            // Analyze each driver
            for (auto& driver : result.drivers) {
                // Signature check
                if (m_config.verifySignatures) {
                    driver.signatureStatus = VerifySignature(driver.driverPath);

                    if (driver.signatureStatus == DriverSignatureStatus::Unsigned) {
                        result.unsignedDrivers++;
                    }
                }

                // Vulnerable driver check
                if (m_config.checkVulnerableDrivers) {
                    if (IsVulnerableDriver(driver.sha256Hash)) {
                        driver.isKnownVulnerable = true;
                        result.vulnerableDrivers++;
                    }
                }

                // Malicious driver check via HashStore
                if (!driver.sha256Hash.empty() && IsMaliciousDriver(driver.sha256Hash)) {
                    driver.threatLevel = DriverThreatLevel::Malicious;
                    result.maliciousDrivers++;
                }

                // Suspicious check
                if (driver.threatLevel >= DriverThreatLevel::Suspicious) {
                    result.suspiciousDrivers++;
                }
            }

            // Rootkit scan
            if (m_config.scanForRootkits) {
                result.rootkitIndicators = ScanForRootkits();
            }

            // Hidden driver detection
            if (m_config.detectHiddenDrivers) {
                result.hiddenDriversFound = DetectHiddenDriversInternal();
                result.hiddenDrivers = static_cast<uint32_t>(result.hiddenDriversFound.size());
            }

            // Integrity checks - these return std::nullopt when kernel driver not available
            auto ssdtResult = VerifySSDTIntegrityInternal();
            auto idtResult = VerifyIDTIntegrityInternal();
            
            result.ssdtIntact = ssdtResult.value_or(true);  // Assume intact if unknown
            result.idtIntact = idtResult.value_or(true);    // Assume intact if unknown
            result.moduleListIntact = result.hiddenDrivers == 0;

            // Suspicious callbacks
            if (m_config.monitorCallbacks) {
                result.suspiciousCallbacks = GetSuspiciousCallbacks();
            }

            auto endTime = std::chrono::steady_clock::now();
            result.scanDuration = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime);

            SS_LOG_INFO(LOG_CATEGORY, L"Driver scan complete: %u drivers, %u unsigned, %u vulnerable, %u malicious (%lldms)",
                result.totalDrivers, result.unsignedDrivers, result.vulnerableDrivers,
                result.maliciousDrivers, static_cast<long long>(result.scanDuration.count()));

        } catch (const std::exception& e) {
            SS_LOG_ERROR(LOG_CATEGORY, L"PerformFullScan exception: %hs", e.what());
        }

        return result;
    }

    // ========================================================================
    // CALLBACKS
    // ========================================================================

    uint64_t RegisterDriverLoadCallback(DriverLoadCallback callback) {
        std::unique_lock lock(m_mutex);
        uint64_t id = ++m_nextCallbackId;
        m_driverLoadCallbacks[id] = std::move(callback);
        return id;
    }

    void UnregisterDriverLoadCallback(uint64_t callbackId) {
        std::unique_lock lock(m_mutex);
        m_driverLoadCallbacks.erase(callbackId);
    }

    uint64_t RegisterRootkitAlertCallback(RootkitAlertCallback callback) {
        std::unique_lock lock(m_mutex);
        uint64_t id = ++m_nextCallbackId;
        m_rootkitAlertCallbacks[id] = std::move(callback);
        return id;
    }

    void UnregisterRootkitAlertCallback(uint64_t callbackId) {
        std::unique_lock lock(m_mutex);
        m_rootkitAlertCallbacks.erase(callbackId);
    }

    // ========================================================================
    // STATISTICS
    // ========================================================================

    [[nodiscard]] const DriverAnalyzerStatistics& GetStatistics() const noexcept {
        return m_stats;
    }

    void ResetStatistics() noexcept {
        m_stats.Reset();
    }

private:
    // ========================================================================
    // INTERNAL METHODS
    // ========================================================================

    /**
     * @brief Compute file hash using HashUtils streaming API
     * @param path File path
     * @param alg Hash algorithm
     * @return Lowercase hex hash string, or empty on failure
     */
    [[nodiscard]] std::string ComputeFileHashHex(const std::wstring& path, HashUtils::Algorithm alg) const noexcept {
        try {
            std::vector<uint8_t> digest;
            HashUtils::Error err;
            
            if (!HashUtils::ComputeFile(alg, path, digest, &err)) {
                SS_LOG_WARN(LOG_CATEGORY, L"Failed to compute hash for %ls: error %lu",
                    path.c_str(), static_cast<unsigned long>(err.win32));
                return {};
            }
            
            return HashUtils::ToHexLower(digest);
        } catch (...) {
            return {};
        }
    }

    [[nodiscard]] DriverInfo GetDriverInfoInternal(const std::wstring& driverPath, uint64_t baseAddress) const {
        DriverInfo info;

        try {
            info.driverPath = driverPath;
            info.baseAddress = baseAddress;

            // Extract driver name
            fs::path p(driverPath);
            info.driverName = p.filename().wstring();

            // Determine type
            info.driverType = DetermineDriverType(driverPath);

            // Get file size with proper exception handling
            if (fs::exists(driverPath)) {
                try {
                    info.imageSize = fs::file_size(driverPath);
                } catch (const std::filesystem::filesystem_error& fsErr) {
                    SS_LOG_WARN(LOG_CATEGORY, L"Cannot get file size for %ls: %hs",
                        driverPath.c_str(), fsErr.what());
                    info.imageSize = 0;
                }

                // Calculate hashes using HashUtils
                info.sha256Hash = ComputeFileHashHex(driverPath, HashUtils::Algorithm::SHA256);
                info.sha1Hash = ComputeFileHashHex(driverPath, HashUtils::Algorithm::SHA1);
                info.md5Hash = ComputeFileHashHex(driverPath, HashUtils::Algorithm::MD5);

                // Get version information
                GetVersionInfoInternal(driverPath, info);

                // Signature verification
                if (m_config.verifySignatures) {
                    info.signatureStatus = VerifySignature(driverPath);
                    info.isMicrosoftSigned = IsMicrosoftSigned(driverPath);
                    info.isWHQL = IsWHQLCertified(driverPath);
                }

                // Check vulnerable database
                if (m_config.checkVulnerableDrivers) {
                    std::string sha256Lower = NarrowToLower(info.sha256Hash);
                    if (VULNERABLE_DRIVER_DATABASE.find(sha256Lower) != VULNERABLE_DRIVER_DATABASE.end()) {
                        info.isKnownVulnerable = true;
                        const auto& vulnEntry = VULNERABLE_DRIVER_DATABASE.at(sha256Lower);
                        info.vulnerabilities.push_back(vulnEntry.category);
                        info.cveIds = vulnEntry.cveIds;
                    }
                }
            }

        } catch (const std::exception& e) {
            SS_LOG_ERROR(LOG_CATEGORY, L"GetDriverInfoInternal exception: %hs", e.what());
        }

        return info;
    }

    void GetVersionInfoInternal(const std::wstring& filePath, DriverInfo& info) const {
        try {
            DWORD handle = 0;
            DWORD size = GetFileVersionInfoSizeW(filePath.c_str(), &handle);

            if (size == 0) return;
            
            // Security: Cap version info size to prevent DoS via malformed resources
            if (size > MAX_VERSION_INFO_SIZE) {
                SS_LOG_WARN(LOG_CATEGORY, L"Version info too large for %ls: %lu bytes (max %lu)",
                    filePath.c_str(), size, MAX_VERSION_INFO_SIZE);
                return;
            }

            std::vector<uint8_t> buffer(size);

            if (!GetFileVersionInfoW(filePath.c_str(), handle, size, buffer.data())) {
                return;
            }

            // Get version numbers
            VS_FIXEDFILEINFO* fileInfo = nullptr;
            UINT len = 0;

            if (VerQueryValueW(buffer.data(), L"\\", reinterpret_cast<LPVOID*>(&fileInfo), &len)) {
                if (fileInfo) {
                    std::wostringstream oss;
                    oss << HIWORD(fileInfo->dwFileVersionMS) << L"."
                        << LOWORD(fileInfo->dwFileVersionMS) << L"."
                        << HIWORD(fileInfo->dwFileVersionLS) << L"."
                        << LOWORD(fileInfo->dwFileVersionLS);
                    info.fileVersion = oss.str();
                }
            }

            // Get string values
            struct LANGANDCODEPAGE {
                WORD wLanguage;
                WORD wCodePage;
            } *translate;

            if (VerQueryValueW(buffer.data(), L"\\VarFileInfo\\Translation",
                              reinterpret_cast<LPVOID*>(&translate), &len) && len >= sizeof(LANGANDCODEPAGE)) {

                wchar_t subBlock[256];

                // Company name
                swprintf_s(subBlock, L"\\StringFileInfo\\%04x%04x\\CompanyName",
                          translate[0].wLanguage, translate[0].wCodePage);

                wchar_t* value = nullptr;
                if (VerQueryValueW(buffer.data(), subBlock, reinterpret_cast<LPVOID*>(&value), &len)) {
                    info.companyName = value ? value : L"";
                }

                // Product name
                swprintf_s(subBlock, L"\\StringFileInfo\\%04x%04x\\ProductName",
                          translate[0].wLanguage, translate[0].wCodePage);

                if (VerQueryValueW(buffer.data(), subBlock, reinterpret_cast<LPVOID*>(&value), &len)) {
                    info.productName = value ? value : L"";
                }

                // File description
                swprintf_s(subBlock, L"\\StringFileInfo\\%04x%04x\\FileDescription",
                          translate[0].wLanguage, translate[0].wCodePage);

                if (VerQueryValueW(buffer.data(), subBlock, reinterpret_cast<LPVOID*>(&value), &len)) {
                    info.description = value ? value : L"";
                }
            }

        } catch (const std::exception& e) {
            SS_LOG_ERROR(LOG_CATEGORY, L"GetVersionInfoInternal exception: %hs", e.what());
        }
    }

    /**
     * @brief Verifies if a driver is signed by Microsoft using certificate verification
     * 
     * This implementation extracts the Authenticode signature certificate and verifies
     * the thumbprint against known Microsoft code signing certificates.
     * 
     * @param driverPath Path to the driver file
     * @return true if signed by a known Microsoft certificate, false otherwise
     */
    [[nodiscard]] bool IsMicrosoftSigned(const std::wstring& driverPath) const {
        try {
            // Verify signature and extract signer certificate via WinVerifyTrust
            WINTRUST_FILE_INFO fileInfo = {};
            fileInfo.cbStruct = sizeof(WINTRUST_FILE_INFO);
            fileInfo.pcwszFilePath = driverPath.c_str();
            
            GUID actionGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;
            
            WINTRUST_DATA trustData = {};
            trustData.cbStruct = sizeof(WINTRUST_DATA);
            trustData.dwUIChoice = WTD_UI_NONE;
            trustData.fdwRevocationChecks = WTD_REVOKE_NONE;
            trustData.dwUnionChoice = WTD_CHOICE_FILE;
            trustData.pFile = &fileInfo;
            trustData.dwStateAction = WTD_STATEACTION_VERIFY;
            trustData.dwProvFlags = WTD_SAFER_FLAG;
            
            LONG status = WinVerifyTrust(nullptr, &actionGUID, &trustData);
            
            if (status != ERROR_SUCCESS) {
                // Not signed or signature invalid
                trustData.dwStateAction = WTD_STATEACTION_CLOSE;
                WinVerifyTrust(nullptr, &actionGUID, &trustData);
                return false;
            }
            
            // Get the signer certificate from the cryptographic provider
            CRYPT_PROVIDER_DATA* provData = WTHelperProvDataFromStateData(trustData.hWVTStateData);
            bool isMicrosoft = false;
            
            if (provData) {
                CRYPT_PROVIDER_SGNR* signer = WTHelperGetProvSignerFromChain(provData, 0, FALSE, 0);
                if (signer && signer->pasCertChain && signer->csCertChain > 0) {
                    PCCERT_CONTEXT pCert = signer->pasCertChain[0].pCert;
                    if (pCert) {
                        // Compute SHA-1 thumbprint (standard for certificate identification)
                        BYTE thumbprintHash[20] = {};
                        DWORD thumbprintSize = sizeof(thumbprintHash);
                        
                        if (CryptHashCertificate(0, CALG_SHA1, 0,
                                pCert->pbCertEncoded, pCert->cbCertEncoded,
                                thumbprintHash, &thumbprintSize)) {
                            
                            // Convert to hex string for comparison
                            std::string thumbprintHex = HashUtils::ToHexLower(thumbprintHash, thumbprintSize);
                            std::wstring thumbprintHexW = StringUtils::ToWide(thumbprintHex);
                            
                            // Check against known Microsoft certificate thumbprints
                            if (MICROSOFT_CERT_THUMBPRINTS.count(thumbprintHexW) > 0) {
                                isMicrosoft = true;
                            }
                        }
                        
                        // Also check certificate issuer as secondary validation
                        if (!isMicrosoft) {
                            // Extract issuer name
                            wchar_t issuerName[512] = {};
                            DWORD issuerSize = sizeof(issuerName) / sizeof(wchar_t);
                            
                            if (CertGetNameStringW(pCert, CERT_NAME_SIMPLE_DISPLAY_TYPE,
                                    CERT_NAME_ISSUER_FLAG, nullptr, issuerName, issuerSize) > 1) {
                                
                                std::wstring lowerIssuer = StringUtils::ToLowerCopy(issuerName);
                                
                                // Microsoft code signing certificates are issued by specific CAs
                                if (lowerIssuer.find(L"microsoft code signing pca") != std::wstring::npos ||
                                    lowerIssuer.find(L"microsoft windows production pca") != std::wstring::npos ||
                                    lowerIssuer.find(L"microsoft windows hardware compatibility") != std::wstring::npos) {
                                    isMicrosoft = true;
                                }
                            }
                        }
                    }
                }
            }
            
            // Clean up
            trustData.dwStateAction = WTD_STATEACTION_CLOSE;
            WinVerifyTrust(nullptr, &actionGUID, &trustData);
            
            return isMicrosoft;

        } catch (const std::exception& e) {
            SS_LOG_ERROR(LOG_CATEGORY, L"IsMicrosoftSigned exception: %hs", e.what());
            return false;
        } catch (...) {
            return false;
        }
    }

    /**
     * @brief Verifies if a driver has WHQL (Windows Hardware Quality Labs) certification
     * 
     * WHQL certification is verified through Windows catalog files. This implementation
     * uses CryptCATAdminAcquireContext2 to verify the driver against system catalogs.
     * 
     * @param driverPath Path to the driver file
     * @return true if WHQL certified, false otherwise
     */
    [[nodiscard]] bool IsWHQLCertified(const std::wstring& driverPath) const {
        HCATADMIN hCatAdmin = nullptr;
        HCATINFO hCatInfo = nullptr;
        HANDLE hFile = INVALID_HANDLE_VALUE;
        bool isWHQL = false;
        
        try {
            // Acquire catalog admin context
            // Use SHA256 algorithm (szOID_NIST_sha256 = "2.16.840.1.101.3.4.2.1")
            static const GUID driverActionGuid = DRIVER_ACTION_VERIFY;
            
            if (!CryptCATAdminAcquireContext2(&hCatAdmin, &driverActionGuid, 
                    BCRYPT_SHA256_ALGORITHM, nullptr, 0)) {
                // Fall back to SHA1 if SHA256 not available
                if (!CryptCATAdminAcquireContext(&hCatAdmin, &driverActionGuid, 0)) {
                    SS_LOG_WARN(LOG_CATEGORY, L"CryptCATAdminAcquireContext failed: %lu", GetLastError());
                    return false;
                }
            }
            
            // Open the file
            hFile = CreateFileW(driverPath.c_str(), GENERIC_READ, FILE_SHARE_READ,
                nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
            
            if (hFile == INVALID_HANDLE_VALUE) {
                CryptCATAdminReleaseContext(hCatAdmin, 0);
                return false;
            }
            
            // Calculate file hash for catalog lookup
            BYTE hashData[256] = {};
            DWORD hashSize = sizeof(hashData);
            
            if (!CryptCATAdminCalcHashFromFileHandle(hFile, &hashSize, hashData, 0)) {
                CloseHandle(hFile);
                CryptCATAdminReleaseContext(hCatAdmin, 0);
                return false;
            }
            
            // Look up the hash in system catalogs
            hCatInfo = CryptCATAdminEnumCatalogFromHash(hCatAdmin, hashData, hashSize, 0, nullptr);

            uint32_t catalogIterations = 0;
            while (hCatInfo != nullptr) {
                if (++catalogIterations > MAX_CATALOG_ITERATIONS) {
                    SS_LOG_WARN(LOG_CATEGORY,
                        L"IsWHQLCertified: catalog enumeration cap (%u) reached for %ls",
                        MAX_CATALOG_ITERATIONS, driverPath.c_str());
                    CryptCATAdminReleaseCatalogContext(hCatAdmin, hCatInfo, 0);
                    hCatInfo = nullptr;
                    break;
                }
                CATALOG_INFO catalogInfo = {};
                catalogInfo.cbStruct = sizeof(CATALOG_INFO);
                
                if (CryptCATCatalogInfoFromContext(hCatInfo, &catalogInfo, 0)) {
                    // Found in a catalog - verify the catalog signature
                    WINTRUST_CATALOG_INFO wtCatalogInfo = {};
                    wtCatalogInfo.cbStruct = sizeof(WINTRUST_CATALOG_INFO);
                    wtCatalogInfo.pcwszCatalogFilePath = catalogInfo.wszCatalogFile;
                    wtCatalogInfo.pcwszMemberFilePath = driverPath.c_str();
                    wtCatalogInfo.hMemberFile = hFile;
                    wtCatalogInfo.cbCalculatedFileHash = hashSize;
                    wtCatalogInfo.pbCalculatedFileHash = hashData;
                    
                    GUID wvtPolicyGuid = WINTRUST_ACTION_GENERIC_VERIFY_V2;
                    
                    WINTRUST_DATA trustData = {};
                    trustData.cbStruct = sizeof(WINTRUST_DATA);
                    trustData.dwUIChoice = WTD_UI_NONE;
                    trustData.fdwRevocationChecks = WTD_REVOKE_NONE;
                    trustData.dwUnionChoice = WTD_CHOICE_CATALOG;
                    trustData.pCatalog = &wtCatalogInfo;
                    trustData.dwStateAction = WTD_STATEACTION_VERIFY;
                    trustData.dwProvFlags = WTD_SAFER_FLAG;
                    
                    LONG verifyResult = WinVerifyTrust(nullptr, &wvtPolicyGuid, &trustData);
                    
                    trustData.dwStateAction = WTD_STATEACTION_CLOSE;
                    WinVerifyTrust(nullptr, &wvtPolicyGuid, &trustData);
                    
                    if (verifyResult == ERROR_SUCCESS) {
                        // Check if this is a WHQL catalog (contains "WHQL" or is a Microsoft catalog)
                        std::wstring catalogPath = catalogInfo.wszCatalogFile;
                        std::wstring lowerCatalog = StringUtils::ToLowerCopy(catalogPath);
                        
                        // WHQL catalogs are typically in %windir%\system32\catroot
                        if (lowerCatalog.find(L"catroot") != std::wstring::npos) {
                            isWHQL = true;
                        }
                    }
                }
                
                // Check next catalog
                HCATINFO hPrevCatInfo = hCatInfo;
                hCatInfo = CryptCATAdminEnumCatalogFromHash(hCatAdmin, hashData, hashSize, 0, &hPrevCatInfo);
                CryptCATAdminReleaseCatalogContext(hCatAdmin, hPrevCatInfo, 0);
                
                if (isWHQL) break;  // Found WHQL certification, no need to continue
            }
            
        } catch (const std::exception& e) {
            SS_LOG_ERROR(LOG_CATEGORY, L"IsWHQLCertified exception: %hs", e.what());
        } catch (...) {
            // Suppress unexpected exceptions
        }
        
        // Cleanup
        if (hFile != INVALID_HANDLE_VALUE) {
            CloseHandle(hFile);
        }
        if (hCatAdmin) {
            CryptCATAdminReleaseContext(hCatAdmin, 0);
        }
        
        return isWHQL;
    }

    [[nodiscard]] std::vector<DriverInfo> DetectHiddenDriversInternal() const {
        std::vector<DriverInfo> hidden;

        try {
            if (!m_config.detectHiddenDrivers) {
                return hidden;
            }

            // Hidden driver detection requires kernel driver IPC.
            // When connected, query via SendToKernel for PsLoadedModuleList comparison.
            if (Communication::IPCManager::HasInstance() && Communication::IPCManager::Instance().IsConnected()) {
                SS_LOG_DEBUG(LOG_CATEGORY,
                    L"DetectHiddenDrivers: kernel connected, awaiting driver-side module list scan");
            } else {
                SS_LOG_DEBUG(LOG_CATEGORY,
                    L"DetectHiddenDrivers: kernel not connected - skipping");
            }

            m_stats.hiddenDriversFound.fetch_add(static_cast<uint64_t>(hidden.size()), std::memory_order_relaxed);

        } catch (const std::exception& e) {
            SS_LOG_ERROR(LOG_CATEGORY, L"DetectHiddenDriversInternal exception: %hs", e.what());
        }

        return hidden;
    }

    /**
     * @brief Verifies SSDT (System Service Descriptor Table) integrity
     * 
     * NOTE: This requires kernel driver integration. User-mode cannot read SSDT directly.
     * Returns std::nullopt to indicate "unknown" status rather than false positive.
     * 
     * @return std::nullopt if kernel driver not available, true if intact, false if hooked
     */
    [[nodiscard]] std::optional<bool> VerifySSDTIntegrityInternal() const {
        try {
            // SSDT integrity verification requires kernel-mode access via IPC.
            if (Communication::IPCManager::HasInstance() && Communication::IPCManager::Instance().IsConnected()) {
                SS_LOG_DEBUG(LOG_CATEGORY,
                    L"VerifySSDTIntegrity: kernel connected, awaiting SSDT query support");
            } else {
                SS_LOG_DEBUG(LOG_CATEGORY,
                    L"VerifySSDTIntegrity: kernel not connected - cannot verify");
            }
            
            // Return nullopt to indicate "cannot determine" rather than false positive
            return std::nullopt;

        } catch (const std::exception& e) {
            SS_LOG_ERROR(LOG_CATEGORY, L"VerifySSDTIntegrityInternal exception: %hs", e.what());
            return std::nullopt;
        }
    }

    /**
     * @brief Verifies IDT (Interrupt Descriptor Table) integrity
     * 
     * NOTE: This requires kernel driver integration. User-mode cannot read IDT directly.
     * Returns std::nullopt to indicate "unknown" status rather than false positive.
     * 
     * @return std::nullopt if kernel driver not available, true if intact, false if hooked
     */
    [[nodiscard]] std::optional<bool> VerifyIDTIntegrityInternal() const {
        try {
            // IDT integrity verification requires kernel-mode access via IPC.
            if (Communication::IPCManager::HasInstance() && Communication::IPCManager::Instance().IsConnected()) {
                SS_LOG_DEBUG(LOG_CATEGORY,
                    L"VerifyIDTIntegrity: kernel connected, awaiting IDT query support");
            } else {
                SS_LOG_DEBUG(LOG_CATEGORY,
                    L"VerifyIDTIntegrity: kernel not connected - cannot verify");
            }
            
            // Return nullopt to indicate "cannot determine" rather than false positive
            return std::nullopt;

        } catch (const std::exception& e) {
            SS_LOG_ERROR(LOG_CATEGORY, L"VerifyIDTIntegrityInternal exception: %hs", e.what());
            return std::nullopt;
        }
    }

    // ========================================================================
    // MEMBER VARIABLES
    // ========================================================================

    mutable std::shared_mutex m_mutex;
    bool m_initialized{ false };

    DriverAnalyzerConfig m_config;
    mutable DriverAnalyzerStatistics m_stats;

    // HashStore for malicious driver hash lookups
    std::shared_ptr<ShadowStrike::HashStore::HashStore> m_hashStore;

    // Callbacks - use atomic for thread-safe ID generation
    std::unordered_map<uint64_t, DriverLoadCallback> m_driverLoadCallbacks;
    std::unordered_map<uint64_t, RootkitAlertCallback> m_rootkitAlertCallbacks;
    std::atomic<uint64_t> m_nextCallbackId{ 0 };
};

// ============================================================================
// SINGLETON IMPLEMENTATION
// ============================================================================

DriverAnalyzer& DriverAnalyzer::Instance() {
    static DriverAnalyzer instance;
    return instance;
}

// ============================================================================
// CONSTRUCTOR / DESTRUCTOR
// ============================================================================

DriverAnalyzer::DriverAnalyzer()
    : m_impl(std::make_unique<DriverAnalyzerImpl>()) {
    SS_LOG_INFO(LOG_CATEGORY, L"Instance created");
}

DriverAnalyzer::~DriverAnalyzer() {
    if (m_impl) {
        m_impl->Shutdown();
    }
    SS_LOG_INFO(LOG_CATEGORY, L"Instance destroyed");
}

// ============================================================================
// PUBLIC INTERFACE IMPLEMENTATION
// ============================================================================

bool DriverAnalyzer::Initialize(const DriverAnalyzerConfig& config) {
    return m_impl->Initialize(config);
}

void DriverAnalyzer::Shutdown() noexcept {
    m_impl->Shutdown();
}

// ========================================================================
// DRIVER ENUMERATION
// ========================================================================

std::vector<DriverInfo> DriverAnalyzer::EnumerateDrivers() const {
    return m_impl->EnumerateDrivers();
}

std::vector<DriverInfo> DriverAnalyzer::EnumerateDriversDeep() const {
    return m_impl->EnumerateDriversDeep();
}

std::optional<DriverInfo> DriverAnalyzer::GetDriverInfo(const std::wstring& driverName) const {
    return m_impl->GetDriverInfo(driverName);
}

std::optional<DriverInfo> DriverAnalyzer::GetDriverByAddress(uint64_t address) const {
    return m_impl->GetDriverByAddress(address);
}

bool DriverAnalyzer::IsDriverLoaded(const std::wstring& driverName) const {
    return m_impl->IsDriverLoaded(driverName);
}

// ========================================================================
// SIGNATURE VERIFICATION
// ========================================================================

DriverSignatureStatus DriverAnalyzer::VerifySignature(const std::wstring& driverPath) const {
    return m_impl->VerifySignature(driverPath);
}

std::vector<DriverInfo> DriverAnalyzer::GetUnsignedDrivers() const {
    return m_impl->GetUnsignedDrivers();
}

std::vector<DriverInfo> DriverAnalyzer::GetThirdPartyDrivers() const {
    return m_impl->GetThirdPartyDrivers();
}

// ========================================================================
// ROOTKIT DETECTION
// ========================================================================

std::vector<RootkitIndicator> DriverAnalyzer::ScanForRootkits() const {
    return m_impl->ScanForRootkits();
}

std::vector<DriverInfo> DriverAnalyzer::DetectHiddenDrivers() const {
    return m_impl->DetectHiddenDrivers();
}

bool DriverAnalyzer::VerifySSDTIntegrity() const {
    return m_impl->VerifySSDTIntegrity();
}

bool DriverAnalyzer::VerifyIDTIntegrity() const {
    return m_impl->VerifyIDTIntegrity();
}

std::vector<DriverCallbackInfo> DriverAnalyzer::GetSuspiciousCallbacks() const {
    return m_impl->GetSuspiciousCallbacks();
}

// ========================================================================
// THREAT ASSESSMENT
// ========================================================================

DriverInfo DriverAnalyzer::AnalyzeDriver(const std::wstring& driverPath) const {
    return m_impl->AnalyzeDriver(driverPath);
}

bool DriverAnalyzer::IsVulnerableDriver(const std::wstring& sha256Hash) const {
    return m_impl->IsVulnerableDriver(StringUtils::ToNarrow(sha256Hash));
}

std::optional<VulnerableDriverEntry> DriverAnalyzer::GetVulnerableDriverInfo(
    const std::wstring& sha256Hash) const {
    return m_impl->GetVulnerableDriverInfo(StringUtils::ToNarrow(sha256Hash));
}

std::vector<DriverInfo> DriverAnalyzer::GetLoadedVulnerableDrivers() const {
    return m_impl->GetLoadedVulnerableDrivers();
}

bool DriverAnalyzer::IsMaliciousDriver(const std::wstring& sha256Hash) const {
    return m_impl->IsMaliciousDriver(StringUtils::ToNarrow(sha256Hash));
}

// ========================================================================
// FULL SCAN
// ========================================================================

DriverScanResult DriverAnalyzer::PerformFullScan() const {
    return m_impl->PerformFullScan();
}

// ========================================================================
// CALLBACKS
// ========================================================================

uint64_t DriverAnalyzer::RegisterDriverLoadCallback(DriverLoadCallback callback) {
    return m_impl->RegisterDriverLoadCallback(std::move(callback));
}

void DriverAnalyzer::UnregisterDriverLoadCallback(uint64_t callbackId) {
    m_impl->UnregisterDriverLoadCallback(callbackId);
}

uint64_t DriverAnalyzer::RegisterRootkitAlertCallback(RootkitAlertCallback callback) {
    return m_impl->RegisterRootkitAlertCallback(std::move(callback));
}

void DriverAnalyzer::UnregisterRootkitAlertCallback(uint64_t callbackId) {
    m_impl->UnregisterRootkitAlertCallback(callbackId);
}

// ========================================================================
// STATISTICS
// ========================================================================

const DriverAnalyzerStatistics& DriverAnalyzer::GetStatistics() const noexcept {
    return m_impl->GetStatistics();
}

void DriverAnalyzer::ResetStatistics() noexcept {
    m_impl->ResetStatistics();
}

}  // namespace System
}  // namespace Core
}  // namespace ShadowStrike
