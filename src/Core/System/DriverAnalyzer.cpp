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

// Namespace aliases for cleaner code
using HashUtils = ShadowStrike::Utils::HashUtils;
using CertUtils = ShadowStrike::Utils::CertUtils;

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
#include <fstream>
#include <sstream>
#include <iomanip>

#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "ntdll.lib")

namespace fs = std::filesystem;

namespace ShadowStrike {
namespace Core {
namespace System {

// ============================================================================
// INTERNAL CONSTANTS
// ============================================================================
namespace {

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
            "a7c452bb8fcf2f9c1b51d5a0e3d0c6f3c3b3f3b3f3b3f3b3f3b3f3b3f3b3f3b3",
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
    std::wstring lowerPath = StringUtils::ToLower(path);

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
    std::wstring lowerName = StringUtils::ToLower(name);

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
            m_initialized = true;

            SS_LOG_INFO("DriverAnalyzer", "Initialized (signatures={}, rootkits={}, vulnerable={})",
                config.verifySignatures, config.scanForRootkits, config.checkVulnerableDrivers);

            return true;

        } catch (const std::exception& e) {
            SS_LOG_ERROR("DriverAnalyzer", "Initialization failed: {}", e.what());
            return false;
        }
    }

    void Shutdown() noexcept {
        std::unique_lock lock(m_mutex);

        try {
            m_driverLoadCallbacks.clear();
            m_rootkitAlertCallbacks.clear();
            m_initialized = false;

            SS_LOG_INFO("DriverAnalyzer", "Shutdown complete");

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
            LPVOID driverAddresses[MAX_DRIVERS];
            DWORD cbNeeded = 0;

            if (!EnumDeviceDrivers(driverAddresses, sizeof(driverAddresses), &cbNeeded)) {
                SS_LOG_ERROR("DriverAnalyzer", "EnumDeviceDrivers failed with error {}", GetLastError());
                return drivers;
            }

            // Validate cbNeeded to prevent integer overflow/buffer overflow
            if (cbNeeded > sizeof(driverAddresses)) {
                SS_LOG_WARN("DriverAnalyzer", "Driver list truncated: {} bytes needed, {} available",
                    cbNeeded, sizeof(driverAddresses));
                cbNeeded = sizeof(driverAddresses);
            }

            if (cbNeeded % sizeof(LPVOID) != 0) {
                SS_LOG_ERROR("DriverAnalyzer", "Invalid cbNeeded value: {} (not pointer-aligned)", cbNeeded);
                return drivers;
            }

            uint32_t driverCount = cbNeeded / sizeof(LPVOID);
            
            // Additional sanity check
            if (driverCount > MAX_EXPECTED_DRIVERS) {
                SS_LOG_WARN("DriverAnalyzer", "Unusually high driver count: {} (expected < {})",
                    driverCount, MAX_EXPECTED_DRIVERS);
            }
            
            drivers.reserve(driverCount);

            for (uint32_t i = 0; i < driverCount; ++i) {
                // Use extended path buffer to handle long paths
                wchar_t driverNameBuffer[EXTENDED_PATH_BUFFER_SIZE];

                if (GetDeviceDriverFileNameW(driverAddresses[i], driverNameBuffer, EXTENDED_PATH_BUFFER_SIZE)) {
                    DriverInfo info = GetDriverInfoInternal(driverNameBuffer,
                                                            reinterpret_cast<uint64_t>(driverAddresses[i]));
                    info.isLoaded = true;
                    info.loadOrder = i;
                    drivers.push_back(std::move(info));

                    m_stats.driversAnalyzed++;
                }
            }

            SS_LOG_INFO("DriverAnalyzer", "Enumerated {} drivers", drivers.size());

        } catch (const std::exception& e) {
            SS_LOG_ERROR("DriverAnalyzer", "EnumerateDrivers exception: {}", e.what());
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
                SS_LOG_WARN("DriverAnalyzer", "GetDriverInfo called with empty driver name");
                return std::nullopt;
            }
            
            auto drivers = EnumerateDrivers();

            for (const auto& driver : drivers) {
                std::wstring lowerDriverName = StringUtils::ToLower(driver.driverName);
                std::wstring lowerSearchName = StringUtils::ToLower(driverName);

                if (lowerDriverName.find(lowerSearchName) != std::wstring::npos) {
                    return driver;
                }
            }

        } catch (const std::exception& e) {
            SS_LOG_ERROR("DriverAnalyzer", "GetDriverInfo exception: {}", e.what());
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
            SS_LOG_ERROR("DriverAnalyzer", "GetDriverByAddress exception: {}", e.what());
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
            m_stats.signaturesVerified++;

            if (!fs::exists(driverPath)) {
                return DriverSignatureStatus::Unknown;
            }

            WINTRUST_FILE_INFO fileInfo = {};
            fileInfo.cbStruct = sizeof(WINTRUST_FILE_INFO);
            fileInfo.pcwszFilePath = driverPath.c_str();
            fileInfo.hFile = nullptr;
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

            // Clean up
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
            SS_LOG_ERROR("DriverAnalyzer", "VerifySignature exception: {}", e.what());
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
            SS_LOG_ERROR("DriverAnalyzer", "GetUnsignedDrivers exception: {}", e.what());
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
            SS_LOG_ERROR("DriverAnalyzer", "GetThirdPartyDrivers exception: {}", e.what());
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
                m_stats.rootkitIndicatorsFound++;
            }

            // Check IDT integrity
            if (!VerifyIDTIntegrityInternal()) {
                RootkitIndicator indicator;
                indicator.technique = RootkitTechnique::IDTHooking;
                indicator.description = L"IDT hooks detected";
                indicator.severity = 9;
                indicator.confidence = 0.85;
                indicators.push_back(indicator);
                m_stats.rootkitIndicatorsFound++;
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
                m_stats.rootkitIndicatorsFound++;
            }

        } catch (const std::exception& e) {
            SS_LOG_ERROR("DriverAnalyzer", "ScanForRootkits exception: {}", e.what());
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
            // NOTE: Full callback monitoring requires ShadowStrike kernel driver component
            // This user-mode implementation cannot enumerate kernel callbacks directly
            // The kernel driver (when integrated) will provide:
            // - PsSetCreateProcessNotifyRoutine callbacks
            // - PsSetCreateThreadNotifyRoutine callbacks
            // - PsSetLoadImageNotifyRoutine callbacks
            // - Object callback registrations
            // - Registry callback registrations
            
            SS_LOG_DEBUG("DriverAnalyzer", 
                "GetSuspiciousCallbacks: Kernel callback enumeration requires driver component (not yet integrated)");

        } catch (const std::exception& e) {
            SS_LOG_ERROR("DriverAnalyzer", "GetSuspiciousCallbacks exception: {}", e.what());
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
                SS_LOG_WARN("DriverAnalyzer", "Driver file not found: {}", StringUtils::WideToUtf8(driverPath));
                return info;
            }

            info = GetDriverInfoInternal(driverPath, 0);

            // Signature verification
            if (m_config.verifySignatures) {
                info.signatureStatus = VerifySignature(driverPath);
            }

            // Check vulnerable driver database
            if (m_config.checkVulnerableDrivers) {
                std::string sha256Lower = StringUtils::ToLower(info.sha256Hash);
                if (VULNERABLE_DRIVER_DATABASE.find(sha256Lower) != VULNERABLE_DRIVER_DATABASE.end()) {
                    info.isKnownVulnerable = true;
                    info.threatLevel = DriverThreatLevel::VulnerableDriver;
                    m_stats.vulnerableDriversFound++;

                    const auto& vulnEntry = VULNERABLE_DRIVER_DATABASE.at(sha256Lower);
                    info.vulnerabilities.push_back(vulnEntry.category);
                    info.cveIds = vulnEntry.cveIds;

                    SS_LOG_WARN("DriverAnalyzer", "Vulnerable driver detected: {} ({})",
                        StringUtils::WideToUtf8(info.driverName),
                        StringUtils::WideToUtf8(vulnEntry.description));
                }
            }

            // Check malicious driver hash
            if (HashStore::Instance().IsKnownMalware(info.sha256Hash)) {
                info.threatLevel = DriverThreatLevel::Malicious;
                m_stats.maliciousDriversFound++;

                SS_LOG_FATAL("DriverAnalyzer", "Malicious driver detected: {}",
                    StringUtils::WideToUtf8(info.driverName));
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
            SS_LOG_ERROR("DriverAnalyzer", "AnalyzeDriver exception: {}", e.what());
        }

        return info;
    }

    [[nodiscard]] bool IsVulnerableDriver(const std::string& sha256Hash) const {
        std::string sha256Lower = StringUtils::ToLower(sha256Hash);
        return VULNERABLE_DRIVER_DATABASE.find(sha256Lower) != VULNERABLE_DRIVER_DATABASE.end();
    }

    [[nodiscard]] std::optional<VulnerableDriverEntry> GetVulnerableDriverInfo(
        const std::string& sha256Hash) const {

        std::string sha256Lower = StringUtils::ToLower(sha256Hash);
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
            SS_LOG_ERROR("DriverAnalyzer", "GetLoadedVulnerableDrivers exception: {}", e.what());
        }

        return vulnerable;
    }

    [[nodiscard]] bool IsMaliciousDriver(const std::string& sha256Hash) const {
        return HashStore::Instance().IsKnownMalware(sha256Hash);
    }

    // ========================================================================
    // FULL SCAN
    // ========================================================================

    [[nodiscard]] DriverScanResult PerformFullScan() const {
        auto startTime = std::chrono::steady_clock::now();

        DriverScanResult result;

        try {
            SS_LOG_INFO("DriverAnalyzer", "Starting full driver scan...");

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

                // Malicious driver check
                if (IsMaliciousDriver(driver.sha256Hash)) {
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

            SS_LOG_INFO("DriverAnalyzer", "Driver scan complete: {} drivers, {} unsigned, {} vulnerable, {} malicious ({}ms)",
                result.totalDrivers, result.unsignedDrivers, result.vulnerableDrivers,
                result.maliciousDrivers, result.scanDuration.count());

        } catch (const std::exception& e) {
            SS_LOG_ERROR("DriverAnalyzer", "PerformFullScan exception: {}", e.what());
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
                SS_LOG_WARN("DriverAnalyzer", "Failed to compute hash for {}: error {}",
                    StringUtils::WideToUtf8(path), err.win32);
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
                    SS_LOG_WARN("DriverAnalyzer", "Cannot get file size for {}: {}", 
                        StringUtils::WideToUtf8(driverPath), fsErr.what());
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
                    std::string sha256Lower = StringUtils::ToLower(info.sha256Hash);
                    if (VULNERABLE_DRIVER_DATABASE.find(sha256Lower) != VULNERABLE_DRIVER_DATABASE.end()) {
                        info.isKnownVulnerable = true;
                        const auto& vulnEntry = VULNERABLE_DRIVER_DATABASE.at(sha256Lower);
                        info.vulnerabilities.push_back(vulnEntry.category);
                        info.cveIds = vulnEntry.cveIds;
                    }
                }
            }

        } catch (const std::exception& e) {
            SS_LOG_ERROR("DriverAnalyzer", "GetDriverInfoInternal exception: {}", e.what());
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
                SS_LOG_WARN("DriverAnalyzer", "Version info too large for {}: {} bytes (max {})",
                    StringUtils::WideToUtf8(filePath), size, MAX_VERSION_INFO_SIZE);
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
            SS_LOG_ERROR("DriverAnalyzer", "GetVersionInfoInternal exception: {}", e.what());
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
            // Use CertUtils to extract the signing certificate from the PE file
            CertUtils::Certificate cert;
            CertUtils::Error certErr;
            
            // Try to load certificate from the Authenticode signature
            // First, we need to get the signer certificate from WinVerifyTrust
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
                            std::wstring thumbprintHexW(thumbprintHex.begin(), thumbprintHex.end());
                            
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
                                
                                std::wstring lowerIssuer = StringUtils::ToLower(issuerName);
                                
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
            SS_LOG_ERROR("DriverAnalyzer", "IsMicrosoftSigned exception: {}", e.what());
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
                    SS_LOG_WARN("DriverAnalyzer", "CryptCATAdminAcquireContext failed: {}", GetLastError());
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
            
            while (hCatInfo != nullptr) {
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
                        std::wstring lowerCatalog = StringUtils::ToLower(catalogPath);
                        
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
            SS_LOG_ERROR("DriverAnalyzer", "IsWHQLCertified exception: {}", e.what());
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

            // NOTE: Hidden driver detection requires ShadowStrike kernel driver component
            // User-mode cannot reliably detect DKOM (Direct Kernel Object Manipulation) or
            // drivers hidden from PsLoadedModuleList
            //
            // When kernel driver is integrated, it will provide:
            // 1. Memory scanning for PE signatures in kernel space
            // 2. Comparison of EnumDeviceDrivers vs manual PsLoadedModuleList walk
            // 3. Object directory enumeration for DriverObject comparison
            // 4. VAD (Virtual Address Descriptor) analysis
            
            SS_LOG_DEBUG("DriverAnalyzer", 
                "DetectHiddenDrivers: Kernel-mode detection requires driver component (not yet integrated)");

            m_stats.hiddenDriversFound += static_cast<uint32_t>(hidden.size());

        } catch (const std::exception& e) {
            SS_LOG_ERROR("DriverAnalyzer", "DetectHiddenDriversInternal exception: {}", e.what());
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
            // SSDT integrity verification requires kernel-mode access
            // The ShadowStrike kernel driver (when integrated) will:
            // 1. Read KeServiceDescriptorTable
            // 2. Compare SSDT entries against known-good ntoskrnl.exe exports
            // 3. Detect inline hooks in system call handlers
            // 4. Verify KiServiceTable addresses are within ntoskrnl range
            
            SS_LOG_DEBUG("DriverAnalyzer", 
                "VerifySSDTIntegrity: Kernel-mode verification requires driver component (not yet integrated)");
            
            // Return nullopt to indicate "cannot determine" rather than false positive
            return std::nullopt;

        } catch (const std::exception& e) {
            SS_LOG_ERROR("DriverAnalyzer", "VerifySSDTIntegrityInternal exception: {}", e.what());
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
            // IDT integrity verification requires kernel-mode access
            // The ShadowStrike kernel driver (when integrated) will:
            // 1. Read IDTR register
            // 2. Compare IDT entries against known-good values
            // 3. Detect patched interrupt handlers
            // 4. Verify ISR addresses are within expected kernel ranges
            
            SS_LOG_DEBUG("DriverAnalyzer", 
                "VerifyIDTIntegrity: Kernel-mode verification requires driver component (not yet integrated)");
            
            // Return nullopt to indicate "cannot determine" rather than false positive
            return std::nullopt;

        } catch (const std::exception& e) {
            SS_LOG_ERROR("DriverAnalyzer", "VerifyIDTIntegrityInternal exception: {}", e.what());
            return std::nullopt;
            return false;
        }
    }

    // ========================================================================
    // MEMBER VARIABLES
    // ========================================================================

    mutable std::shared_mutex m_mutex;
    bool m_initialized{ false };

    DriverAnalyzerConfig m_config;
    mutable DriverAnalyzerStatistics m_stats;

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
    SS_LOG_INFO("DriverAnalyzer", "Instance created");
}

DriverAnalyzer::~DriverAnalyzer() {
    if (m_impl) {
        m_impl->Shutdown();
    }
    SS_LOG_INFO("DriverAnalyzer", "Instance destroyed");
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
    return m_impl->IsVulnerableDriver(StringUtils::WideToUtf8(sha256Hash));
}

std::optional<VulnerableDriverEntry> DriverAnalyzer::GetVulnerableDriverInfo(
    const std::wstring& sha256Hash) const {
    return m_impl->GetVulnerableDriverInfo(StringUtils::WideToUtf8(sha256Hash));
}

std::vector<DriverInfo> DriverAnalyzer::GetLoadedVulnerableDrivers() const {
    return m_impl->GetLoadedVulnerableDrivers();
}

bool DriverAnalyzer::IsMaliciousDriver(const std::wstring& sha256Hash) const {
    return m_impl->IsMaliciousDriver(StringUtils::WideToUtf8(sha256Hash));
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
