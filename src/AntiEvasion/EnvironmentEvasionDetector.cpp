/**
 * @file EnvironmentEvasionDetector.cpp
 * @brief Enterprise-grade environment-based sandbox/analysis evasion detection
 *
 * ShadowStrike AntiEvasion - Environment Evasion Detection Module
 * Copyright (c) 2026 ShadowStrike Security Suite. All rights reserved.
 *
 * This module detects malware that attempts to evade analysis by checking
 * environmental characteristics (usernames, hardware, artifacts, etc.)
 *
 * Implementation follows enterprise C++20 standards:
 * - PIMPL pattern for ABI stability
 * - Thread-safe with std::shared_mutex
 * - Exception-safe with comprehensive error handling
 * - Statistics tracking for all operations
 * - Memory-safe with smart pointers only
 * - Infrastructure reuse (Utils modules)
 */

#include "pch.h"
#include "EnvironmentEvasionDetector.hpp"

 // ============================================================================
 // STANDARD LIBRARY INCLUDES
 // ============================================================================

#include <algorithm>
#include <cctype>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <unordered_map>
#include <map>
#include <queue>

// ============================================================================
// WINDOWS SDK INCLUDES
// ============================================================================

#include <iphlpapi.h>
#include <wbemidl.h>
#include <comdef.h>
#include <locale>
#include <setupapi.h>
#include <devguid.h>
#include <tlhelp32.h>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "setupapi.lib")
#pragma comment(lib, "advapi32.lib")

// ============================================================================
// SHADOWSTRIKE INTERNAL INCLUDES
// ============================================================================

#include "../Utils/Logger.hpp"
#include "../Utils/StringUtils.hpp"
#include "../Utils/CryptoUtils.hpp"
#include "../Utils/NetworkUtils.hpp"
#include "../ThreatIntel/ThreatIntelStore.hpp"

// ============================================================================
// EXTERNAL ASSEMBLY FUNCTIONS
// ============================================================================

extern "C" {
    // Defined in EnvironmentEvasionDetector_x64.asm
    bool CheckCPUIDHypervisorBit();
    void GetCPUIDBrandString(char* buffer, size_t bufferSize);
}

namespace fs = std::filesystem;

namespace ShadowStrike::AntiEvasion {

    // ========================================================================
    // HELPER FUNCTIONS
    // ========================================================================

    /**
     * @brief Get string representation of technique
     */
    [[nodiscard]] const wchar_t* EnvironmentTechniqueToString(EnvironmentEvasionTechnique technique) noexcept {
        switch (technique) {
            // Name Checks
        case EnvironmentEvasionTechnique::NAME_BlacklistedUsername:
            return L"Blacklisted Username Detected";
        case EnvironmentEvasionTechnique::NAME_BlacklistedComputerName:
            return L"Blacklisted Computer Name Detected";
        case EnvironmentEvasionTechnique::NAME_BlacklistedDomain:
            return L"Blacklisted Domain Name Detected";
        case EnvironmentEvasionTechnique::NAME_DefaultUsername:
            return L"Default/Generic Username";
        case EnvironmentEvasionTechnique::NAME_VMNamingPattern:
            return L"VM Naming Pattern Detected";
        case EnvironmentEvasionTechnique::NAME_SuspiciousLength:
            return L"Suspicious Username Length";

            // Hardware Fingerprinting
        case EnvironmentEvasionTechnique::HARDWARE_LowProcessorCount:
            return L"Low Processor Count";
        case EnvironmentEvasionTechnique::HARDWARE_LowRAM:
            return L"Low RAM Detected";
        case EnvironmentEvasionTechnique::HARDWARE_SmallDisk:
            return L"Small Disk Capacity";
        case EnvironmentEvasionTechnique::HARDWARE_SingleDisk:
            return L"Single Disk Drive";
        case EnvironmentEvasionTechnique::HARDWARE_VMDiskVendor:
            return L"VM Disk Vendor String";
        case EnvironmentEvasionTechnique::HARDWARE_VMBIOSVendor:
            return L"VM BIOS Vendor";
        case EnvironmentEvasionTechnique::HARDWARE_VMManufacturer:
            return L"VM System Manufacturer";
        case EnvironmentEvasionTechnique::HARDWARE_VMProductName:
            return L"VM Product Name";
        case EnvironmentEvasionTechnique::HARDWARE_VMCPUBrand:
            return L"VM CPU Brand String";
        case EnvironmentEvasionTechnique::HARDWARE_HypervisorBit:
            return L"Hypervisor CPUID Bit Set";
        case EnvironmentEvasionTechnique::HARDWARE_VMMotherboard:
            return L"VM Motherboard Detected";
        case EnvironmentEvasionTechnique::HARDWARE_VMDisplayAdapter:
            return L"VM Display Adapter";
        case EnvironmentEvasionTechnique::HARDWARE_SMBIOSVMIndicators:
            return L"SMBIOS VM Indicators";
        case EnvironmentEvasionTechnique::HARDWARE_ACPIVMIndicators:
            return L"ACPI VM Indicators";

            // File System Artifacts
        case EnvironmentEvasionTechnique::FILESYSTEM_VMToolsDirectory:
            return L"VM Tools Directory Present";
        case EnvironmentEvasionTechnique::FILESYSTEM_VMDrivers:
            return L"VM Drivers Present";
        case EnvironmentEvasionTechnique::FILESYSTEM_SandboxAgentFiles:
            return L"Sandbox Agent Files Detected";
        case EnvironmentEvasionTechnique::FILESYSTEM_AnalysisToolsInstalled:
            return L"Analysis Tools Installed";
        case EnvironmentEvasionTechnique::FILESYSTEM_EmptyDocuments:
            return L"Empty Documents Folder";
        case EnvironmentEvasionTechnique::FILESYSTEM_EmptyDownloads:
            return L"Empty Downloads Folder";
        case EnvironmentEvasionTechnique::FILESYSTEM_EmptyDesktop:
            return L"Empty Desktop Folder";
        case EnvironmentEvasionTechnique::FILESYSTEM_NoRecentFiles:
            return L"No Recent Files";
        case EnvironmentEvasionTechnique::FILESYSTEM_MissingUserArtifacts:
            return L"Missing User Artifacts";
        case EnvironmentEvasionTechnique::FILESYSTEM_SuspiciousTempDir:
            return L"Suspicious Temp Directory";
        case EnvironmentEvasionTechnique::FILESYSTEM_AnalysisFiles:
            return L"Analysis Files Present";
        case EnvironmentEvasionTechnique::FILESYSTEM_VMSharedFolders:
            return L"VM Shared Folders Mounted";
        case EnvironmentEvasionTechnique::FILESYSTEM_CleanSystemDirs:
            return L"Unusually Clean System Directories";

            // Registry Artifacts
        case EnvironmentEvasionTechnique::REGISTRY_VMwareKeys:
            return L"VMware Registry Keys";
        case EnvironmentEvasionTechnique::REGISTRY_VirtualBoxKeys:
            return L"VirtualBox Registry Keys";
        case EnvironmentEvasionTechnique::REGISTRY_HyperVKeys:
            return L"Hyper-V Registry Keys";
        case EnvironmentEvasionTechnique::REGISTRY_ParallelsKeys:
            return L"Parallels Registry Keys";
        case EnvironmentEvasionTechnique::REGISTRY_QEMUKeys:
            return L"QEMU Registry Keys";
        case EnvironmentEvasionTechnique::REGISTRY_SandboxieKeys:
            return L"Sandboxie Registry Keys";
        case EnvironmentEvasionTechnique::REGISTRY_WineKeys:
            return L"Wine Registry Keys";
        case EnvironmentEvasionTechnique::REGISTRY_EmptyMRULists:
            return L"Empty MRU Lists";
        case EnvironmentEvasionTechnique::REGISTRY_NoTypedURLs:
            return L"No Typed URLs";
        case EnvironmentEvasionTechnique::REGISTRY_NoRecentPrograms:
            return L"No Recent Programs";
        case EnvironmentEvasionTechnique::REGISTRY_SuspiciousInstallDate:
            return L"Suspicious Install Date";
        case EnvironmentEvasionTechnique::REGISTRY_MissingSoftwareKeys:
            return L"Missing Common Software Keys";
        case EnvironmentEvasionTechnique::REGISTRY_VMServices:
            return L"VM Guest Services";

            // User Activity
        case EnvironmentEvasionTechnique::ACTIVITY_NoMouseMovement:
            return L"No Mouse Movement";
        case EnvironmentEvasionTechnique::ACTIVITY_NoKeyboardActivity:
            return L"No Keyboard Activity";
        case EnvironmentEvasionTechnique::ACTIVITY_NoWindowFocus:
            return L"No Window Focus Changes";
        case EnvironmentEvasionTechnique::ACTIVITY_NoClipboardHistory:
            return L"No Clipboard History";
        case EnvironmentEvasionTechnique::ACTIVITY_NoScreenshots:
            return L"No Screenshots";
        case EnvironmentEvasionTechnique::ACTIVITY_EmptyRecycleBin:
            return L"Empty Recycle Bin";
        case EnvironmentEvasionTechnique::ACTIVITY_NoPrinterHistory:
            return L"No Printer History";
        case EnvironmentEvasionTechnique::ACTIVITY_NoNetworkDrives:
            return L"No Network Drives";
        case EnvironmentEvasionTechnique::ACTIVITY_NoRecentSearches:
            return L"No Recent Searches";
        case EnvironmentEvasionTechnique::ACTIVITY_EmptyJumpLists:
            return L"Empty Jump Lists";
        case EnvironmentEvasionTechnique::ACTIVITY_NoNotifications:
            return L"No Notification History";
        case EnvironmentEvasionTechnique::ACTIVITY_UserIdleDetection:
            return L"User Idle Detected";
        case EnvironmentEvasionTechnique::ACTIVITY_SimulationCheck:
            return L"Human Interaction Simulation";

            // Network Configuration
        case EnvironmentEvasionTechnique::NETWORK_VMMACPrefix:
            return L"VM MAC Address Prefix";
        case EnvironmentEvasionTechnique::NETWORK_OnlyLoopback:
            return L"Only Loopback Adapter";
        case EnvironmentEvasionTechnique::NETWORK_VMAdapterName:
            return L"VM Network Adapter Name";
        case EnvironmentEvasionTechnique::NETWORK_NoWiFiHistory:
            return L"No WiFi Adapter History";
        case EnvironmentEvasionTechnique::NETWORK_SuspiciousDNS:
            return L"Suspicious DNS Configuration";
        case EnvironmentEvasionTechnique::NETWORK_NoNetworkShares:
            return L"No Network Shares";
        case EnvironmentEvasionTechnique::NETWORK_SandboxGateway:
            return L"Sandbox Gateway IP";
        case EnvironmentEvasionTechnique::NETWORK_NATOnlyNetwork:
            return L"NAT-Only Network";
        case EnvironmentEvasionTechnique::NETWORK_NoMountedDrives:
            return L"No Mounted Drives";
        case EnvironmentEvasionTechnique::NETWORK_SuspiciousIPRange:
            return L"Suspicious IP Range";

            // Process Enumeration
        case EnvironmentEvasionTechnique::PROCESS_AnalysisToolRunning:
            return L"Analysis Tool Running";
        case EnvironmentEvasionTechnique::PROCESS_DebuggerRunning:
            return L"Debugger Running";
        case EnvironmentEvasionTechnique::PROCESS_VMToolsRunning:
            return L"VM Tools Running";
        case EnvironmentEvasionTechnique::PROCESS_SandboxAgentRunning:
            return L"Sandbox Agent Running";
        case EnvironmentEvasionTechnique::PROCESS_SuspiciousService:
            return L"Suspicious Service";
        case EnvironmentEvasionTechnique::PROCESS_LowProcessCount:
            return L"Low Process Count";
        case EnvironmentEvasionTechnique::PROCESS_MissingSystemProcesses:
            return L"Missing System Processes";
        case EnvironmentEvasionTechnique::PROCESS_AnalysisWindowTitles:
            return L"Analysis Window Titles";
        case EnvironmentEvasionTechnique::PROCESS_HookingDLLs:
            return L"API Hooking DLLs";

            // Timing Checks
        case EnvironmentEvasionTechnique::TIMING_ShortUptime:
            return L"Short System Uptime";
        case EnvironmentEvasionTechnique::TIMING_RecentInstall:
            return L"Recent System Install";
        case EnvironmentEvasionTechnique::TIMING_NoScheduledTasks:
            return L"No Scheduled Tasks";
        case EnvironmentEvasionTechnique::TIMING_EventLogCleared:
            return L"Event Log Cleared";
        case EnvironmentEvasionTechnique::TIMING_AcceleratedTime:
            return L"Accelerated Time Detected";
        case EnvironmentEvasionTechnique::TIMING_SleepSkipping:
            return L"Sleep Skipping Detected";
        case EnvironmentEvasionTechnique::TIMING_BootTimeAnomaly:
            return L"Boot Time Anomaly";
        case EnvironmentEvasionTechnique::TIMING_TimestampClustering:
            return L"File Timestamp Clustering";

            // Environment Variables
        case EnvironmentEvasionTechnique::ENV_SandboxVariable:
            return L"Sandbox Environment Variable";
        case EnvironmentEvasionTechnique::ENV_VMVariable:
            return L"VM Environment Variable";
        case EnvironmentEvasionTechnique::ENV_AnalysisVariable:
            return L"Analysis Environment Variable";
        case EnvironmentEvasionTechnique::ENV_MissingVariables:
            return L"Missing Expected Variables";
        case EnvironmentEvasionTechnique::ENV_SuspiciousPath:
            return L"Suspicious PATH Configuration";
        case EnvironmentEvasionTechnique::ENV_UnusualTempPath:
            return L"Unusual TEMP Path";

            // Display Configuration
        case EnvironmentEvasionTechnique::DISPLAY_LowResolution:
            return L"Low Screen Resolution";
        case EnvironmentEvasionTechnique::DISPLAY_SingleMonitor:
            return L"Single Monitor Only";
        case EnvironmentEvasionTechnique::DISPLAY_VMDriver:
            return L"VM Display Driver";
        case EnvironmentEvasionTechnique::DISPLAY_MissingGPU:
            return L"Missing GPU";
        case EnvironmentEvasionTechnique::DISPLAY_UnusualColorDepth:
            return L"Unusual Color Depth";
        case EnvironmentEvasionTechnique::DISPLAY_VMGraphicsAdapter:
            return L"VM Graphics Adapter";

            // Locale/Regional
        case EnvironmentEvasionTechnique::LOCALE_DefaultLocale:
            return L"Default Locale";
        case EnvironmentEvasionTechnique::LOCALE_MismatchedTimezone:
            return L"Mismatched Timezone";
        case EnvironmentEvasionTechnique::LOCALE_SingleKeyboard:
            return L"Single Keyboard Layout";
        case EnvironmentEvasionTechnique::LOCALE_DefaultLanguage:
            return L"Default Language";
        case EnvironmentEvasionTechnique::LOCALE_SuspiciousRegion:
            return L"Suspicious Region";

            // Browser Artifacts
        case EnvironmentEvasionTechnique::BROWSER_NoHistory:
            return L"No Browser History";
        case EnvironmentEvasionTechnique::BROWSER_NoBookmarks:
            return L"No Bookmarks";
        case EnvironmentEvasionTechnique::BROWSER_NoCookies:
            return L"No Cookies";
        case EnvironmentEvasionTechnique::BROWSER_NoPasswords:
            return L"No Saved Passwords";
        case EnvironmentEvasionTechnique::BROWSER_NoExtensions:
            return L"No Browser Extensions";
        case EnvironmentEvasionTechnique::BROWSER_NoDownloads:
            return L"No Download History";
        case EnvironmentEvasionTechnique::BROWSER_NoAutofill:
            return L"No Autofill Data";
        case EnvironmentEvasionTechnique::BROWSER_OnlyDefault:
            return L"Only Default Browser";

            // Peripheral History
        case EnvironmentEvasionTechnique::PERIPHERAL_NoUSBHistory:
            return L"No USB Device History";
        case EnvironmentEvasionTechnique::PERIPHERAL_NoBluetoothPairings:
            return L"No Bluetooth Pairings";
        case EnvironmentEvasionTechnique::PERIPHERAL_NoPrinters:
            return L"No Printers Installed";
        case EnvironmentEvasionTechnique::PERIPHERAL_NoAudioDevices:
            return L"No Audio Devices";
        case EnvironmentEvasionTechnique::PERIPHERAL_NoWebcam:
            return L"No Webcam";
        case EnvironmentEvasionTechnique::PERIPHERAL_MissingDevices:
            return L"Missing Typical Peripherals";

            // File Naming
        case EnvironmentEvasionTechnique::FILENAME_MD5Hash:
            return L"File Name is MD5 Hash";
        case EnvironmentEvasionTechnique::FILENAME_SHA1Hash:
            return L"File Name is SHA1 Hash";
        case EnvironmentEvasionTechnique::FILENAME_SHA256Hash:
            return L"File Name is SHA256 Hash";
        case EnvironmentEvasionTechnique::FILENAME_Generic:
            return L"Generic File Name";
        case EnvironmentEvasionTechnique::FILENAME_SuspiciousLocation:
            return L"Suspicious File Location";
        case EnvironmentEvasionTechnique::FILENAME_AnalysisKeywords:
            return L"Analysis Keywords in Name";
        case EnvironmentEvasionTechnique::FILENAME_MultipleExtensions:
            return L"Multiple File Extensions";
        case EnvironmentEvasionTechnique::FILENAME_RandomPattern:
            return L"Random File Name Pattern";

            // Advanced
        case EnvironmentEvasionTechnique::ADVANCED_MultiCategoryEvasion:
            return L"Multi-Category Evasion";
        case EnvironmentEvasionTechnique::ADVANCED_SophisticatedFingerprinting:
            return L"Sophisticated Fingerprinting";
        case EnvironmentEvasionTechnique::ADVANCED_PolymorphicCheck:
            return L"Polymorphic Environment Check";
        case EnvironmentEvasionTechnique::ADVANCED_EncryptedCheck:
            return L"Encrypted Check";
        case EnvironmentEvasionTechnique::ADVANCED_DelayedCheck:
            return L"Time-Delayed Check";
        case EnvironmentEvasionTechnique::ADVANCED_AntiForensics:
            return L"Anti-Forensics Detected";

        default:
            return L"Unknown Technique";
        }
    }

    // ========================================================================
    // PIMPL IMPLEMENTATION CLASS
    // ========================================================================

    class EnvironmentEvasionDetector::Impl {
    public:
        // ====================================================================
        // MEMBERS
        // ====================================================================

        /// @brief Thread synchronization
        mutable std::shared_mutex m_mutex;

        /// @brief Initialization state
        std::atomic<bool> m_initialized{ false };

        /// @brief Threat intelligence store
        std::shared_ptr<ThreatIntel::ThreatIntelStore> m_threatIntel;

        /// @brief Detection callback
        EnvironmentDetectionCallback m_detectionCallback;

        /// @brief Statistics
        EnvironmentEvasionDetector::Statistics m_stats;

        /// @brief Custom blacklisted usernames
        std::vector<std::wstring> m_customBlacklistedUsernames;

        /// @brief Custom blacklisted computer names
        std::vector<std::wstring> m_customBlacklistedComputerNames;

        /// @brief Custom analysis tool processes
        std::vector<std::wstring> m_customAnalysisToolProcesses;

        /// @brief Result cache
        struct CacheEntry {
            EnvironmentEvasionResult result;
            std::chrono::steady_clock::time_point timestamp;
        };
        std::unordered_map<uint32_t, CacheEntry> m_resultCache;

        /// @brief System identity info (cached)
        std::optional<SystemIdentityInfo> m_cachedIdentityInfo;

        /// @brief Hardware info (cached)
        std::optional<HardwareFingerprintInfo> m_cachedHardwareInfo;

        // ====================================================================
        // METHODS
        // ====================================================================

        Impl() = default;
        ~Impl() = default;

        [[nodiscard]] bool Initialize(EnvironmentError* err) noexcept;
        void Shutdown() noexcept;

        // Helper methods
        [[nodiscard]] bool IsBlacklistedUsername(std::wstring_view name) const noexcept;
        [[nodiscard]] bool IsBlacklistedComputerName(std::wstring_view name) const noexcept;
        [[nodiscard]] bool IsAnalysisToolProcess(std::wstring_view name) const noexcept;
        [[nodiscard]] bool IsVMMACAddress(const std::array<uint8_t, 6>& mac) const noexcept;
        [[nodiscard]] bool LooksLikeHash(std::wstring_view name, std::wstring& hashType) const noexcept;
        [[nodiscard]] bool ContainsSubstringCI(std::wstring_view haystack, std::wstring_view needle) const noexcept;

        void CollectHardwareInfo(HardwareFingerprintInfo& info) noexcept;
        void CollectIdentityInfo(SystemIdentityInfo& info) noexcept;
        void CollectNetworkInfo(NetworkConfigInfo& info) noexcept;
        void CollectUserActivityInfo(UserActivityInfo& info) noexcept;
        void CollectProcessEnvironmentInfo(uint32_t processId, ProcessEnvironmentInfo& info) noexcept;
        void AnalyzeFileNaming(std::wstring_view filePath, FileNamingInfo& info) noexcept;

        [[nodiscard]] size_t CountFilesInDirectory(const fs::path& dir, EnvironmentError* err) noexcept;
        [[nodiscard]] std::wstring GetRegistryString(HKEY hKey, const std::wstring& subKey, const std::wstring& valueName) noexcept;
        [[nodiscard]] bool RegistryKeyExists(HKEY hKey, const std::wstring& subKey) noexcept;
    };

    // ========================================================================
    // IMPL: INITIALIZATION
    // ========================================================================

    bool EnvironmentEvasionDetector::Impl::Initialize(EnvironmentError* err) noexcept {
        try {
            if (m_initialized.exchange(true)) {
                return true; // Already initialized
            }

            SS_LOG_INFO(L"EnvironmentEvasionDetector", L"Initializing...");

            // Pre-cache system identity and hardware info for performance
            m_cachedIdentityInfo = SystemIdentityInfo{};
            CollectIdentityInfo(*m_cachedIdentityInfo);

            m_cachedHardwareInfo = HardwareFingerprintInfo{};
            CollectHardwareInfo(*m_cachedHardwareInfo);

            SS_LOG_INFO(L"EnvironmentEvasionDetector", L"Initialized successfully");
            return true;

        }
        catch (const std::exception& e) {
            SS_LOG_ERROR(L"EnvironmentEvasionDetector", L"Initialization failed: %hs", e.what());

            if (err) {
                err->win32Code = ERROR_INTERNAL_ERROR;
                err->message = L"Initialization failed";
                err->context = Utils::StringUtils::ToWide(e.what());
            }

            m_initialized = false;
            return false;
        }
        catch (...) {
            SS_LOG_FATAL(L"EnvironmentEvasionDetector", L"Unknown initialization error");

            if (err) {
                err->win32Code = ERROR_INTERNAL_ERROR;
                err->message = L"Unknown initialization error";
            }

            m_initialized = false;
            return false;
        }
    }

    void EnvironmentEvasionDetector::Impl::Shutdown() noexcept {
        try {
            std::unique_lock lock(m_mutex);

            if (!m_initialized.exchange(false)) {
                return; // Already shutdown
            }

            SS_LOG_INFO(L"EnvironmentEvasionDetector", L"Shutting down...");

            // Clear caches
            m_resultCache.clear();
            m_cachedIdentityInfo.reset();
            m_cachedHardwareInfo.reset();

            // Clear custom lists
            m_customBlacklistedUsernames.clear();
            m_customBlacklistedComputerNames.clear();
            m_customAnalysisToolProcesses.clear();

            // Clear callback
            m_detectionCallback = nullptr;

            SS_LOG_INFO(L"EnvironmentEvasionDetector", L"Shutdown complete");
        }
        catch (...) {
            SS_LOG_ERROR(L"EnvironmentEvasionDetector", L"Exception during shutdown");
        }
    }

    // ========================================================================
    // IMPL: HELPER METHODS
    // ========================================================================

    bool EnvironmentEvasionDetector::Impl::IsBlacklistedUsername(std::wstring_view name) const noexcept {
        try {
            // Convert to lowercase for case-insensitive comparison
            std::wstring nameLower(name);
            std::transform(nameLower.begin(), nameLower.end(), nameLower.begin(), ::towlower);

            // Check built-in blacklist
            for (const auto& blacklisted : EnvironmentConstants::BLACKLISTED_USERNAMES) {
                std::wstring blacklistedLower(blacklisted);
                std::transform(blacklistedLower.begin(), blacklistedLower.end(), blacklistedLower.begin(), ::towlower);

                if (nameLower == blacklistedLower || nameLower.find(blacklistedLower) != std::wstring::npos) {
                    return true;
                }
            }

            // Check custom blacklist
            for (const auto& blacklisted : m_customBlacklistedUsernames) {
                std::wstring blacklistedLower(blacklisted);
                std::transform(blacklistedLower.begin(), blacklistedLower.end(), blacklistedLower.begin(), ::towlower);

                if (nameLower == blacklistedLower || nameLower.find(blacklistedLower) != std::wstring::npos) {
                    return true;
                }
            }

            return false;
        }
        catch (...) {
            return false;
        }
    }

    bool EnvironmentEvasionDetector::Impl::IsBlacklistedComputerName(std::wstring_view name) const noexcept {
        try {
            std::wstring nameLower(name);
            std::transform(nameLower.begin(), nameLower.end(), nameLower.begin(), ::towlower);

            // Check built-in blacklist
            for (const auto& blacklisted : EnvironmentConstants::BLACKLISTED_COMPUTER_NAMES) {
                std::wstring blacklistedLower(blacklisted);
                std::transform(blacklistedLower.begin(), blacklistedLower.end(), blacklistedLower.begin(), ::towlower);

                if (nameLower == blacklistedLower || nameLower.find(blacklistedLower) != std::wstring::npos) {
                    return true;
                }
            }

            // Check custom blacklist
            for (const auto& blacklisted : m_customBlacklistedComputerNames) {
                std::wstring blacklistedLower(blacklisted);
                std::transform(blacklistedLower.begin(), blacklistedLower.end(), blacklistedLower.begin(), ::towlower);

                if (nameLower == blacklistedLower || nameLower.find(blacklistedLower) != std::wstring::npos) {
                    return true;
                }
            }

            return false;
        }
        catch (...) {
            return false;
        }
    }

    bool EnvironmentEvasionDetector::Impl::IsAnalysisToolProcess(std::wstring_view name) const noexcept {
        try {
            std::wstring nameLower(name);
            std::transform(nameLower.begin(), nameLower.end(), nameLower.begin(), ::towlower);

            // Check built-in list
            for (const auto& tool : EnvironmentConstants::ANALYSIS_TOOL_PROCESSES) {
                std::wstring toolLower(tool);
                std::transform(toolLower.begin(), toolLower.end(), toolLower.begin(), ::towlower);

                if (nameLower.find(toolLower) != std::wstring::npos) {
                    return true;
                }
            }

            // Check custom list
            for (const auto& tool : m_customAnalysisToolProcesses) {
                std::wstring toolLower(tool);
                std::transform(toolLower.begin(), toolLower.end(), toolLower.begin(), ::towlower);

                if (nameLower.find(toolLower) != std::wstring::npos) {
                    return true;
                }
            }

            return false;
        }
        catch (...) {
            return false;
        }
    }

    bool EnvironmentEvasionDetector::Impl::IsVMMACAddress(const std::array<uint8_t, 6>& mac) const noexcept {
        try {
            for (const auto& vmPrefix : EnvironmentConstants::SANDBOX_MAC_PREFIXES) {
                if (mac[0] == vmPrefix[0] && mac[1] == vmPrefix[1] && mac[2] == vmPrefix[2]) {
                    return true;
                }
            }
            return false;
        }
        catch (...) {
            return false;
        }
    }

    bool EnvironmentEvasionDetector::Impl::LooksLikeHash(std::wstring_view name, std::wstring& hashType) const noexcept {
        try {
            // Check if string is all hexadecimal
            bool allHex = std::all_of(name.begin(), name.end(), [](wchar_t c) {
                return std::isxdigit(static_cast<unsigned char>(c));
                });

            if (!allHex) {
                return false;
            }

            // Check length for common hash types
            const size_t len = name.length();

            if (len == 32) {
                hashType = L"MD5";
                return true;
            }
            else if (len == 40) {
                hashType = L"SHA1";
                return true;
            }
            else if (len == 64) {
                hashType = L"SHA256";
                return true;
            }

            return false;
        }
        catch (...) {
            return false;
        }
    }

    bool EnvironmentEvasionDetector::Impl::ContainsSubstringCI(std::wstring_view haystack, std::wstring_view needle) const noexcept {
        try {
            std::wstring haystackLower(haystack);
            std::wstring needleLower(needle);

            std::transform(haystackLower.begin(), haystackLower.end(), haystackLower.begin(), ::towlower);
            std::transform(needleLower.begin(), needleLower.end(), needleLower.begin(), ::towlower);

            return haystackLower.find(needleLower) != std::wstring::npos;
        }
        catch (...) {
            return false;
        }
    }

    // ========================================================================
    // IMPL: DATA COLLECTION METHODS
    // ========================================================================

    void EnvironmentEvasionDetector::Impl::CollectHardwareInfo(HardwareFingerprintInfo& info) noexcept {
        try {
            info = HardwareFingerprintInfo{};

            // Get processor count
            SYSTEM_INFO sysInfo = {};
            GetSystemInfo(&sysInfo);
            info.processorCount = sysInfo.dwNumberOfProcessors;

            // Get RAM size
            MEMORYSTATUSEX memStatus = {};
            memStatus.dwLength = sizeof(memStatus);
            if (GlobalMemoryStatusEx(&memStatus)) {
                info.totalRAM = memStatus.ullTotalPhys;
            }

            // Get disk space
            ULARGE_INTEGER freeBytesAvailable, totalBytes, totalFreeBytes;
            if (GetDiskFreeSpaceExW(L"C:\\", &freeBytesAvailable, &totalBytes, &totalFreeBytes)) {
                info.totalDiskSpace = totalBytes.QuadPart;
            }

            // Get screen resolution
            info.screenWidth = static_cast<uint32_t>(GetSystemMetrics(SM_CXSCREEN));
            info.screenHeight = static_cast<uint32_t>(GetSystemMetrics(SM_CYSCREEN));
            info.monitorCount = static_cast<uint32_t>(GetSystemMetrics(SM_CMONITORS));

            // Get CPU brand string using assembly function
            char cpuBrand[256] = {};
            GetCPUIDBrandString(cpuBrand, sizeof(cpuBrand));
            info.cpuBrand = Utils::StringUtils::ToWide(cpuBrand);

            // Check hypervisor bit using assembly function
            info.hypervisorDetected = CheckCPUIDHypervisorBit();

            // Get BIOS info from registry
            info.biosVendor = GetRegistryString(HKEY_LOCAL_MACHINE,
                L"HARDWARE\\DESCRIPTION\\System\\BIOS", L"BIOSVendor");

            info.manufacturer = GetRegistryString(HKEY_LOCAL_MACHINE,
                L"HARDWARE\\DESCRIPTION\\System\\BIOS", L"SystemManufacturer");

            info.productName = GetRegistryString(HKEY_LOCAL_MACHINE,
                L"HARDWARE\\DESCRIPTION\\System\\BIOS", L"SystemProductName");

            // Check for VM indicators in strings
            const std::vector<std::wstring_view> vmKeywords = {
                L"vmware", L"virtualbox", L"vbox", L"qemu", L"xen",
                L"hyperv", L"hyper-v", L"parallels", L"virtual", L"kvm"
            };

            for (const auto& keyword : vmKeywords) {
                if (ContainsSubstringCI(info.biosVendor, keyword) ||
                    ContainsSubstringCI(info.manufacturer, keyword) ||
                    ContainsSubstringCI(info.productName, keyword) ||
                    ContainsSubstringCI(info.cpuBrand, keyword)) {
                    info.vmIndicators.push_back(std::wstring(keyword));
                }
            }

            info.valid = true;
        }
        catch (const std::exception& e) {
            SS_LOG_ERROR(L"EnvironmentEvasionDetector", L"CollectHardwareInfo failed: %hs", e.what());
            info.valid = false;
        }
        catch (...) {
            SS_LOG_ERROR(L"EnvironmentEvasionDetector", L"CollectHardwareInfo: Unknown error");
            info.valid = false;
        }
    }

    void EnvironmentEvasionDetector::Impl::CollectIdentityInfo(SystemIdentityInfo& info) noexcept {
        try {
            info = SystemIdentityInfo{};

            // Get username
            wchar_t username[UNLEN + 1] = {};
            DWORD usernameLen = UNLEN + 1;
            if (GetUserNameW(username, &usernameLen)) {
                info.username = username;
            }

            // Get computer name
            wchar_t computerName[MAX_COMPUTERNAME_LENGTH + 1] = {};
            DWORD computerNameLen = MAX_COMPUTERNAME_LENGTH + 1;
            if (GetComputerNameW(computerName, &computerNameLen)) {
                info.computerName = computerName;
            }

            // Get domain name
            wchar_t domainName[MAX_COMPUTERNAME_LENGTH + 1] = {};
            DWORD domainNameLen = MAX_COMPUTERNAME_LENGTH + 1;
            if (GetComputerNameExW(ComputerNameDnsDomain, domainName, &domainNameLen)) {
                info.domainName = domainName;
            }

            // Get system uptime
            info.uptimeMs = GetTickCount64();

            // Calculate last boot time
            const auto now = std::chrono::system_clock::now();
            const auto uptime = std::chrono::milliseconds(info.uptimeMs);
            info.lastBootTime = now - uptime;

            // Get OS version from registry
            info.osProductName = GetRegistryString(HKEY_LOCAL_MACHINE,
                L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", L"ProductName");

            info.osVersion = GetRegistryString(HKEY_LOCAL_MACHINE,
                L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", L"CurrentVersion");

            info.valid = true;
        }
        catch (const std::exception& e) {
            SS_LOG_ERROR(L"EnvironmentEvasionDetector", L"CollectIdentityInfo failed: %hs", e.what());
            info.valid = false;
        }
        catch (...) {
            SS_LOG_ERROR(L"EnvironmentEvasionDetector", L"CollectIdentityInfo: Unknown error");
            info.valid = false;
        }
    }

    void EnvironmentEvasionDetector::Impl::CollectNetworkInfo(NetworkConfigInfo& info) noexcept {
        try {
            info = NetworkConfigInfo{};

            // Get adapter info
            ULONG bufferSize = 0;
            GetAdaptersInfo(nullptr, &bufferSize);

            if (bufferSize == 0) {
                info.valid = false;
                return;
            }

            std::vector<uint8_t> buffer(bufferSize);
            PIP_ADAPTER_INFO pAdapterInfo = reinterpret_cast<PIP_ADAPTER_INFO>(buffer.data());

            if (GetAdaptersInfo(pAdapterInfo, &bufferSize) == ERROR_SUCCESS) {
                PIP_ADAPTER_INFO pAdapter = pAdapterInfo;

                while (pAdapter) {
                    NetworkConfigInfo::AdapterInfo adapter;
                    adapter.name = Utils::StringUtils::ToWide(pAdapter->AdapterName);
                    adapter.description = Utils::StringUtils::ToWide(pAdapter->Description);

                    // Copy MAC address
                    if (pAdapter->AddressLength == 6) {
                        std::copy(pAdapter->Address, pAdapter->Address + 6, adapter.macAddress.begin());

                        // Format MAC address string
                        std::wstringstream ss;
                        ss << std::hex << std::setfill(L'0');
                        for (size_t i = 0; i < 6; ++i) {
                            if (i > 0) ss << L"-";
                            ss << std::setw(2) << static_cast<int>(adapter.macAddress[i]);
                        }
                        adapter.macAddressString = ss.str();

                        // Check if VM adapter
                        adapter.isVMAdapter = IsVMMACAddress(adapter.macAddress);
                        if (adapter.isVMAdapter) {
                            info.vmAdapterCount++;
                        }
                    }

                    // Get IP address
                    if (pAdapter->IpAddressList.IpAddress.String[0] != '\0') {
                        adapter.ipAddress = Utils::StringUtils::ToWide(pAdapter->IpAddressList.IpAddress.String);
                        adapter.subnetMask = Utils::StringUtils::ToWide(pAdapter->IpAddressList.IpMask.String);
                    }

                    // Check if WiFi
                    if (ContainsSubstringCI(adapter.description, L"wireless") ||
                        ContainsSubstringCI(adapter.description, L"wi-fi") ||
                        ContainsSubstringCI(adapter.description, L"wifi")) {
                        info.hasWiFi = true;
                    }

                    info.adapters.push_back(adapter);
                    info.adapterCount++;

                    pAdapter = pAdapter->Next;
                }
            }

            info.valid = true;
        }
        catch (const std::exception& e) {
            SS_LOG_ERROR(L"EnvironmentEvasionDetector", L"CollectNetworkInfo failed: %hs", e.what());
            info.valid = false;
        }
        catch (...) {
            SS_LOG_ERROR(L"EnvironmentEvasionDetector", L"CollectNetworkInfo: Unknown error");
            info.valid = false;
        }
    }

    void EnvironmentEvasionDetector::Impl::CollectUserActivityInfo(UserActivityInfo& info) noexcept {
        try {
            info = UserActivityInfo{};

            // Expand environment variables
            auto expandPath = [](const wchar_t* path) -> std::wstring {
                wchar_t expanded[MAX_PATH];
                ExpandEnvironmentStringsW(path, expanded, MAX_PATH);
                return expanded;
                };

            // Count files in various user directories
            info.desktopItemsCount = CountFilesInDirectory(expandPath(L"%USERPROFILE%\\Desktop"), nullptr);
            info.documentsCount = CountFilesInDirectory(expandPath(L"%USERPROFILE%\\Documents"), nullptr);
            info.downloadsCount = CountFilesInDirectory(expandPath(L"%USERPROFILE%\\Downloads"), nullptr);
            info.recentDocumentsCount = CountFilesInDirectory(expandPath(L"%APPDATA%\\Microsoft\\Windows\\Recent"), nullptr);

            // Check if system appears "lived-in"
            info.isLivedInSystem = (
                info.desktopItemsCount >= 3 ||
                info.documentsCount >= EnvironmentConstants::MIN_RECENT_DOCUMENTS ||
                info.downloadsCount >= 5 ||
                info.recentDocumentsCount >= EnvironmentConstants::MIN_RECENT_DOCUMENTS
                );

            info.valid = true;
        }
        catch (const std::exception& e) {
            SS_LOG_ERROR(L"EnvironmentEvasionDetector", L"CollectUserActivityInfo failed: %hs", e.what());
            info.valid = false;
        }
        catch (...) {
            SS_LOG_ERROR(L"EnvironmentEvasionDetector", L"CollectUserActivityInfo: Unknown error");
            info.valid = false;
        }
    }

    void EnvironmentEvasionDetector::Impl::CollectProcessEnvironmentInfo(uint32_t processId, ProcessEnvironmentInfo& info) noexcept {
        try {
            info = ProcessEnvironmentInfo{};

            // Get process handle
            HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);
            if (!hProcess) {
                info.valid = false;
                return;
            }

            // Get executable path
            wchar_t exePath[MAX_PATH] = {};
            DWORD exePathLen = MAX_PATH;
            if (QueryFullProcessImageNameW(hProcess, 0, exePath, &exePathLen)) {
                info.executablePath = exePath;
            }

            CloseHandle(hProcess);

            // Check environment variables of current process (if analyzing current process)
            if (processId == GetCurrentProcessId()) {
                wchar_t* env = GetEnvironmentStringsW();
                if (env) {
                    wchar_t* p = env;
                    while (*p) {
                        std::wstring envVar(p);
                        auto pos = envVar.find(L'=');
                        if (pos != std::wstring::npos) {
                            std::wstring name = envVar.substr(0, pos);
                            std::wstring value = envVar.substr(pos + 1);
                            info.environmentVars[name] = value;

                            // Check for sandbox-specific variables
                            for (const auto& sandboxVar : EnvironmentConstants::SANDBOX_ENV_VARIABLES) {
                                if (ContainsSubstringCI(name, sandboxVar)) {
                                    info.suspiciousVariables.push_back(name);
                                }
                            }
                        }
                        p += wcslen(p) + 1;
                    }
                    FreeEnvironmentStringsW(env);
                }
            }

            info.valid = true;
        }
        catch (const std::exception& e) {
            SS_LOG_ERROR(L"EnvironmentEvasionDetector", L"CollectProcessEnvironmentInfo failed: %hs", e.what());
            info.valid = false;
        }
        catch (...) {
            SS_LOG_ERROR(L"EnvironmentEvasionDetector", L"CollectProcessEnvironmentInfo: Unknown error");
            info.valid = false;
        }
    }

    void EnvironmentEvasionDetector::Impl::AnalyzeFileNaming(std::wstring_view filePath, FileNamingInfo& info) noexcept {
        try {
            info = FileNamingInfo{};
            info.executablePath = filePath;

            fs::path path(filePath);
            info.fileName = path.filename().wstring();
            info.baseName = path.stem().wstring();
            info.extension = path.extension().wstring();
            info.directoryPath = path.parent_path().wstring();

            // Check if filename looks like a hash
            std::wstring hashType;
            if (LooksLikeHash(info.baseName, hashType)) {
                if (hashType == L"MD5") info.isMD5 = true;
                else if (hashType == L"SHA1") info.isSHA1 = true;
                else if (hashType == L"SHA256") info.isSHA256 = true;
            }

            // Check for generic names
            const std::vector<std::wstring_view> genericNames = {
                L"sample", L"malware", L"virus", L"test", L"analysis",
                L"infected", L"trojan", L"backdoor", L"payload"
            };

            for (const auto& generic : genericNames) {
                if (ContainsSubstringCI(info.baseName, generic)) {
                    info.isGeneric = true;
                    break;
                }
            }

            // Check for suspicious locations
            const std::vector<std::wstring_view> suspiciousLocs = {
                L"\\temp\\", L"\\tmp\\", L"\\appdata\\local\\temp\\",
                L"\\downloads\\", L"\\desktop\\"
            };

            for (const auto& loc : suspiciousLocs) {
                if (ContainsSubstringCI(info.directoryPath, loc)) {
                    info.inSuspiciousLocation = true;
                    break;
                }
            }

            info.valid = true;
        }
        catch (const std::exception& e) {
            SS_LOG_ERROR(L"EnvironmentEvasionDetector", L"AnalyzeFileNaming failed: %hs", e.what());
            info.valid = false;
        }
        catch (...) {
            SS_LOG_ERROR(L"EnvironmentEvasionDetector", L"AnalyzeFileNaming: Unknown error");
            info.valid = false;
        }
    }

    size_t EnvironmentEvasionDetector::Impl::CountFilesInDirectory(const fs::path& dir, EnvironmentError* err) noexcept {
        try {
            if (!fs::exists(dir) || !fs::is_directory(dir)) {
                return 0;
            }

            size_t count = 0;
            for (const auto& entry : fs::directory_iterator(dir)) {
                if (fs::is_regular_file(entry.status())) {
                    count++;
                }

                if (count >= EnvironmentConstants::MAX_FILES_PER_DIRECTORY) {
                    break; // Safety limit
                }
            }

            return count;
        }
        catch (const fs::filesystem_error& e) {
            if (err) {
                err->win32Code = static_cast<DWORD>(e.code().value());
                err->message = L"Directory enumeration failed";
                err->context = dir.wstring();
            }
            return 0;
        }
        catch (...) {
            return 0;
        }
    }

    std::wstring EnvironmentEvasionDetector::Impl::GetRegistryString(HKEY hKey, const std::wstring& subKey, const std::wstring& valueName) noexcept {
        try {
            HKEY hOpenKey = nullptr;
            if (RegOpenKeyExW(hKey, subKey.c_str(), 0, KEY_READ, &hOpenKey) != ERROR_SUCCESS) {
                return L"";
            }

            wchar_t buffer[512] = {};
            DWORD bufferSize = sizeof(buffer);
            DWORD type = REG_SZ;

            if (RegQueryValueExW(hOpenKey, valueName.c_str(), nullptr, &type,
                reinterpret_cast<LPBYTE>(buffer), &bufferSize) == ERROR_SUCCESS) {
                RegCloseKey(hOpenKey);
                return buffer;
            }

            RegCloseKey(hOpenKey);
            return L"";
        }
        catch (...) {
            return L"";
        }
    }

    bool EnvironmentEvasionDetector::Impl::RegistryKeyExists(HKEY hKey, const std::wstring& subKey) noexcept {
        try {
            HKEY hOpenKey = nullptr;
            if (RegOpenKeyExW(hKey, subKey.c_str(), 0, KEY_READ, &hOpenKey) == ERROR_SUCCESS) {
                RegCloseKey(hOpenKey);
                return true;
            }
            return false;
        }
        catch (...) {
            return false;
        }
    }

    // ========================================================================
    // PUBLIC API IMPLEMENTATION
    // ========================================================================

    EnvironmentEvasionDetector::EnvironmentEvasionDetector() noexcept
        : m_impl(std::make_unique<Impl>()) {
    }

    EnvironmentEvasionDetector::EnvironmentEvasionDetector(
        std::shared_ptr<ThreatIntel::ThreatIntelStore> threatIntel
    ) noexcept
        : m_impl(std::make_unique<Impl>()) {
        m_impl->m_threatIntel = std::move(threatIntel);
    }

    EnvironmentEvasionDetector::~EnvironmentEvasionDetector() {
        if (m_impl) {
            m_impl->Shutdown();
        }
    }

    EnvironmentEvasionDetector::EnvironmentEvasionDetector(EnvironmentEvasionDetector&&) noexcept = default;
    EnvironmentEvasionDetector& EnvironmentEvasionDetector::operator=(EnvironmentEvasionDetector&&) noexcept = default;

    bool EnvironmentEvasionDetector::Initialize(EnvironmentError* err) noexcept {
        if (!m_impl) {
            if (err) {
                err->win32Code = ERROR_INVALID_HANDLE;
                err->message = L"Invalid detector instance";
            }
            return false;
        }
        return m_impl->Initialize(err);
    }

    void EnvironmentEvasionDetector::Shutdown() noexcept {
        if (m_impl) {
            m_impl->Shutdown();
        }
    }

    bool EnvironmentEvasionDetector::IsInitialized() const noexcept {
        return m_impl && m_impl->m_initialized.load();
    }

    // ========================================================================
    // ANALYSIS METHODS - STUBS (Continued in next part due to size)
    // ========================================================================

    EnvironmentEvasionResult EnvironmentEvasionDetector::AnalyzeProcess(
        uint32_t processId,
        const EnvironmentAnalysisConfig& config,
        EnvironmentError* err
    ) noexcept {
        EnvironmentEvasionResult result;

        try {
            if (!IsInitialized()) {
                if (err) {
                    err->win32Code = ERROR_NOT_READY;
                    err->message = L"Detector not initialized";
                }
                return result;
            }

            const auto startTime = std::chrono::high_resolution_clock::now();

            // Check cache first
            if (config.enableCaching) {
                std::shared_lock lock(m_impl->m_mutex);
                auto it = m_impl->m_resultCache.find(processId);

                if (it != m_impl->m_resultCache.end()) {
                    const auto age = std::chrono::steady_clock::now() - it->second.timestamp;
                    const auto maxAge = std::chrono::seconds(config.cacheTtlSeconds);

                    if (age < maxAge) {
                        m_impl->m_stats.cacheHits++;
                        result = it->second.result;
                        result.fromCache = true;
                        return result;
                    }
                }
                m_impl->m_stats.cacheMisses++;
            }

            // Open process
            HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);
            if (!hProcess) {
                if (err) {
                    err->win32Code = GetLastError();
                    err->message = L"Failed to open process";
                }
                m_impl->m_stats.analysisErrors++;
                return result;
            }

            AnalyzeProcessInternal(hProcess, processId, config, result);
            CloseHandle(hProcess);

            const auto endTime = std::chrono::high_resolution_clock::now();
            const auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime);

            result.analysisDurationMs = duration.count();
            m_impl->m_stats.totalAnalyses++;
            m_impl->m_stats.totalAnalysisTimeUs += std::chrono::duration_cast<std::chrono::microseconds>(duration).count();

            if (result.isEvasive) {
                m_impl->m_stats.evasiveProcesses++;
            }

            // Update cache
            if (config.enableCaching) {
                UpdateCache(processId, result);
            }

            return result;
        }
        catch (const std::exception& e) {
            SS_LOG_ERROR(L"EnvironmentEvasionDetector", L"AnalyzeProcess failed: %hs", e.what());

            if (err) {
                err->win32Code = ERROR_INTERNAL_ERROR;
                err->message = L"Analysis failed";
            }

            m_impl->m_stats.analysisErrors++;
            return result;
        }
        catch (...) {
            SS_LOG_FATAL(L"EnvironmentEvasionDetector", L"AnalyzeProcess: Unknown error");

            if (err) {
                err->win32Code = ERROR_INTERNAL_ERROR;
                err->message = L"Unknown analysis error";
            }

            m_impl->m_stats.analysisErrors++;
            return result;
        }
    }

    EnvironmentEvasionResult EnvironmentEvasionDetector::AnalyzeProcess(
        HANDLE hProcess,
        const EnvironmentAnalysisConfig& config,
        EnvironmentError* err
    ) noexcept {
        EnvironmentEvasionResult result;

        try {
            if (!IsInitialized()) {
                if (err) {
                    err->win32Code = ERROR_NOT_READY;
                    err->message = L"Detector not initialized";
                }
                return result;
            }

            const uint32_t processId = GetProcessId(hProcess);
            if (processId == 0) {
                if (err) {
                    err->win32Code = GetLastError();
                    err->message = L"Failed to get process ID";
                }
                return result;
            }

            AnalyzeProcessInternal(hProcess, processId, config, result);
            m_impl->m_stats.totalAnalyses++;

            return result;
        }
        catch (const std::exception& e) {
            SS_LOG_ERROR(L"EnvironmentEvasionDetector", L"AnalyzeProcess (handle) failed: %hs", e.what());

            if (err) {
                err->win32Code = ERROR_INTERNAL_ERROR;
                err->message = L"Analysis failed";
            }

            m_impl->m_stats.analysisErrors++;
            return result;
        }
        catch (...) {
            if (err) {
                err->win32Code = ERROR_INTERNAL_ERROR;
                err->message = L"Unknown error";
            }
            m_impl->m_stats.analysisErrors++;
            return result;
        }
    }

    EnvironmentEvasionResult EnvironmentEvasionDetector::AnalyzeSystemEnvironment(
        const EnvironmentAnalysisConfig& config,
        EnvironmentError* err
    ) noexcept {
        EnvironmentEvasionResult result;

        try {
            if (!IsInitialized()) {
                if (err) {
                    err->win32Code = ERROR_NOT_READY;
                    err->message = L"Detector not initialized";
                }
                return result;
            }

            AnalyzeSystemInternal(config, result);
            m_impl->m_stats.totalAnalyses++;

            return result;
        }
        catch (const std::exception& e) {
            SS_LOG_ERROR(L"EnvironmentEvasionDetector", L"AnalyzeSystemEnvironment failed: %hs", e.what());

            if (err) {
                err->win32Code = ERROR_INTERNAL_ERROR;
                err->message = L"System analysis failed";
            }

            return result;
        }
        catch (...) {
            if (err) {
                err->win32Code = ERROR_INTERNAL_ERROR;
                err->message = L"Unknown error";
            }
            return result;
        }
    }

    // ========================================================================
    // INTERNAL ANALYSIS METHODS
    // Enterprise-grade comprehensive environment analysis implementation
    // ========================================================================

    void EnvironmentEvasionDetector::AnalyzeProcessInternal(
        HANDLE hProcess,
        uint32_t processId,
        const EnvironmentAnalysisConfig& config,
        EnvironmentEvasionResult& result
    ) noexcept {
        result.targetPid = processId;
        result.config = config;
        result.analysisStartTime = std::chrono::system_clock::now();

        // Collect all requested data based on flags
        if (HasFlag(config.flags, EnvironmentAnalysisFlags::ScanHardwareFingerprint)) {
            if (m_impl->m_cachedHardwareInfo) {
                result.hardwareInfo = *m_impl->m_cachedHardwareInfo;
            }
        }

        if (HasFlag(config.flags, EnvironmentAnalysisFlags::ScanNameChecks)) {
            if (m_impl->m_cachedIdentityInfo) {
                result.identityInfo = *m_impl->m_cachedIdentityInfo;
            }
        }

        if (HasFlag(config.flags, EnvironmentAnalysisFlags::ScanNetworkConfig)) {
            m_impl->CollectNetworkInfo(result.networkInfo);
        }

        if (HasFlag(config.flags, EnvironmentAnalysisFlags::ScanUserActivity)) {
            m_impl->CollectUserActivityInfo(result.activityInfo);
        }

        if (HasFlag(config.flags, EnvironmentAnalysisFlags::ScanEnvironmentVars)) {
            m_impl->CollectProcessEnvironmentInfo(processId, result.processEnvInfo);
        }

        // Run detection checks based on flags
        std::vector<EnvironmentDetectedTechnique> detections;

        if (HasFlag(config.flags, EnvironmentAnalysisFlags::ScanNameChecks)) {
            CheckBlacklistedNames(detections, nullptr);
        }

        if (HasFlag(config.flags, EnvironmentAnalysisFlags::ScanHardwareFingerprint)) {
            CheckHardwareFingerprint(result.hardwareInfo, detections, nullptr);
        }

        if (HasFlag(config.flags, EnvironmentAnalysisFlags::ScanFileSystemArtifacts)) {
            CheckFileSystemArtifacts(detections, nullptr);
        }

        if (HasFlag(config.flags, EnvironmentAnalysisFlags::ScanRegistryArtifacts)) {
            CheckRegistryArtifacts(detections, nullptr);
        }

        if (HasFlag(config.flags, EnvironmentAnalysisFlags::ScanNetworkConfig)) {
            CheckNetworkConfiguration(result.networkInfo, detections, nullptr);
        }

        if (HasFlag(config.flags, EnvironmentAnalysisFlags::ScanProcessEnumeration)) {
            CheckRunningProcesses(detections, nullptr);
        }

        if (HasFlag(config.flags, EnvironmentAnalysisFlags::ScanTimingChecks)) {
            CheckTimingIndicators(detections, nullptr);
        }

        // Add all detections to result
        for (auto& detection : detections) {
            AddDetection(result, std::move(detection));
        }

        CalculateEvasionScore(result);

        result.analysisEndTime = std::chrono::system_clock::now();
        result.analysisComplete = true;
    }

    void EnvironmentEvasionDetector::AnalyzeSystemInternal(
        const EnvironmentAnalysisConfig& config,
        EnvironmentEvasionResult& result
    ) noexcept {
        // System-wide analysis (similar to process analysis but without process-specific checks)
        result.targetPid = 0;
        result.processName = L"[System-Wide Scan]";
        result.config = config;
        result.analysisStartTime = std::chrono::system_clock::now();

        // Use cached system info
        if (m_impl->m_cachedIdentityInfo) {
            result.identityInfo = *m_impl->m_cachedIdentityInfo;
        }

        if (m_impl->m_cachedHardwareInfo) {
            result.hardwareInfo = *m_impl->m_cachedHardwareInfo;
        }

        std::vector<EnvironmentDetectedTechnique> detections;

        CheckBlacklistedNames(detections, nullptr);
        CheckHardwareFingerprint(result.hardwareInfo, detections, nullptr);
        CheckFileSystemArtifacts(detections, nullptr);
        CheckRegistryArtifacts(detections, nullptr);
        CheckTimingIndicators(detections, nullptr);

        for (auto& detection : detections) {
            AddDetection(result, std::move(detection));
        }

        CalculateEvasionScore(result);

        result.analysisEndTime = std::chrono::system_clock::now();
        result.analysisComplete = true;
    }

    void EnvironmentEvasionDetector::CalculateEvasionScore(EnvironmentEvasionResult& result) noexcept {
        double score = 0.0;
        EnvironmentEvasionSeverity maxSev = EnvironmentEvasionSeverity::Low;

        for (const auto& detection : result.detectedTechniques) {
            // Weight by category
            double categoryWeight = 1.0;
            switch (detection.category) {
            case EnvironmentEvasionCategory::NameChecks:
                categoryWeight = EnvironmentConstants::WEIGHT_NAME_CHECKS;
                break;
            case EnvironmentEvasionCategory::HardwareFingerprinting:
                categoryWeight = EnvironmentConstants::WEIGHT_HARDWARE_CHECKS;
                break;
            case EnvironmentEvasionCategory::FileSystemArtifacts:
                categoryWeight = EnvironmentConstants::WEIGHT_FILESYSTEM_CHECKS;
                break;
            case EnvironmentEvasionCategory::RegistryArtifacts:
                categoryWeight = EnvironmentConstants::WEIGHT_REGISTRY_CHECKS;
                break;
            case EnvironmentEvasionCategory::UserActivityIndicators:
                categoryWeight = EnvironmentConstants::WEIGHT_USER_ACTIVITY_CHECKS;
                break;
            case EnvironmentEvasionCategory::NetworkConfiguration:
                categoryWeight = EnvironmentConstants::WEIGHT_NETWORK_CHECKS;
                break;
            case EnvironmentEvasionCategory::ProcessEnumeration:
                categoryWeight = EnvironmentConstants::WEIGHT_PROCESS_CHECKS;
                break;
            case EnvironmentEvasionCategory::TimingChecks:
                categoryWeight = EnvironmentConstants::WEIGHT_TIMING_CHECKS;
                break;
            default:
                categoryWeight = 1.0;
            }

            // Weight by severity
            double severityMultiplier = 1.0;
            switch (detection.severity) {
            case EnvironmentEvasionSeverity::Low: severityMultiplier = 1.0; break;
            case EnvironmentEvasionSeverity::Medium: severityMultiplier = 2.5; break;
            case EnvironmentEvasionSeverity::High: severityMultiplier = 5.0; break;
            case EnvironmentEvasionSeverity::Critical: severityMultiplier = 10.0; break;
            }

            score += (categoryWeight * severityMultiplier * detection.confidence);

            if (detection.severity > maxSev) {
                maxSev = detection.severity;
            }
        }

        result.evasionScore = std::min(score, 100.0);
        result.maxSeverity = maxSev;
        result.isEvasive = (score >= EnvironmentConstants::HIGH_EVASION_THRESHOLD);
    }

    void EnvironmentEvasionDetector::AddDetection(
        EnvironmentEvasionResult& result,
        EnvironmentDetectedTechnique detection
    ) noexcept {
        // Set category bit
        const auto catIdx = static_cast<uint32_t>(detection.category);
        if (catIdx < 16) {
            result.detectedCategories |= (1u << catIdx);
            m_impl->m_stats.categoryDetections[catIdx]++;
        }

        result.totalDetections++;
        m_impl->m_stats.totalDetections++;

        // Invoke callback if set
        if (m_impl->m_detectionCallback) {
            try {
                m_impl->m_detectionCallback(result.targetPid, detection);
            }
            catch (...) {
                // Swallow callback exceptions
            }
        }

        result.detectedTechniques.push_back(std::move(detection));
    }

    // ========================================================================
    // CATEGORY CHECK IMPLEMENTATIONS
    // ========================================================================

    bool EnvironmentEvasionDetector::CheckBlacklistedNames(
        std::vector<EnvironmentDetectedTechnique>& outDetections,
        EnvironmentError* err
    ) noexcept {
        try {
            bool found = false;
            std::shared_lock lock(m_impl->m_mutex);

            // Use cached identity info
            if (!m_impl->m_cachedIdentityInfo || !m_impl->m_cachedIdentityInfo->valid) {
                return false;
            }

            const auto& identity = *m_impl->m_cachedIdentityInfo;

            // Check username
            if (m_impl->IsBlacklistedUsername(identity.username)) {
                EnvironmentDetectedTechnique detection(EnvironmentEvasionTechnique::NAME_BlacklistedUsername);
                detection.confidence = 0.95;
                detection.detectedValue = identity.username;
                detection.description = L"Username matches known sandbox/analysis environment";
                detection.source = L"System Identity";
                outDetections.push_back(detection);
                found = true;
            }

            // Check computer name
            if (m_impl->IsBlacklistedComputerName(identity.computerName)) {
                EnvironmentDetectedTechnique detection(EnvironmentEvasionTechnique::NAME_BlacklistedComputerName);
                detection.confidence = 0.95;
                detection.detectedValue = identity.computerName;
                detection.description = L"Computer name matches known sandbox/analysis environment";
                detection.source = L"System Identity";
                outDetections.push_back(detection);
                found = true;
            }

            return found;
        }
        catch (const std::exception& e) {
            SS_LOG_ERROR(L"EnvironmentEvasionDetector", L"CheckBlacklistedNames failed: %hs", e.what());

            if (err) {
                err->win32Code = ERROR_INTERNAL_ERROR;
                err->message = L"Name check failed";
            }
            return false;
        }
        catch (...) {
            if (err) {
                err->win32Code = ERROR_INTERNAL_ERROR;
                err->message = L"Unknown error";
            }
            return false;
        }
    }

    bool EnvironmentEvasionDetector::CheckHardwareFingerprint(
        HardwareFingerprintInfo& outHardwareInfo,
        std::vector<EnvironmentDetectedTechnique>& outDetections,
        EnvironmentError* err
    ) noexcept {
        try {
            bool found = false;

            if (!outHardwareInfo.valid) {
                return false;
            }

            // Check low processor count
            if (outHardwareInfo.processorCount < EnvironmentConstants::MIN_NORMAL_PROCESSOR_COUNT) {
                EnvironmentDetectedTechnique detection(EnvironmentEvasionTechnique::HARDWARE_LowProcessorCount);
                detection.confidence = 0.7;
                detection.detectedValue = std::to_wstring(outHardwareInfo.processorCount);
                detection.expectedValue = L">= 2";
                detection.description = L"Low processor count typical of sandbox environments";
                outDetections.push_back(detection);
                found = true;
            }

            // Check low RAM
            if (outHardwareInfo.totalRAM < EnvironmentConstants::MIN_NORMAL_RAM_BYTES) {
                EnvironmentDetectedTechnique detection(EnvironmentEvasionTechnique::HARDWARE_LowRAM);
                detection.confidence = 0.7;
                detection.detectedValue = std::to_wstring(outHardwareInfo.totalRAM / (1024 * 1024)) + L" MB";
                detection.expectedValue = L">= 2048 MB";
                detection.description = L"Low RAM typical of sandbox VMs";
                outDetections.push_back(detection);
                found = true;
            }

            // Check hypervisor bit
            if (outHardwareInfo.hypervisorDetected) {
                EnvironmentDetectedTechnique detection(EnvironmentEvasionTechnique::HARDWARE_HypervisorBit);
                detection.confidence = 0.95;
                detection.detectedValue = L"Present";
                detection.description = L"CPUID hypervisor bit is set - running in VM";
                outDetections.push_back(detection);
                found = true;
            }

            // Check for VM indicators in hardware strings
            if (!outHardwareInfo.vmIndicators.empty()) {
                EnvironmentDetectedTechnique detection(EnvironmentEvasionTechnique::HARDWARE_VMManufacturer);
                detection.confidence = 0.90;
                detection.detectedValue = outHardwareInfo.manufacturer;
                detection.description = L"VM indicators found in hardware info";
                detection.technicalDetails = L"Keywords: " +
                    [&]() {
                    std::wstring result;
                    for (const auto& ind : outHardwareInfo.vmIndicators) {
                        if (!result.empty()) result += L", ";
                        result += ind;
                    }
                    return result;
                    }();
                outDetections.push_back(detection);
                found = true;
            }

            return found;
        }
        catch (const std::exception& e) {
            SS_LOG_ERROR(L"EnvironmentEvasionDetector", L"CheckHardwareFingerprint failed: %hs", e.what());

            if (err) {
                err->win32Code = ERROR_INTERNAL_ERROR;
                err->message = L"Hardware check failed";
            }
            return false;
        }
        catch (...) {
            if (err) {
                err->win32Code = ERROR_INTERNAL_ERROR;
                err->message = L"Unknown error";
            }
            return false;
        }
    }
    // ========================================================================
    // COMPREHENSIVE FILE SYSTEM ARTIFACT CHECKS
    // Enterprise-grade VM/Sandbox detection through file system analysis
    // ========================================================================

    bool EnvironmentEvasionDetector::CheckFileSystemArtifacts(
        std::vector<EnvironmentDetectedTechnique>& outDetections,
        EnvironmentError* err
    ) noexcept {
        try {
            bool found = false;
            std::shared_lock lock(m_impl->m_mutex);

            // ================================================================
            // 1. VM GUEST TOOLS DIRECTORIES
            // ================================================================
            const std::vector<std::pair<std::wstring, std::wstring>> vmToolsDirs = {
                // VMware
                {L"C:\\Program Files\\VMware\\VMware Tools", L"VMware"},
                {L"C:\\Program Files (x86)\\VMware\\VMware Tools", L"VMware"},
                {L"C:\\Windows\\System32\\vmGuestLib.dll", L"VMware"},
                {L"C:\\Windows\\System32\\vmhgfs.dll", L"VMware"},
                {L"C:\\Windows\\System32\\drivers\\vmhgfs.sys", L"VMware"},
                {L"C:\\Windows\\System32\\drivers\\vmmouse.sys", L"VMware"},
                {L"C:\\Windows\\System32\\drivers\\vmrawdsk.sys", L"VMware"},
                {L"C:\\Windows\\System32\\drivers\\vmusbmouse.sys", L"VMware"},

                // VirtualBox
                {L"C:\\Program Files\\Oracle\\VirtualBox Guest Additions", L"VirtualBox"},
                {L"C:\\Windows\\System32\\VBoxControl.exe", L"VirtualBox"},
                {L"C:\\Windows\\System32\\VBoxDisp.dll", L"VirtualBox"},
                {L"C:\\Windows\\System32\\VBoxHook.dll", L"VirtualBox"},
                {L"C:\\Windows\\System32\\VBoxMRXNP.dll", L"VirtualBox"},
                {L"C:\\Windows\\System32\\VBoxOGL.dll", L"VirtualBox"},
                {L"C:\\Windows\\System32\\VBoxOGLarrayspu.dll", L"VirtualBox"},
                {L"C:\\Windows\\System32\\VBoxService.exe", L"VirtualBox"},
                {L"C:\\Windows\\System32\\VBoxTray.exe", L"VirtualBox"},
                {L"C:\\Windows\\System32\\drivers\\VBoxGuest.sys", L"VirtualBox"},
                {L"C:\\Windows\\System32\\drivers\\VBoxMouse.sys", L"VirtualBox"},
                {L"C:\\Windows\\System32\\drivers\\VBoxSF.sys", L"VirtualBox"},
                {L"C:\\Windows\\System32\\drivers\\VBoxVideo.sys", L"VirtualBox"},

                // QEMU/KVM
                {L"C:\\Program Files\\Qemu-ga", L"QEMU"},
                {L"C:\\Program Files\\qemu-ga\\qemu-ga.exe", L"QEMU"},
                {L"C:\\Windows\\System32\\drivers\\balloon.sys", L"QEMU/Virtio"},
                {L"C:\\Windows\\System32\\drivers\\netkvm.sys", L"QEMU/Virtio"},
                {L"C:\\Windows\\System32\\drivers\\vioinput.sys", L"QEMU/Virtio"},
                {L"C:\\Windows\\System32\\drivers\\viorng.sys", L"QEMU/Virtio"},
                {L"C:\\Windows\\System32\\drivers\\vioscsi.sys", L"QEMU/Virtio"},
                {L"C:\\Windows\\System32\\drivers\\vioserial.sys", L"QEMU/Virtio"},
                {L"C:\\Windows\\System32\\drivers\\viostor.sys", L"QEMU/Virtio"},

                // Hyper-V
                {L"C:\\Windows\\System32\\drivers\\vmbus.sys", L"Hyper-V"},
                {L"C:\\Windows\\System32\\drivers\\VMBusHID.sys", L"Hyper-V"},
                {L"C:\\Windows\\System32\\drivers\\hyperkbd.sys", L"Hyper-V"},
                {L"C:\\Windows\\System32\\drivers\\hvservice.sys", L"Hyper-V"},
                {L"C:\\Windows\\System32\\vmicheartbeat.dll", L"Hyper-V"},
                {L"C:\\Windows\\System32\\vmicshutdown.dll", L"Hyper-V"},
                {L"C:\\Windows\\System32\\vmictimesync.dll", L"Hyper-V"},
                {L"C:\\Windows\\System32\\vmicvss.dll", L"Hyper-V"},

                // Parallels
                {L"C:\\Program Files\\Parallels\\Parallels Tools", L"Parallels"},
                {L"C:\\Windows\\System32\\drivers\\prl_boot.sys", L"Parallels"},
                {L"C:\\Windows\\System32\\drivers\\prl_fs.sys", L"Parallels"},
                {L"C:\\Windows\\System32\\drivers\\prl_memdev.sys", L"Parallels"},
                {L"C:\\Windows\\System32\\drivers\\prl_mouf.sys", L"Parallels"},
                {L"C:\\Windows\\System32\\drivers\\prl_pv32.sys", L"Parallels"},
                {L"C:\\Windows\\System32\\drivers\\prl_tg.sys", L"Parallels"},

                // Xen
                {L"C:\\Windows\\System32\\drivers\\xen.sys", L"Xen"},
                {L"C:\\Windows\\System32\\drivers\\xenfilt.sys", L"Xen"},
                {L"C:\\Windows\\System32\\drivers\\xennet.sys", L"Xen"},
                {L"C:\\Windows\\System32\\drivers\\xenvbd.sys", L"Xen"},

                // SPICE (remote virtualization)
                {L"C:\\Program Files\\SPICE Guest Tools", L"SPICE"},
                {L"C:\\Windows\\System32\\qxl.dll", L"SPICE"},
            };

            for (const auto& [path, vendor] : vmToolsDirs) {
                if (fs::exists(path)) {
                    EnvironmentDetectedTechnique detection(EnvironmentEvasionTechnique::FILESYSTEM_VMToolsDirectory);
                    detection.confidence = 0.98;
                    detection.detectedValue = path;
                    detection.description = vendor + L" VM artifact detected";
                    detection.source = L"File System";
                    detection.technicalDetails = L"Vendor: " + vendor;
                    outDetections.push_back(detection);
                    found = true;
                }
            }

            // ================================================================
            // 2. SANDBOX-SPECIFIC FILES AND DIRECTORIES
            // ================================================================
            const std::vector<std::pair<std::wstring, std::wstring>> sandboxPaths = {
                // Cuckoo Sandbox
                {L"C:\\cuckoo", L"Cuckoo Sandbox"},
                {L"C:\\analysis", L"Generic Sandbox"},
                {L"C:\\agent", L"Sandbox Agent"},
                {L"C:\\sandbox", L"Generic Sandbox"},
                {L"C:\\insidetm", L"ThreatGrid"},
                {L"C:\\strawberry", L"Perl Sandbox"},

                // Sandboxie
                {L"C:\\Program Files\\Sandboxie", L"Sandboxie"},
                {L"C:\\Program Files\\Sandboxie-Plus", L"Sandboxie-Plus"},
                {L"C:\\Sandbox", L"Sandboxie"},

                // Analysis tools
                {L"C:\\Program Files\\Wireshark", L"Wireshark Analysis"},
                {L"C:\\Program Files\\Process Monitor", L"SysInternals"},
                {L"C:\\Program Files\\Sysinternals", L"SysInternals"},
                {L"C:\\SysInternals", L"SysInternals"},

                // Sample directories
                {L"C:\\samples", L"Analysis Environment"},
                {L"C:\\malware", L"Analysis Environment"},
                {L"C:\\virus", L"Analysis Environment"},
            };

            for (const auto& [path, desc] : sandboxPaths) {
                if (fs::exists(path)) {
                    EnvironmentDetectedTechnique detection(EnvironmentEvasionTechnique::FILESYSTEM_SandboxAgentFiles);
                    detection.confidence = 0.90;
                    detection.detectedValue = path;
                    detection.description = desc + L" directory detected";
                    detection.source = L"File System";
                    outDetections.push_back(detection);
                    found = true;
                }
            }

            // ================================================================
            // 3. SUSPICIOUS DLL FILES IN SYSTEM32
            // ================================================================
            const std::vector<std::pair<std::wstring, std::wstring>> suspiciousDlls = {
                {L"C:\\Windows\\System32\\sbiedll.dll", L"Sandboxie Hook DLL"},
                {L"C:\\Windows\\System32\\api_log.dll", L"API Logging DLL"},
                {L"C:\\Windows\\System32\\dir_watch.dll", L"Directory Watcher DLL"},
                {L"C:\\Windows\\System32\\pstorec.dll", L"Protected Storage"},
                {L"C:\\Windows\\System32\\cmdvrt32.dll", L"Comodo Sandbox"},
                {L"C:\\Windows\\System32\\cmdvrt64.dll", L"Comodo Sandbox"},
                {L"C:\\Windows\\System32\\cuckoomon.dll", L"Cuckoo Monitor"},
                {L"C:\\Windows\\System32\\avghookx.dll", L"AVG Hook"},
                {L"C:\\Windows\\System32\\avghooka.dll", L"AVG Hook"},
                {L"C:\\Windows\\System32\\snxhk.dll", L"Avast Hook"},
                {L"C:\\Windows\\System32\\sxin.dll", L"360 Sandbox"},
                {L"C:\\Windows\\System32\\sf2.dll", L"Avast Sandbox"},
            };

            for (const auto& [path, desc] : suspiciousDlls) {
                if (fs::exists(path)) {
                    EnvironmentDetectedTechnique detection(EnvironmentEvasionTechnique::FILESYSTEM_AnalysisToolsInstalled);
                    detection.confidence = 0.95;
                    detection.detectedValue = path;
                    detection.description = desc + L" detected in System32";
                    detection.source = L"File System";
                    outDetections.push_back(detection);
                    found = true;
                }
            }

            // ================================================================
            // 4. "LIVED-IN" SYSTEM CHECKS
            // ================================================================
            UserActivityInfo activityInfo;
            m_impl->CollectUserActivityInfo(activityInfo);

            // Empty Desktop folder check
            if (activityInfo.desktopItemsCount == 0) {
                EnvironmentDetectedTechnique detection(EnvironmentEvasionTechnique::FILESYSTEM_EmptyDesktop);
                detection.confidence = 0.65;
                detection.detectedValue = L"0 items";
                detection.description = L"Empty Desktop folder (typical of fresh sandboxes)";
                detection.source = L"User Activity";
                outDetections.push_back(detection);
                found = true;
            }

            // Empty Documents folder check
            if (activityInfo.documentsCount == 0) {
                EnvironmentDetectedTechnique detection(EnvironmentEvasionTechnique::FILESYSTEM_EmptyDocuments);
                detection.confidence = 0.60;
                detection.detectedValue = L"0 items";
                detection.description = L"Empty Documents folder";
                detection.source = L"User Activity";
                outDetections.push_back(detection);
                found = true;
            }

            // Empty Downloads folder check
            if (activityInfo.downloadsCount == 0) {
                EnvironmentDetectedTechnique detection(EnvironmentEvasionTechnique::FILESYSTEM_EmptyDownloads);
                detection.confidence = 0.60;
                detection.detectedValue = L"0 items";
                detection.description = L"Empty Downloads folder";
                detection.source = L"User Activity";
                outDetections.push_back(detection);
                found = true;
            }

            // Very few Recent Documents
            if (activityInfo.recentDocumentsCount < 3) {
                EnvironmentDetectedTechnique detection(EnvironmentEvasionTechnique::FILESYSTEM_NoRecentFiles);
                detection.confidence = 0.55;
                detection.detectedValue = std::to_wstring(activityInfo.recentDocumentsCount) + L" items";
                detection.expectedValue = L">= 5 items";
                detection.description = L"Very few recent documents (sandbox indicator)";
                detection.source = L"User Activity";
                outDetections.push_back(detection);
                found = true;
            }

            // ================================================================
            // 5. WINDOWS PREFETCH ANALYSIS
            // ================================================================
            const std::wstring prefetchPath = L"C:\\Windows\\Prefetch";
            if (fs::exists(prefetchPath) && fs::is_directory(prefetchPath)) {
                size_t prefetchCount = 0;
                try {
                    for (const auto& entry : fs::directory_iterator(prefetchPath)) {
                        if (entry.path().extension() == L".pf") {
                            prefetchCount++;
                            if (prefetchCount > 50) break; // Enough to determine lived-in
                        }
                    }
                }
                catch (...) {}

                if (prefetchCount < 10) {
                    EnvironmentDetectedTechnique detection(EnvironmentEvasionTechnique::FILESYSTEM_CleanSystemDirs);
                    detection.confidence = 0.70;
                    detection.detectedValue = std::to_wstring(prefetchCount) + L" prefetch files";
                    detection.expectedValue = L">= 30 files on normal system";
                    detection.description = L"Very few prefetch files (fresh/sandbox system)";
                    detection.source = L"Windows Prefetch";
                    outDetections.push_back(detection);
                    found = true;
                }
            }

            // ================================================================
            // 6. TEMP FOLDER ANALYSIS
            // ================================================================
            wchar_t tempPath[MAX_PATH];
            if (GetTempPathW(MAX_PATH, tempPath)) {
                size_t tempFileCount = 0;
                try {
                    for (const auto& entry : fs::directory_iterator(tempPath)) {
                        (void)entry;
                        tempFileCount++;
                        if (tempFileCount > 100) break;
                    }
                }
                catch (...) {}

                if (tempFileCount < 5) {
                    EnvironmentDetectedTechnique detection(EnvironmentEvasionTechnique::FILESYSTEM_SuspiciousTempDir);
                    detection.confidence = 0.55;
                    detection.detectedValue = std::to_wstring(tempFileCount) + L" items";
                    detection.description = L"Nearly empty TEMP folder (fresh/sandbox system)";
                    detection.source = L"File System";
                    outDetections.push_back(detection);
                    found = true;
                }
            }

            // ================================================================
            // 7. CHECK FOR COMMON PRODUCTIVITY SOFTWARE
            // ================================================================
            const std::vector<std::wstring> productivityApps = {
                L"C:\\Program Files\\Microsoft Office",
                L"C:\\Program Files (x86)\\Microsoft Office",
                L"C:\\Program Files\\Adobe",
                L"C:\\Program Files (x86)\\Adobe",
                L"C:\\Program Files\\Google\\Chrome",
                L"C:\\Program Files (x86)\\Google\\Chrome",
                L"C:\\Program Files\\Mozilla Firefox",
                L"C:\\Program Files (x86)\\Mozilla Firefox",
                L"C:\\Program Files\\7-Zip",
                L"C:\\Program Files\\WinRAR",
            };

            size_t installedApps = 0;
            for (const auto& appPath : productivityApps) {
                if (fs::exists(appPath)) {
                    installedApps++;
                }
            }

            if (installedApps < 2) {
                EnvironmentDetectedTechnique detection(EnvironmentEvasionTechnique::FILESYSTEM_MissingUserArtifacts);
                detection.confidence = 0.50;
                detection.detectedValue = std::to_wstring(installedApps) + L" common apps found";
                detection.expectedValue = L">= 3 on typical user system";
                detection.description = L"Very few common applications installed (sandbox indicator)";
                detection.source = L"File System";
                outDetections.push_back(detection);
                found = true;
            }

            return found;
        }
        catch (const std::exception& e) {
            SS_LOG_ERROR(L"EnvironmentEvasionDetector", L"CheckFileSystemArtifacts failed: %hs", e.what());
            if (err) {
                err->win32Code = ERROR_INTERNAL_ERROR;
                err->message = L"File system check failed";
            }
            return false;
        }
        catch (...) {
            if (err) {
                err->win32Code = ERROR_INTERNAL_ERROR;
                err->message = L"Unknown error in file system check";
            }
            return false;
        }
    }

    // ========================================================================
    // COMPREHENSIVE REGISTRY ARTIFACT CHECKS
    // Enterprise-grade VM/Sandbox detection through registry analysis
    // ========================================================================

    bool EnvironmentEvasionDetector::CheckRegistryArtifacts(
        std::vector<EnvironmentDetectedTechnique>& outDetections,
        EnvironmentError* err
    ) noexcept {
        try {
            bool found = false;

            // ================================================================
            // 1. VM-SPECIFIC REGISTRY KEYS (HKLM)
            // ================================================================
            const std::vector<std::tuple<std::wstring, std::wstring, EnvironmentEvasionTechnique>> vmRegistryKeys = {
                // VMware
                {L"SOFTWARE\\VMware, Inc.\\VMware Tools", L"VMware Tools", EnvironmentEvasionTechnique::REGISTRY_VMwareKeys},
                {L"SOFTWARE\\VMware, Inc.\\VMware VGAuth", L"VMware VGAuth", EnvironmentEvasionTechnique::REGISTRY_VMwareKeys},
                {L"SYSTEM\\CurrentControlSet\\Services\\vmtools", L"VMware Tools Service", EnvironmentEvasionTechnique::REGISTRY_VMwareKeys},
                {L"SYSTEM\\CurrentControlSet\\Services\\vmvss", L"VMware VSS", EnvironmentEvasionTechnique::REGISTRY_VMwareKeys},
                {L"SYSTEM\\CurrentControlSet\\Services\\vmhgfs", L"VMware HGFS", EnvironmentEvasionTechnique::REGISTRY_VMwareKeys},
                {L"SYSTEM\\CurrentControlSet\\Services\\VMMEMCTL", L"VMware Memory Control", EnvironmentEvasionTechnique::REGISTRY_VMwareKeys},
                {L"SYSTEM\\ControlSet001\\Services\\vmci", L"VMware VMCI", EnvironmentEvasionTechnique::REGISTRY_VMwareKeys},
                {L"SYSTEM\\ControlSet001\\Services\\vmx86", L"VMware vmx86", EnvironmentEvasionTechnique::REGISTRY_VMwareKeys},

                // VirtualBox
                {L"SOFTWARE\\Oracle\\VirtualBox Guest Additions", L"VirtualBox Guest Additions", EnvironmentEvasionTechnique::REGISTRY_VirtualBoxKeys},
                {L"SYSTEM\\CurrentControlSet\\Services\\VBoxGuest", L"VirtualBox Guest", EnvironmentEvasionTechnique::REGISTRY_VirtualBoxKeys},
                {L"SYSTEM\\CurrentControlSet\\Services\\VBoxMouse", L"VirtualBox Mouse", EnvironmentEvasionTechnique::REGISTRY_VirtualBoxKeys},
                {L"SYSTEM\\CurrentControlSet\\Services\\VBoxService", L"VirtualBox Service", EnvironmentEvasionTechnique::REGISTRY_VirtualBoxKeys},
                {L"SYSTEM\\CurrentControlSet\\Services\\VBoxSF", L"VirtualBox SF", EnvironmentEvasionTechnique::REGISTRY_VirtualBoxKeys},
                {L"SYSTEM\\CurrentControlSet\\Services\\VBoxVideo", L"VirtualBox Video", EnvironmentEvasionTechnique::REGISTRY_VirtualBoxKeys},
                {L"HARDWARE\\ACPI\\DSDT\\VBOX__", L"VirtualBox ACPI", EnvironmentEvasionTechnique::REGISTRY_VirtualBoxKeys},
                {L"HARDWARE\\ACPI\\FADT\\VBOX__", L"VirtualBox FADT", EnvironmentEvasionTechnique::REGISTRY_VirtualBoxKeys},
                {L"HARDWARE\\ACPI\\RSDT\\VBOX__", L"VirtualBox RSDT", EnvironmentEvasionTechnique::REGISTRY_VirtualBoxKeys},

                // QEMU/KVM
                {L"SYSTEM\\CurrentControlSet\\Services\\qemu-ga", L"QEMU Guest Agent", EnvironmentEvasionTechnique::REGISTRY_QEMUKeys},
                {L"SYSTEM\\CurrentControlSet\\Services\\BALLOON", L"QEMU/KVM Balloon", EnvironmentEvasionTechnique::REGISTRY_QEMUKeys},
                {L"SYSTEM\\CurrentControlSet\\Services\\VirtIO", L"QEMU/KVM VirtIO", EnvironmentEvasionTechnique::REGISTRY_QEMUKeys},
                {L"SYSTEM\\CurrentControlSet\\Services\\netkvm", L"QEMU/KVM NetKVM", EnvironmentEvasionTechnique::REGISTRY_QEMUKeys},
                {L"SYSTEM\\CurrentControlSet\\Services\\viostor", L"QEMU/KVM Viostor", EnvironmentEvasionTechnique::REGISTRY_QEMUKeys},
                {L"HARDWARE\\ACPI\\DSDT\\BOCHS_", L"BOCHS/QEMU ACPI", EnvironmentEvasionTechnique::REGISTRY_QEMUKeys},
                {L"HARDWARE\\ACPI\\FADT\\BOCHS_", L"BOCHS/QEMU FADT", EnvironmentEvasionTechnique::REGISTRY_QEMUKeys},

                // Hyper-V
                {L"SOFTWARE\\Microsoft\\Virtual Machine\\Guest\\Parameters", L"Hyper-V Guest", EnvironmentEvasionTechnique::REGISTRY_HyperVKeys},
                {L"SYSTEM\\CurrentControlSet\\Services\\vmbus", L"Hyper-V VMBus", EnvironmentEvasionTechnique::REGISTRY_HyperVKeys},
                {L"SYSTEM\\CurrentControlSet\\Services\\vmicheartbeat", L"Hyper-V Heartbeat", EnvironmentEvasionTechnique::REGISTRY_HyperVKeys},
                {L"SYSTEM\\CurrentControlSet\\Services\\vmickvpexchange", L"Hyper-V KVP", EnvironmentEvasionTechnique::REGISTRY_HyperVKeys},
                {L"SYSTEM\\CurrentControlSet\\Services\\vmicshutdown", L"Hyper-V Shutdown", EnvironmentEvasionTechnique::REGISTRY_HyperVKeys},
                {L"SYSTEM\\CurrentControlSet\\Services\\vmictimesync", L"Hyper-V Time Sync", EnvironmentEvasionTechnique::REGISTRY_HyperVKeys},
                {L"SYSTEM\\CurrentControlSet\\Services\\vmicvss", L"Hyper-V VSS", EnvironmentEvasionTechnique::REGISTRY_HyperVKeys},

                // Parallels
                {L"SYSTEM\\CurrentControlSet\\Services\\prl_boot", L"Parallels Boot", EnvironmentEvasionTechnique::REGISTRY_ParallelsKeys},
                {L"SYSTEM\\CurrentControlSet\\Services\\prl_fs", L"Parallels FS", EnvironmentEvasionTechnique::REGISTRY_ParallelsKeys},
                {L"SYSTEM\\CurrentControlSet\\Services\\prl_memdev", L"Parallels MemDev", EnvironmentEvasionTechnique::REGISTRY_ParallelsKeys},
                {L"SYSTEM\\CurrentControlSet\\Services\\prl_mouf", L"Parallels Mouse", EnvironmentEvasionTechnique::REGISTRY_ParallelsKeys},
                {L"SYSTEM\\CurrentControlSet\\Services\\prl_tg", L"Parallels TG", EnvironmentEvasionTechnique::REGISTRY_ParallelsKeys},

                // Xen (use VMServices for VM services)
                {L"SYSTEM\\CurrentControlSet\\Services\\xenevtchn", L"Xen Event Channel", EnvironmentEvasionTechnique::REGISTRY_VMServices},
                {L"SYSTEM\\CurrentControlSet\\Services\\xennet", L"Xen Network", EnvironmentEvasionTechnique::REGISTRY_VMServices},
                {L"SYSTEM\\CurrentControlSet\\Services\\xenvbd", L"Xen VBD", EnvironmentEvasionTechnique::REGISTRY_VMServices},
                {L"SYSTEM\\CurrentControlSet\\Services\\xenfilt", L"Xen Filter", EnvironmentEvasionTechnique::REGISTRY_VMServices},
            };

            for (const auto& [key, desc, technique] : vmRegistryKeys) {
                if (m_impl->RegistryKeyExists(HKEY_LOCAL_MACHINE, key)) {
                    EnvironmentDetectedTechnique detection(technique);
                    detection.confidence = 0.97;
                    detection.detectedValue = key;
                    detection.description = desc + L" registry key detected";
                    detection.source = L"Registry";
                    detection.mitreId = EnvironmentTechniqueToMitreId(technique);
                    outDetections.push_back(detection);
                    found = true;
                }
            }

            // ================================================================
            // 2. SANDBOX-SPECIFIC REGISTRY KEYS
            // ================================================================
            const std::vector<std::tuple<std::wstring, std::wstring, EnvironmentEvasionTechnique>> sandboxKeys = {
                // Sandboxie
                {L"SOFTWARE\\Sandboxie", L"Sandboxie", EnvironmentEvasionTechnique::REGISTRY_SandboxieKeys},
                {L"SYSTEM\\CurrentControlSet\\Services\\SbieDrv", L"Sandboxie Driver", EnvironmentEvasionTechnique::REGISTRY_SandboxieKeys},
                {L"SOFTWARE\\Sandboxie-Plus", L"Sandboxie-Plus", EnvironmentEvasionTechnique::REGISTRY_SandboxieKeys},

                // Comodo, CWSandbox, Cuckoo - use SandboxieKeys as generic sandbox
                {L"SOFTWARE\\Comodo\\CIS", L"Comodo CIS", EnvironmentEvasionTechnique::REGISTRY_SandboxieKeys},
                {L"SYSTEM\\CurrentControlSet\\Services\\cmdGuard", L"Comodo Guard", EnvironmentEvasionTechnique::REGISTRY_SandboxieKeys},

                // CWSandbox
                {L"SOFTWARE\\CWSandbox", L"CWSandbox", EnvironmentEvasionTechnique::REGISTRY_SandboxieKeys},

                // Cuckoo
                {L"SOFTWARE\\Cuckoo", L"Cuckoo Sandbox", EnvironmentEvasionTechnique::REGISTRY_SandboxieKeys},
            };

            for (const auto& [key, desc, technique] : sandboxKeys) {
                if (m_impl->RegistryKeyExists(HKEY_LOCAL_MACHINE, key)) {
                    EnvironmentDetectedTechnique detection(technique);
                    detection.confidence = 0.98;
                    detection.detectedValue = key;
                    detection.description = desc + L" registry key detected";
                    detection.source = L"Registry";
                    detection.severity = EnvironmentEvasionSeverity::Critical;
                    outDetections.push_back(detection);
                    found = true;
                }
            }

            // ================================================================
            // 3. HARDWARE DESCRIPTION CHECKS
            // ================================================================
            // Check SystemBiosVersion for VM strings
            std::wstring biosVersion = m_impl->GetRegistryString(HKEY_LOCAL_MACHINE,
                L"HARDWARE\\DESCRIPTION\\System", L"SystemBiosVersion");
            if (!biosVersion.empty()) {
                const std::vector<std::pair<std::wstring, std::wstring>> vmBiosStrings = {
                    {L"VBOX", L"VirtualBox"},
                    {L"VMWARE", L"VMware"},
                    {L"QEMU", L"QEMU"},
                    {L"BOCHS", L"BOCHS"},
                    {L"XEN", L"Xen"},
                    {L"VIRTUAL", L"Generic VM"},
                };

                for (const auto& [pattern, vendor] : vmBiosStrings) {
                    if (m_impl->ContainsSubstringCI(biosVersion, pattern)) {
                        EnvironmentDetectedTechnique detection(EnvironmentEvasionTechnique::REGISTRY_VMServices);
                        detection.confidence = 0.95;
                        detection.detectedValue = biosVersion;
                        detection.description = vendor + L" detected in BIOS version string";
                        detection.source = L"Registry - Hardware Description";
                        outDetections.push_back(detection);
                        found = true;
                        break;
                    }
                }
            }

            // Check VideoBiosVersion
            std::wstring videoBios = m_impl->GetRegistryString(HKEY_LOCAL_MACHINE,
                L"HARDWARE\\DESCRIPTION\\System", L"VideoBiosVersion");
            if (!videoBios.empty() && m_impl->ContainsSubstringCI(videoBios, L"VIRTUALBOX")) {
                EnvironmentDetectedTechnique detection(EnvironmentEvasionTechnique::REGISTRY_VirtualBoxKeys);
                detection.confidence = 0.95;
                detection.detectedValue = videoBios;
                detection.description = L"VirtualBox detected in Video BIOS string";
                detection.source = L"Registry - Hardware Description";
                outDetections.push_back(detection);
                found = true;
            }

            // ================================================================
            // 4. DISK ENUM FOR VM DISK IDENTIFIERS
            // ================================================================
            HKEY hDiskEnumKey;
            if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\Disk\\Enum", 0, KEY_READ, &hDiskEnumKey) == ERROR_SUCCESS) {
                wchar_t diskIdBuffer[512] = {};
                DWORD bufSize = sizeof(diskIdBuffer);
                DWORD type = REG_SZ;

                // Check disk 0
                if (RegQueryValueExW(hDiskEnumKey, L"0", nullptr, &type, reinterpret_cast<LPBYTE>(diskIdBuffer), &bufSize) == ERROR_SUCCESS) {
                    std::wstring diskId(diskIdBuffer);
                    const std::vector<std::pair<std::wstring, std::wstring>> vmDiskPatterns = {
                        {L"VBOX", L"VirtualBox"},
                        {L"VMWARE", L"VMware"},
                        {L"QEMU", L"QEMU"},
                        {L"VIRTUAL", L"Generic VM"},
                        {L"HARDDISK", L""},  // Not VM-specific, skip
                    };

                    for (const auto& [pattern, vendor] : vmDiskPatterns) {
                        if (!vendor.empty() && m_impl->ContainsSubstringCI(diskId, pattern)) {
                            EnvironmentDetectedTechnique detection(EnvironmentEvasionTechnique::HARDWARE_VMDiskVendor);
                            detection.confidence = 0.92;
                            detection.detectedValue = diskId;
                            detection.description = vendor + L" disk identifier detected";
                            detection.source = L"Registry - Disk Enum";
                            outDetections.push_back(detection);
                            found = true;
                            break;
                        }
                    }
                }
                RegCloseKey(hDiskEnumKey);
            }

            // ================================================================
            // 5. SCSI PORT DEVICE CHECKS
            // ================================================================
            const std::wstring scsiBasePath = L"HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0";
            std::wstring scsiIdentifier = m_impl->GetRegistryString(HKEY_LOCAL_MACHINE, scsiBasePath, L"Identifier");
            if (!scsiIdentifier.empty()) {
                const std::vector<std::pair<std::wstring, std::wstring>> vmScsiPatterns = {
                    {L"VBOX", L"VirtualBox"},
                    {L"VMWARE", L"VMware"},
                    {L"QEMU", L"QEMU"},
                    {L"VIRTUAL", L"Generic VM"},
                };

                for (const auto& [pattern, vendor] : vmScsiPatterns) {
                    if (m_impl->ContainsSubstringCI(scsiIdentifier, pattern)) {
                        EnvironmentDetectedTechnique detection(EnvironmentEvasionTechnique::REGISTRY_VMServices);
                        detection.confidence = 0.90;
                        detection.detectedValue = scsiIdentifier;
                        detection.description = vendor + L" SCSI device identifier detected";
                        detection.source = L"Registry - SCSI Device Map";
                        outDetections.push_back(detection);
                        found = true;
                        break;
                    }
                }
            }

            // ================================================================
            // 6. "LIVED-IN" REGISTRY ANALYSIS
            // ================================================================
            
            // Check MRU (Most Recently Used) lists
            HKEY hRecentDocsKey;
            if (RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs", 0, KEY_READ, &hRecentDocsKey) == ERROR_SUCCESS) {
                DWORD subKeyCount = 0;
                DWORD valueCount = 0;
                RegQueryInfoKeyW(hRecentDocsKey, nullptr, nullptr, nullptr, &subKeyCount, nullptr, nullptr, &valueCount, nullptr, nullptr, nullptr, nullptr);
                RegCloseKey(hRecentDocsKey);

                if (subKeyCount < 2 && valueCount < 5) {
                    EnvironmentDetectedTechnique detection(EnvironmentEvasionTechnique::REGISTRY_EmptyMRULists);
                    detection.confidence = 0.55;
                    detection.detectedValue = std::to_wstring(valueCount) + L" values, " + std::to_wstring(subKeyCount) + L" subkeys";
                    detection.expectedValue = L">= 10 values on normal system";
                    detection.description = L"Empty/Sparse RecentDocs MRU list (sandbox indicator)";
                    detection.source = L"Registry - User MRU";
                    outDetections.push_back(detection);
                    found = true;
                }
            }

            // Check ComDlg32 MRU (Open/Save dialog history)
            HKEY hComDlgKey;
            if (RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\OpenSavePidlMRU", 0, KEY_READ, &hComDlgKey) == ERROR_SUCCESS) {
                DWORD subKeyCount = 0;
                RegQueryInfoKeyW(hComDlgKey, nullptr, nullptr, nullptr, &subKeyCount, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr);
                RegCloseKey(hComDlgKey);

                if (subKeyCount < 3) {
                    EnvironmentDetectedTechnique detection(EnvironmentEvasionTechnique::REGISTRY_EmptyMRULists);
                    detection.confidence = 0.50;
                    detection.detectedValue = std::to_wstring(subKeyCount) + L" file type categories";
                    detection.expectedValue = L">= 5 on normal system";
                    detection.description = L"Empty Open/Save dialog history (sandbox indicator)";
                    detection.source = L"Registry - ComDlg32";
                    outDetections.push_back(detection);
                    found = true;
                }
            }

            // Check TypedURLs (Internet Explorer/Edge typed URLs)
            HKEY hTypedURLsKey;
            if (RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Internet Explorer\\TypedURLs", 0, KEY_READ, &hTypedURLsKey) == ERROR_SUCCESS) {
                DWORD valueCount = 0;
                RegQueryInfoKeyW(hTypedURLsKey, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, &valueCount, nullptr, nullptr, nullptr, nullptr);
                RegCloseKey(hTypedURLsKey);

                if (valueCount < 3) {
                    EnvironmentDetectedTechnique detection(EnvironmentEvasionTechnique::REGISTRY_NoTypedURLs);
                    detection.confidence = 0.45;
                    detection.detectedValue = std::to_wstring(valueCount) + L" typed URLs";
                    detection.description = L"Very few typed URLs (possible sandbox)";
                    detection.source = L"Registry - TypedURLs";
                    outDetections.push_back(detection);
                    found = true;
                }
            }

            // ================================================================
            // 7. INSTALLED SOFTWARE COUNT
            // ================================================================
            HKEY hUninstallKey;
            if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall", 0, KEY_READ, &hUninstallKey) == ERROR_SUCCESS) {
                DWORD subKeyCount = 0;
                RegQueryInfoKeyW(hUninstallKey, nullptr, nullptr, nullptr, &subKeyCount, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr);
                RegCloseKey(hUninstallKey);

                if (subKeyCount < 15) {
                    EnvironmentDetectedTechnique detection(EnvironmentEvasionTechnique::REGISTRY_MissingSoftwareKeys);
                    detection.confidence = 0.55;
                    detection.detectedValue = std::to_wstring(subKeyCount) + L" programs";
                    detection.expectedValue = L">= 30 on typical system";
                    detection.description = L"Very few installed programs (sandbox indicator)";
                    detection.source = L"Registry - Uninstall";
                    outDetections.push_back(detection);
                    found = true;
                }
            }

            // ================================================================
            // 8. NETWORK PROFILE HISTORY
            // ================================================================
            HKEY hNetworkProfiles;
            if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NetworkList\\Profiles", 0, KEY_READ, &hNetworkProfiles) == ERROR_SUCCESS) {
                DWORD subKeyCount = 0;
                RegQueryInfoKeyW(hNetworkProfiles, nullptr, nullptr, nullptr, &subKeyCount, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr);
                RegCloseKey(hNetworkProfiles);

                if (subKeyCount < 2) {
                    EnvironmentDetectedTechnique detection(EnvironmentEvasionTechnique::REGISTRY_MissingSoftwareKeys);
                    detection.confidence = 0.50;
                    detection.detectedValue = std::to_wstring(subKeyCount) + L" network profiles";
                    detection.expectedValue = L">= 3 on normal system";
                    detection.description = L"Very few network profile history (sandbox indicator)";
                    detection.source = L"Registry - NetworkList";
                    outDetections.push_back(detection);
                    found = true;
                }
            }

            return found;
        }
        catch (const std::exception& e) {
            SS_LOG_ERROR(L"EnvironmentEvasionDetector", L"CheckRegistryArtifacts failed: %hs", e.what());
            if (err) {
                err->win32Code = ERROR_INTERNAL_ERROR;
                err->message = L"Registry check failed";
            }
            return false;
        }
        catch (...) {
            if (err) {
                err->win32Code = ERROR_INTERNAL_ERROR;
                err->message = L"Unknown error in registry check";
            }
            return false;
        }
    }

    // ========================================================================
    // COMPREHENSIVE USER ACTIVITY CHECKS
    // Enterprise-grade analysis of user activity indicators
    // ========================================================================

    bool EnvironmentEvasionDetector::CheckUserActivity(
        UserActivityInfo& outActivityInfo,
        std::vector<EnvironmentDetectedTechnique>& outDetections,
        EnvironmentError* err
    ) noexcept {
        try {
            bool found = false;

            if (!outActivityInfo.valid) {
                m_impl->CollectUserActivityInfo(outActivityInfo);
            }

            // ================================================================
            // 1. OVERALL "LIVED-IN" SYSTEM CHECK
            // ================================================================
            if (!outActivityInfo.isLivedInSystem) {
                EnvironmentDetectedTechnique detection(EnvironmentEvasionTechnique::ACTIVITY_UserIdleDetection);
                detection.confidence = 0.60;
                detection.description = L"System lacks typical user activity artifacts";
                detection.technicalDetails = L"Desktop: " + std::to_wstring(outActivityInfo.desktopItemsCount) +
                    L", Documents: " + std::to_wstring(outActivityInfo.documentsCount) +
                    L", Downloads: " + std::to_wstring(outActivityInfo.downloadsCount) +
                    L", Recent: " + std::to_wstring(outActivityInfo.recentDocumentsCount);
                detection.source = L"User Activity Analysis";
                outDetections.push_back(detection);
                found = true;
            }

            // ================================================================
            // 2. MOUSE MOVEMENT DETECTION (Last Input Time)
            // ================================================================
            LASTINPUTINFO lii = {};
            lii.cbSize = sizeof(lii);
            if (GetLastInputInfo(&lii)) {
                const DWORD currentTick = GetTickCount();
                const DWORD idleTimeMs = currentTick - lii.dwTime;
                
                // If system has been idle for more than 10 minutes but uptime is high
                // This could indicate automated sandbox without user interaction
                if (idleTimeMs > 10 * 60 * 1000) {
                    EnvironmentDetectedTechnique detection(EnvironmentEvasionTechnique::ACTIVITY_NoMouseMovement);
                    detection.confidence = 0.40;
                    detection.detectedValue = std::to_wstring(idleTimeMs / 60000) + L" minutes idle";
                    detection.description = L"No recent user input detected";
                    detection.source = L"User Input Monitor";
                    outDetections.push_back(detection);
                    found = true;
                }
            }

            // ================================================================
            // 3. CURSOR POSITION CHECK (Static cursor = possible sandbox)
            // ================================================================
            POINT cursorPos1 = {};
            GetCursorPos(&cursorPos1);
            Sleep(50);  // Very brief wait
            POINT cursorPos2 = {};
            GetCursorPos(&cursorPos2);

            // If cursor hasn't moved at all and is at origin, possible headless/sandbox
            if (cursorPos1.x == cursorPos2.x && cursorPos1.y == cursorPos2.y &&
                cursorPos1.x == 0 && cursorPos1.y == 0) {
                EnvironmentDetectedTechnique detection(EnvironmentEvasionTechnique::ACTIVITY_NoMouseMovement);
                detection.confidence = 0.35;
                detection.detectedValue = L"Cursor at (0, 0)";
                detection.description = L"Cursor position at origin (possible headless environment)";
                detection.source = L"Cursor Monitor";
                outDetections.push_back(detection);
                found = true;
            }

            // ================================================================
            // 4. WINDOW COUNT CHECK (Very few windows = possible sandbox)
            // ================================================================
            struct WindowEnumData {
                size_t count = 0;
            } enumData;

            EnumWindows([](HWND hwnd, LPARAM lParam) -> BOOL {
                auto* data = reinterpret_cast<WindowEnumData*>(lParam);
                if (IsWindowVisible(hwnd)) {
                    data->count++;
                }
                return TRUE;
            }, reinterpret_cast<LPARAM>(&enumData));

            if (enumData.count < 5) {
                EnvironmentDetectedTechnique detection(EnvironmentEvasionTechnique::ACTIVITY_NoWindowFocus);
                detection.confidence = 0.45;
                detection.detectedValue = std::to_wstring(enumData.count) + L" visible windows";
                detection.expectedValue = L">= 10 on typical desktop";
                detection.description = L"Very few visible windows (possible automated sandbox)";
                detection.source = L"Window Enumeration";
                outDetections.push_back(detection);
                found = true;
            }

            // ================================================================
            // 5. CHECK CLIPBOARD HISTORY (Empty clipboard = possible sandbox)
            // ================================================================
            if (OpenClipboard(nullptr)) {
                UINT formatCount = CountClipboardFormats();
                CloseClipboard();

                if (formatCount == 0) {
                    EnvironmentDetectedTechnique detection(EnvironmentEvasionTechnique::ACTIVITY_NoClipboardHistory);
                    detection.confidence = 0.30;
                    detection.detectedValue = L"Empty clipboard";
                    detection.description = L"Empty clipboard (possible fresh sandbox)";
                    detection.source = L"Clipboard Check";
                    outDetections.push_back(detection);
                    found = true;
                }
            }

            // ================================================================
            // 6. CHECK WINDOWS EVENT LOG SIZE (Small log = fresh system)
            // ================================================================
            HANDLE hEventLog = OpenEventLogW(nullptr, L"Application");
            if (hEventLog) {
                DWORD numRecords = 0;
                if (GetNumberOfEventLogRecords(hEventLog, &numRecords)) {
                    if (numRecords < 100) {
                        EnvironmentDetectedTechnique detection(EnvironmentEvasionTechnique::ACTIVITY_UserIdleDetection);
                        detection.confidence = 0.50;
                        detection.detectedValue = std::to_wstring(numRecords) + L" events";
                        detection.expectedValue = L">= 500 on normal system";
                        detection.description = L"Very few events in Application log (fresh/sandbox system)";
                        detection.source = L"Event Log";
                        outDetections.push_back(detection);
                        found = true;
                    }
                }
                CloseEventLog(hEventLog);
            }

            return found;
        }
        catch (const std::exception& e) {
            SS_LOG_ERROR(L"EnvironmentEvasionDetector", L"CheckUserActivity failed: %hs", e.what());
            if (err) {
                err->win32Code = ERROR_INTERNAL_ERROR;
                err->message = L"User activity check failed";
            }
            return false;
        }
        catch (...) {
            if (err) {
                err->win32Code = ERROR_INTERNAL_ERROR;
                err->message = L"Unknown error in user activity check";
            }
            return false;
        }
    }

    // ========================================================================
    // COMPREHENSIVE NETWORK CONFIGURATION CHECKS
    // Enterprise-grade VM/Sandbox detection through network analysis
    // ========================================================================

    bool EnvironmentEvasionDetector::CheckNetworkConfiguration(
        NetworkConfigInfo& outNetworkInfo,
        std::vector<EnvironmentDetectedTechnique>& outDetections,
        EnvironmentError* err
    ) noexcept {
        try {
            bool found = false;

            if (!outNetworkInfo.valid) {
                m_impl->CollectNetworkInfo(outNetworkInfo);
            }

            if (!outNetworkInfo.valid) {
                return false;
            }

            // ================================================================
            // 1. VM MAC ADDRESS PREFIX DETECTION
            // ================================================================
            if (outNetworkInfo.vmAdapterCount > 0) {
                std::wstring vmAdapterDetails;
                for (const auto& adapter : outNetworkInfo.adapters) {
                    if (adapter.isVMAdapter) {
                        if (!vmAdapterDetails.empty()) vmAdapterDetails += L", ";
                        vmAdapterDetails += adapter.macAddressString;
                    }
                }

                EnvironmentDetectedTechnique detection(EnvironmentEvasionTechnique::NETWORK_VMMACPrefix);
                detection.confidence = 0.92;
                detection.detectedValue = std::to_wstring(outNetworkInfo.vmAdapterCount) + L" VM adapters";
                detection.technicalDetails = L"VM MACs: " + vmAdapterDetails;
                detection.description = L"VM network adapter MAC address prefix detected";
                detection.source = L"Network Adapters";
                outDetections.push_back(detection);
                found = true;
            }

            // ================================================================
            // 2. VM ADAPTER NAME DETECTION
            // ================================================================
            const std::vector<std::pair<std::wstring, std::wstring>> vmAdapterPatterns = {
                {L"vmware", L"VMware"},
                {L"virtualbox", L"VirtualBox"},
                {L"vbox", L"VirtualBox"},
                {L"hyper-v", L"Hyper-V"},
                {L"virtual", L"Generic VM"},
                {L"qemu", L"QEMU"},
                {L"xen", L"Xen"},
                {L"parallels", L"Parallels"},
                {L"virtio", L"QEMU/KVM VirtIO"},
            };

            for (const auto& adapter : outNetworkInfo.adapters) {
                for (const auto& [pattern, vendor] : vmAdapterPatterns) {
                    if (m_impl->ContainsSubstringCI(adapter.name, pattern) ||
                        m_impl->ContainsSubstringCI(adapter.description, pattern)) {
                        EnvironmentDetectedTechnique detection(EnvironmentEvasionTechnique::NETWORK_VMAdapterName);
                        detection.confidence = 0.88;
                        detection.detectedValue = adapter.description;
                        detection.description = vendor + L" network adapter name detected";
                        detection.source = L"Network Adapters";
                        outDetections.push_back(detection);
                        found = true;
                        break;  // Only report once per adapter
                    }
                }
            }

            // ================================================================
            // 3. NO WIFI ADAPTER CHECK (VMs typically don't have WiFi)
            // ================================================================
            if (!outNetworkInfo.hasWiFi && outNetworkInfo.adapterCount > 0) {
                EnvironmentDetectedTechnique detection(EnvironmentEvasionTechnique::NETWORK_NoWiFiHistory);
                detection.confidence = 0.40;
                detection.detectedValue = L"No WiFi adapter found";
                detection.description = L"No wireless adapter detected (common in VMs)";
                detection.source = L"Network Adapters";
                outDetections.push_back(detection);
                found = true;
            }

            // ================================================================
            // 4. ONLY LOOPBACK ADAPTER CHECK
            // ================================================================
            if (outNetworkInfo.adapterCount == 0) {
                EnvironmentDetectedTechnique detection(EnvironmentEvasionTechnique::NETWORK_OnlyLoopback);
                detection.confidence = 0.70;
                detection.detectedValue = L"Only loopback adapter";
                detection.description = L"Only loopback adapter found (isolated sandbox)";
                detection.source = L"Network Adapters";
                outDetections.push_back(detection);
                found = true;
            }

            // ================================================================
            // 5. SUSPICIOUS IP RANGE DETECTION
            // ================================================================
            for (const auto& adapter : outNetworkInfo.adapters) {
                // Check for common sandbox IP ranges
                if (adapter.ipAddress.starts_with(L"192.168.56.") ||  // VirtualBox default
                    adapter.ipAddress.starts_with(L"172.16.") ||       // VMware default
                    adapter.ipAddress.starts_with(L"10.0.2.")) {       // VirtualBox NAT
                    EnvironmentDetectedTechnique detection(EnvironmentEvasionTechnique::NETWORK_SuspiciousIPRange);
                    detection.confidence = 0.45;
                    detection.detectedValue = adapter.ipAddress;
                    detection.description = L"IP address in common VM/sandbox range";
                    detection.source = L"Network Configuration";
                    outDetections.push_back(detection);
                    found = true;
                }
            }

            // ================================================================
            // 6. DNS SERVER ANALYSIS
            // ================================================================
            FIXED_INFO* pFixedInfo = nullptr;
            ULONG ulOutBufLen = sizeof(FIXED_INFO);
            pFixedInfo = reinterpret_cast<FIXED_INFO*>(HeapAlloc(GetProcessHeap(), 0, ulOutBufLen));
            
            if (pFixedInfo) {
                if (GetNetworkParams(pFixedInfo, &ulOutBufLen) == ERROR_BUFFER_OVERFLOW) {
                    HeapFree(GetProcessHeap(), 0, pFixedInfo);
                    pFixedInfo = reinterpret_cast<FIXED_INFO*>(HeapAlloc(GetProcessHeap(), 0, ulOutBufLen));
                }

                if (pFixedInfo && GetNetworkParams(pFixedInfo, &ulOutBufLen) == NO_ERROR) {
                    std::string dnsServer = pFixedInfo->DnsServerList.IpAddress.String;
                    
                    // Check for suspicious DNS servers
                    if (dnsServer.empty() || dnsServer == "0.0.0.0" || dnsServer == "127.0.0.1") {
                        EnvironmentDetectedTechnique detection(EnvironmentEvasionTechnique::NETWORK_SuspiciousDNS);
                        detection.confidence = 0.50;
                        detection.detectedValue = Utils::StringUtils::ToWide(dnsServer.empty() ? "None" : dnsServer);
                        detection.description = L"Suspicious or missing DNS configuration";
                        detection.source = L"DNS Configuration";
                        outDetections.push_back(detection);
                        found = true;
                    }
                }

                if (pFixedInfo) {
                    HeapFree(GetProcessHeap(), 0, pFixedInfo);
                }
            }

            return found;
        }
        catch (const std::exception& e) {
            SS_LOG_ERROR(L"EnvironmentEvasionDetector", L"CheckNetworkConfiguration failed: %hs", e.what());
            if (err) {
                err->win32Code = ERROR_INTERNAL_ERROR;
                err->message = L"Network check failed";
            }
            return false;
        }
        catch (...) {
            if (err) {
                err->win32Code = ERROR_INTERNAL_ERROR;
                err->message = L"Unknown error in network check";
            }
            return false;
        }
    }

    // ========================================================================
    // COMPREHENSIVE RUNNING PROCESSES CHECKS
    // Enterprise-grade analysis tool and VM process detection
    // ========================================================================

    bool EnvironmentEvasionDetector::CheckRunningProcesses(
        std::vector<EnvironmentDetectedTechnique>& outDetections,
        EnvironmentError* err
    ) noexcept {
        try {
            bool found = false;
            size_t totalProcessCount = 0;
            std::vector<std::wstring> detectedAnalysisTools;
            std::vector<std::wstring> detectedVMTools;
            std::vector<std::wstring> detectedDebuggers;
            std::vector<std::wstring> detectedSandboxAgents;

            // Extended analysis tool process names
            const std::vector<std::pair<std::wstring, std::wstring>> analysisToolProcesses = {
                // Debuggers
                {L"ollydbg.exe", L"OllyDbg"},
                {L"x64dbg.exe", L"x64dbg"},
                {L"x32dbg.exe", L"x32dbg"},
                {L"windbg.exe", L"WinDbg"},
                {L"idaq.exe", L"IDA Pro"},
                {L"idaq64.exe", L"IDA Pro 64"},
                {L"radare2.exe", L"Radare2"},
                {L"immunity debugger.exe", L"Immunity Debugger"},
                {L"devenv.exe", L"Visual Studio"},

                // Network analyzers
                {L"wireshark.exe", L"Wireshark"},
                {L"fiddler.exe", L"Fiddler"},
                {L"charles.exe", L"Charles Proxy"},
                {L"burpsuite.exe", L"Burp Suite"},
                {L"tcpview.exe", L"TCPView"},
                {L"netstat.exe", L"Netstat"},  // Built-in but suspicious in context

                // Process monitors
                {L"procmon.exe", L"Process Monitor"},
                {L"procmon64.exe", L"Process Monitor 64"},
                {L"procexp.exe", L"Process Explorer"},
                {L"procexp64.exe", L"Process Explorer 64"},
                {L"autoruns.exe", L"Autoruns"},
                {L"autoruns64.exe", L"Autoruns 64"},

                // File monitors
                {L"regmon.exe", L"RegMon"},
                {L"filemon.exe", L"FileMon"},

                // PE analysis
                {L"pestudio.exe", L"PEStudio"},
                {L"die.exe", L"Detect It Easy"},
                {L"exeinfope.exe", L"ExeInfo PE"},
                {L"lordpe.exe", L"LordPE"},
                {L"peview.exe", L"PEView"},
                {L"cffexplorer.exe", L"CFF Explorer"},

                // Hex editors
                {L"hxd.exe", L"HxD"},
                {L"010editor.exe", L"010 Editor"},
                {L"hexworkshop.exe", L"Hex Workshop"},

                // API monitors
                {L"apimonitor.exe", L"API Monitor"},
                {L"rohitab.exe", L"API Monitor"},

                // Sandboxes
                {L"sandboxie.exe", L"Sandboxie"},
                {L"sbiectrl.exe", L"Sandboxie Control"},
                {L"sbielsvc.exe", L"Sandboxie Service"},

                // Virtual machine tools
                {L"vboxservice.exe", L"VirtualBox Service"},
                {L"vboxtray.exe", L"VirtualBox Tray"},
                {L"vmtoolsd.exe", L"VMware Tools"},
                {L"vmwaretray.exe", L"VMware Tray"},
                {L"vmwareuser.exe", L"VMware User"},
                {L"vgauthservice.exe", L"VMware Guest Auth"},
                {L"vm3dservice.exe", L"VMware 3D Service"},
                {L"prl_tools.exe", L"Parallels Tools"},
                {L"prl_cc.exe", L"Parallels Control"},
                {L"xenservice.exe", L"Xen Service"},
                {L"qemu-ga.exe", L"QEMU Guest Agent"},

                // AV sandbox agents
                {L"cuckoo.exe", L"Cuckoo Sandbox"},
                {L"python.exe", L"Python (common in sandboxes)"},  // Lower confidence
                {L"agent.exe", L"Generic Agent"},

                // System analysis
                {L"sysinternals.exe", L"Sysinternals"},
                {L"mmc.exe", L"Management Console"},  // Lower confidence
            };

            HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if (hSnapshot == INVALID_HANDLE_VALUE) {
                if (err) {
                    err->win32Code = GetLastError();
                    err->message = L"Failed to create process snapshot";
                }
                return false;
            }

            PROCESSENTRY32W pe = {};
            pe.dwSize = sizeof(pe);

            if (Process32FirstW(hSnapshot, &pe)) {
                do {
                    totalProcessCount++;
                    std::wstring processName(pe.szExeFile);
                    std::wstring processNameLower = processName;
                    std::transform(processNameLower.begin(), processNameLower.end(), processNameLower.begin(), ::towlower);

                    for (const auto& [toolName, toolDesc] : analysisToolProcesses) {
                        if (processNameLower == toolName) {
                            // Categorize the detection
                            if (toolDesc.find(L"VirtualBox") != std::wstring::npos ||
                                toolDesc.find(L"VMware") != std::wstring::npos ||
                                toolDesc.find(L"Parallels") != std::wstring::npos ||
                                toolDesc.find(L"Xen") != std::wstring::npos ||
                                toolDesc.find(L"QEMU") != std::wstring::npos) {
                                detectedVMTools.push_back(toolDesc);
                            }
                            else if (toolDesc.find(L"Dbg") != std::wstring::npos ||
                                     toolDesc.find(L"IDA") != std::wstring::npos ||
                                     toolDesc.find(L"Debugger") != std::wstring::npos ||
                                     toolDesc.find(L"Radare") != std::wstring::npos) {
                                detectedDebuggers.push_back(toolDesc);
                            }
                            else if (toolDesc.find(L"Sandbox") != std::wstring::npos ||
                                     toolDesc.find(L"Cuckoo") != std::wstring::npos) {
                                detectedSandboxAgents.push_back(toolDesc);
                            }
                            else {
                                detectedAnalysisTools.push_back(toolDesc);
                            }
                            break;
                        }
                    }

                    // Also check using the impl's built-in check
                    if (m_impl->IsAnalysisToolProcess(processName)) {
                        // Already handled above or add to general list
                    }

                } while (Process32NextW(hSnapshot, &pe));
            }

            CloseHandle(hSnapshot);

            // Generate detections based on findings
            if (!detectedVMTools.empty()) {
                EnvironmentDetectedTechnique detection(EnvironmentEvasionTechnique::PROCESS_VMToolsRunning);
                detection.confidence = 0.95;
                std::wstring tools;
                for (const auto& t : detectedVMTools) {
                    if (!tools.empty()) tools += L", ";
                    tools += t;
                }
                detection.detectedValue = tools;
                detection.description = L"VM Tools processes detected";
                detection.source = L"Process Enumeration";
                detection.severity = EnvironmentEvasionSeverity::High;
                outDetections.push_back(detection);
                found = true;
            }

            if (!detectedDebuggers.empty()) {
                EnvironmentDetectedTechnique detection(EnvironmentEvasionTechnique::PROCESS_DebuggerRunning);
                detection.confidence = 0.92;
                std::wstring tools;
                for (const auto& t : detectedDebuggers) {
                    if (!tools.empty()) tools += L", ";
                    tools += t;
                }
                detection.detectedValue = tools;
                detection.description = L"Debugger processes detected";
                detection.source = L"Process Enumeration";
                detection.severity = EnvironmentEvasionSeverity::High;
                outDetections.push_back(detection);
                found = true;
            }

            if (!detectedSandboxAgents.empty()) {
                EnvironmentDetectedTechnique detection(EnvironmentEvasionTechnique::PROCESS_SandboxAgentRunning);
                detection.confidence = 0.98;
                std::wstring tools;
                for (const auto& t : detectedSandboxAgents) {
                    if (!tools.empty()) tools += L", ";
                    tools += t;
                }
                detection.detectedValue = tools;
                detection.description = L"Sandbox agent processes detected";
                detection.source = L"Process Enumeration";
                detection.severity = EnvironmentEvasionSeverity::Critical;
                outDetections.push_back(detection);
                found = true;
            }

            if (!detectedAnalysisTools.empty()) {
                EnvironmentDetectedTechnique detection(EnvironmentEvasionTechnique::PROCESS_AnalysisToolRunning);
                detection.confidence = 0.88;
                std::wstring tools;
                for (const auto& t : detectedAnalysisTools) {
                    if (!tools.empty()) tools += L", ";
                    tools += t;
                }
                detection.detectedValue = tools;
                detection.description = L"Analysis tool processes detected";
                detection.source = L"Process Enumeration";
                outDetections.push_back(detection);
                found = true;
            }

            // Check for low process count (minimal sandbox)
            if (totalProcessCount < 30) {
                EnvironmentDetectedTechnique detection(EnvironmentEvasionTechnique::PROCESS_LowProcessCount);
                detection.confidence = 0.55;
                detection.detectedValue = std::to_wstring(totalProcessCount) + L" processes";
                detection.expectedValue = L">= 50 on typical Windows system";
                detection.description = L"Very low process count (minimal/sandbox system)";
                detection.source = L"Process Enumeration";
                outDetections.push_back(detection);
                found = true;
            }

            return found;
        }
        catch (const std::exception& e) {
            SS_LOG_ERROR(L"EnvironmentEvasionDetector", L"CheckRunningProcesses failed: %hs", e.what());
            if (err) {
                err->win32Code = ERROR_INTERNAL_ERROR;
                err->message = L"Process check failed";
            }
            return false;
        }
        catch (...) {
            if (err) {
                err->win32Code = ERROR_INTERNAL_ERROR;
                err->message = L"Unknown error in process check";
            }
            return false;
        }
    }

    // ========================================================================
    // COMPREHENSIVE TIMING INDICATOR CHECKS
    // Enterprise-grade timing-based sandbox/analysis detection
    // ========================================================================

    bool EnvironmentEvasionDetector::CheckTimingIndicators(
        std::vector<EnvironmentDetectedTechnique>& outDetections,
        EnvironmentError* err
    ) noexcept {
        try {
            bool found = false;

            if (!m_impl->m_cachedIdentityInfo || !m_impl->m_cachedIdentityInfo->valid) {
                return false;
            }

            const auto& identity = *m_impl->m_cachedIdentityInfo;

            // ================================================================
            // 1. SHORT SYSTEM UPTIME CHECK
            // ================================================================
            if (identity.uptimeMs < EnvironmentConstants::MAX_FRESH_BOOT_UPTIME_MS) {
                double confidenceAdjust = 0.0;
                // Shorter uptime = higher confidence it's a sandbox
                if (identity.uptimeMs < 5 * 60 * 1000) {  // Less than 5 minutes
                    confidenceAdjust = 0.3;
                }
                else if (identity.uptimeMs < 15 * 60 * 1000) {  // Less than 15 minutes
                    confidenceAdjust = 0.15;
                }

                EnvironmentDetectedTechnique detection(EnvironmentEvasionTechnique::TIMING_ShortUptime);
                detection.confidence = 0.60 + confidenceAdjust;
                detection.detectedValue = std::to_wstring(identity.uptimeMs / 60000) + L" minutes";
                detection.expectedValue = L"> 30 minutes on normal system";
                detection.description = L"Very short system uptime indicates fresh sandbox";
                detection.source = L"System Timing";
                outDetections.push_back(detection);
                found = true;
            }

            // ================================================================
            // 2. SYSTEM INSTALL DATE CHECK
            // ================================================================
            std::wstring installDateStr = m_impl->GetRegistryString(HKEY_LOCAL_MACHINE,
                L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", L"InstallDate");
            if (!installDateStr.empty()) {
                try {
                    // InstallDate is stored as a Unix timestamp (seconds since 1970)
                    uint64_t installTimestamp = std::stoull(installDateStr);
                    auto installTime = std::chrono::system_clock::from_time_t(static_cast<time_t>(installTimestamp));
                    auto now = std::chrono::system_clock::now();
                    auto systemAge = std::chrono::duration_cast<std::chrono::hours>(now - installTime).count();
                    
                    // If system is less than 24 hours old
                    if (systemAge < 24) {
                        EnvironmentDetectedTechnique detection(EnvironmentEvasionTechnique::TIMING_RecentInstall);
                        detection.confidence = 0.75;
                        detection.detectedValue = std::to_wstring(systemAge) + L" hours since install";
                        detection.expectedValue = L"> 7 days on normal system";
                        detection.description = L"Very recent Windows installation (sandbox indicator)";
                        detection.source = L"Install Timestamp";
                        outDetections.push_back(detection);
                        found = true;
                    }
                    else if (systemAge < 168) {  // Less than 7 days
                        EnvironmentDetectedTechnique detection(EnvironmentEvasionTechnique::TIMING_RecentInstall);
                        detection.confidence = 0.50;
                        detection.detectedValue = std::to_wstring(systemAge / 24) + L" days since install";
                        detection.expectedValue = L"> 30 days on typical system";
                        detection.description = L"Recent Windows installation";
                        detection.source = L"Install Timestamp";
                        outDetections.push_back(detection);
                        found = true;
                    }
                }
                catch (...) {
                    // Failed to parse install date, ignore
                }
            }

            // ================================================================
            // 3. TICK COUNT CONSISTENCY CHECK
            // ================================================================
            // Compare GetTickCount with system time to detect time manipulation
            ULONGLONG tick1 = GetTickCount64();
            Sleep(100);
            ULONGLONG tick2 = GetTickCount64();
            
            // Expected difference should be ~100ms
            ULONGLONG tickDiff = tick2 - tick1;
            if (tickDiff < 50 || tickDiff > 500) {  // Too fast or too slow
                EnvironmentDetectedTechnique detection(EnvironmentEvasionTechnique::TIMING_AcceleratedTime);
                detection.confidence = 0.70;
                detection.detectedValue = std::to_wstring(tickDiff) + L" ms (expected ~100ms)";
                detection.description = L"Time acceleration or manipulation detected";
                detection.source = L"Tick Count Analysis";
                outDetections.push_back(detection);
                found = true;
            }

            // ================================================================
            // 4. SCHEDULED TASKS COUNT
            // ================================================================
            // Few scheduled tasks = fresh system
            HKEY hTaskKey;
            if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tasks", 0, KEY_READ, &hTaskKey) == ERROR_SUCCESS) {
                DWORD taskCount = 0;
                RegQueryInfoKeyW(hTaskKey, nullptr, nullptr, nullptr, &taskCount, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr);
                RegCloseKey(hTaskKey);

                if (taskCount < 50) {
                    EnvironmentDetectedTechnique detection(EnvironmentEvasionTechnique::TIMING_NoScheduledTasks);
                    detection.confidence = 0.45;
                    detection.detectedValue = std::to_wstring(taskCount) + L" scheduled tasks";
                    detection.expectedValue = L">= 100 on typical system";
                    detection.description = L"Very few scheduled tasks (fresh/sandbox system)";
                    detection.source = L"Task Scheduler";
                    outDetections.push_back(detection);
                    found = true;
                }
            }

            // ================================================================
            // 5. SYSTEM RESTORE POINTS CHECK
            // ================================================================
            // No restore points = fresh system or snapshot-based VM
            // Check via shadow copies (vssadmin list shadows)
            // For now, check registry for System Protection settings
            HKEY hSysProtKey;
            if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SystemRestore", 0, KEY_READ, &hSysProtKey) == ERROR_SUCCESS) {
                DWORD rpSessionInterval = 0;
                DWORD dataSize = sizeof(rpSessionInterval);
                if (RegQueryValueExW(hSysProtKey, L"RPSessionInterval", nullptr, nullptr, reinterpret_cast<LPBYTE>(&rpSessionInterval), &dataSize) == ERROR_SUCCESS) {
                    // RPSessionInterval of 0 means disabled
                    if (rpSessionInterval == 0) {
                        EnvironmentDetectedTechnique detection(EnvironmentEvasionTechnique::TIMING_NoScheduledTasks);
                        detection.confidence = 0.40;
                        detection.detectedValue = L"System Restore disabled";
                        detection.description = L"System Restore is disabled (common in VMs)";
                        detection.source = L"System Restore";
                        outDetections.push_back(detection);
                        found = true;
                    }
                }
                RegCloseKey(hSysProtKey);
            }

            // ================================================================
            // 6. EVENT LOG TIMESTAMP ANALYSIS
            // ================================================================
            // Check if earliest event log entry is very recent
            HANDLE hEventLog = OpenEventLogW(nullptr, L"System");
            if (hEventLog) {
                DWORD oldestRecord = 0;
                DWORD numRecords = 0;
                if (GetOldestEventLogRecord(hEventLog, &oldestRecord) && 
                    GetNumberOfEventLogRecords(hEventLog, &numRecords)) {
                    
                    // If very few records, it's a fresh system
                    if (numRecords < 200) {
                        EnvironmentDetectedTechnique detection(EnvironmentEvasionTechnique::TIMING_EventLogCleared);
                        detection.confidence = 0.55;
                        detection.detectedValue = std::to_wstring(numRecords) + L" system events";
                        detection.expectedValue = L">= 1000 on normal system";
                        detection.description = L"Very few system events (fresh/sandbox system)";
                        detection.source = L"Event Log";
                        outDetections.push_back(detection);
                        found = true;
                    }
                }
                CloseEventLog(hEventLog);
            }

            // ================================================================
            // 7. BOOT TIME CONSISTENCY
            // ================================================================
            // Cross-check boot time from multiple sources
            // GetTickCount64 vs System time - install date
            auto expectedUptime = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::system_clock::now() - identity.lastBootTime).count();
            
            // If there's significant mismatch (>1 hour), something is off
            int64_t uptimeDiff = static_cast<int64_t>(identity.uptimeMs) - static_cast<int64_t>(expectedUptime);
            if (std::abs(uptimeDiff) > 3600000) {  // More than 1 hour difference
                EnvironmentDetectedTechnique detection(EnvironmentEvasionTechnique::TIMING_BootTimeAnomaly);
                detection.confidence = 0.60;
                detection.detectedValue = L"Uptime mismatch: " + std::to_wstring(uptimeDiff / 60000) + L" minutes";
                detection.description = L"Boot time inconsistency detected (possible snapshot restore)";
                detection.source = L"Boot Time Analysis";
                outDetections.push_back(detection);
                found = true;
            }

            return found;
        }
        catch (const std::exception& e) {
            SS_LOG_ERROR(L"EnvironmentEvasionDetector", L"CheckTimingIndicators failed: %hs", e.what());
            if (err) {
                err->win32Code = ERROR_INTERNAL_ERROR;
                err->message = L"Timing check failed";
            }
            return false;
        }
        catch (...) {
            if (err) {
                err->win32Code = ERROR_INTERNAL_ERROR;
                err->message = L"Unknown error in timing check";
            }
            return false;
        }
    }

    // ========================================================================
    // COMPREHENSIVE ENVIRONMENT VARIABLES CHECKS
    // Enterprise-grade sandbox/VM detection through environment analysis
    // ========================================================================

    bool EnvironmentEvasionDetector::CheckEnvironmentVariables(
        uint32_t processId,
        ProcessEnvironmentInfo& outEnvInfo,
        std::vector<EnvironmentDetectedTechnique>& outDetections,
        EnvironmentError* err
    ) noexcept {
        try {
            bool found = false;

            if (!outEnvInfo.valid) {
                m_impl->CollectProcessEnvironmentInfo(processId, outEnvInfo);
            }

            // ================================================================
            // 1. SANDBOX-SPECIFIC ENVIRONMENT VARIABLES
            // ================================================================
            for (const auto& var : outEnvInfo.suspiciousVariables) {
                EnvironmentDetectedTechnique detection(EnvironmentEvasionTechnique::ENV_SandboxVariable);
                detection.confidence = 0.92;
                detection.detectedValue = var;
                detection.description = L"Sandbox-specific environment variable detected";
                detection.source = L"Environment Variables";
                detection.severity = EnvironmentEvasionSeverity::Critical;
                outDetections.push_back(detection);
                found = true;
            }

            // ================================================================
            // 2. VM-SPECIFIC PATHS IN PATH VARIABLE
            // ================================================================
            auto pathIt = outEnvInfo.environmentVars.find(L"PATH");
            if (pathIt != outEnvInfo.environmentVars.end()) {
                const auto& pathValue = pathIt->second;
                
                const std::vector<std::pair<std::wstring, std::wstring>> vmPathPatterns = {
                    {L"vmware", L"VMware"},
                    {L"virtualbox", L"VirtualBox"},
                    {L"vbox", L"VirtualBox"},
                    {L"qemu", L"QEMU"},
                    {L"parallels", L"Parallels"},
                    {L"sandbox", L"Sandbox"},
                };

                for (const auto& [pattern, vendor] : vmPathPatterns) {
                    if (m_impl->ContainsSubstringCI(pathValue, pattern)) {
                        EnvironmentDetectedTechnique detection(EnvironmentEvasionTechnique::ENV_VMVariable);
                        detection.confidence = 0.80;
                        detection.detectedValue = vendor + L" path in PATH variable";
                        detection.description = L"VM-related path found in PATH environment variable";
                        detection.source = L"Environment Variables";
                        outDetections.push_back(detection);
                        found = true;
                        break;
                    }
                }
            }

            // ================================================================
            // 3. UNUSUAL TEMP PATH
            // ================================================================
            auto tempIt = outEnvInfo.environmentVars.find(L"TEMP");
            auto tmpIt = outEnvInfo.environmentVars.find(L"TMP");
            
            std::wstring tempPath;
            if (tempIt != outEnvInfo.environmentVars.end()) {
                tempPath = tempIt->second;
            }
            else if (tmpIt != outEnvInfo.environmentVars.end()) {
                tempPath = tmpIt->second;
            }

            if (!tempPath.empty()) {
                // Check for unusual temp locations
                if (!m_impl->ContainsSubstringCI(tempPath, L"AppData\\Local\\Temp") &&
                    !m_impl->ContainsSubstringCI(tempPath, L"Windows\\Temp")) {
                    EnvironmentDetectedTechnique detection(EnvironmentEvasionTechnique::ENV_UnusualTempPath);
                    detection.confidence = 0.50;
                    detection.detectedValue = tempPath;
                    detection.description = L"Unusual TEMP directory location";
                    detection.source = L"Environment Variables";
                    outDetections.push_back(detection);
                    found = true;
                }
            }

            // ================================================================
            // 4. MISSING COMMON ENVIRONMENT VARIABLES
            // ================================================================
            const std::vector<std::wstring> expectedVars = {
                L"COMPUTERNAME", L"USERNAME", L"USERPROFILE", L"TEMP",
                L"TMP", L"SYSTEMROOT", L"WINDIR", L"PATH", L"PATHEXT",
            };

            size_t missingCount = 0;
            std::wstring missingVars;
            for (const auto& expected : expectedVars) {
                if (outEnvInfo.environmentVars.find(expected) == outEnvInfo.environmentVars.end()) {
                    missingCount++;
                    if (!missingVars.empty()) missingVars += L", ";
                    missingVars += expected;
                }
            }

            if (missingCount > 2) {
                EnvironmentDetectedTechnique detection(EnvironmentEvasionTechnique::ENV_MissingVariables);
                detection.confidence = 0.60;
                detection.detectedValue = missingVars;
                detection.description = L"Missing expected environment variables";
                detection.source = L"Environment Variables";
                outDetections.push_back(detection);
                found = true;
            }

            // ================================================================
            // 5. ANALYSIS-RELATED ENVIRONMENT VARIABLES
            // ================================================================
            const std::vector<std::pair<std::wstring, std::wstring>> analysisVars = {
                {L"CUCKOO", L"Cuckoo Sandbox"},
                {L"MALWARE", L"Generic Analysis"},
                {L"SAMPLE", L"Generic Analysis"},
                {L"DEBUG", L"Debug Environment"},
                {L"ANALYSIS", L"Generic Analysis"},
                {L"SANDBOX", L"Generic Sandbox"},
                {L"HOOK", L"API Hooking"},
            };

            for (const auto& [var, name] : analysisVars) {
                for (const auto& [envName, envValue] : outEnvInfo.environmentVars) {
                    if (m_impl->ContainsSubstringCI(envName, var) ||
                        m_impl->ContainsSubstringCI(envValue, var)) {
                        EnvironmentDetectedTechnique detection(EnvironmentEvasionTechnique::ENV_AnalysisVariable);
                        detection.confidence = 0.85;
                        detection.detectedValue = envName + L"=" + envValue;
                        detection.description = name + L" environment variable detected";
                        detection.source = L"Environment Variables";
                        outDetections.push_back(detection);
                        found = true;
                        break;
                    }
                }
            }

            return found;
        }
        catch (const std::exception& e) {
            SS_LOG_ERROR(L"EnvironmentEvasionDetector", L"CheckEnvironmentVariables failed: %hs", e.what());
            if (err) {
                err->win32Code = ERROR_INTERNAL_ERROR;
                err->message = L"Environment variable check failed";
            }
            return false;
        }
        catch (...) {
            if (err) {
                err->win32Code = ERROR_INTERNAL_ERROR;
                err->message = L"Unknown error in environment check";
            }
            return false;
        }
    }

    // ========================================================================
    // COMPREHENSIVE DISPLAY CONFIGURATION CHECKS
    // Enterprise-grade VM detection through display analysis
    // ========================================================================

    bool EnvironmentEvasionDetector::CheckDisplayConfiguration(
        std::vector<EnvironmentDetectedTechnique>& outDetections,
        EnvironmentError* err
    ) noexcept {
        try {
            bool found = false;
            std::shared_lock lock(m_impl->m_mutex);

            if (!m_impl->m_cachedHardwareInfo || !m_impl->m_cachedHardwareInfo->valid) {
                return false;
            }

            const auto& hw = *m_impl->m_cachedHardwareInfo;

            // ================================================================
            // 1. LOW RESOLUTION CHECK
            // ================================================================
            if (hw.screenWidth < 1024 || hw.screenHeight < 768) {
                EnvironmentDetectedTechnique detection(EnvironmentEvasionTechnique::DISPLAY_LowResolution);
                detection.confidence = 0.65;
                detection.detectedValue = std::to_wstring(hw.screenWidth) + L"x" + std::to_wstring(hw.screenHeight);
                detection.expectedValue = L">= 1024x768";
                detection.description = L"Low screen resolution typical of headless/automated VMs";
                detection.source = L"Display Configuration";
                outDetections.push_back(detection);
                found = true;
            }

            // ================================================================
            // 2. MONITOR COUNT CHECK
            // ================================================================
            if (hw.monitorCount < 1) {
                EnvironmentDetectedTechnique detection(EnvironmentEvasionTechnique::DISPLAY_SingleMonitor);
                detection.confidence = 0.80;
                detection.detectedValue = std::to_wstring(hw.monitorCount);
                detection.description = L"No monitors detected (headless environment)";
                detection.source = L"Display Configuration";
                outDetections.push_back(detection);
                found = true;
            }

            // ================================================================
            // 3. VM DISPLAY DRIVER CHECK
            // ================================================================
            // Check for VM display adapters via EnumDisplayDevices
            DISPLAY_DEVICEW displayDevice = {};
            displayDevice.cb = sizeof(displayDevice);
            
            const std::vector<std::pair<std::wstring, std::wstring>> vmDisplayPatterns = {
                {L"vmware", L"VMware"},
                {L"virtualbox", L"VirtualBox"},
                {L"vbox", L"VirtualBox"},
                {L"qxl", L"QEMU/SPICE"},
                {L"hyper-v", L"Hyper-V"},
                {L"microsoft basic display", L"Generic VM/Headless"},
                {L"microsoft hyper-v", L"Hyper-V"},
                {L"red hat", L"QEMU/KVM"},
                {L"cirrus", L"QEMU/Cirrus"},
                {L"parallels", L"Parallels"},
            };

            for (DWORD i = 0; EnumDisplayDevicesW(nullptr, i, &displayDevice, 0); i++) {
                std::wstring deviceString(displayDevice.DeviceString);
                std::wstring deviceName(displayDevice.DeviceName);
                
                for (const auto& [pattern, vendor] : vmDisplayPatterns) {
                    if (m_impl->ContainsSubstringCI(deviceString, pattern) ||
                        m_impl->ContainsSubstringCI(deviceName, pattern)) {
                        EnvironmentDetectedTechnique detection(EnvironmentEvasionTechnique::DISPLAY_VMDriver);
                        detection.confidence = 0.90;
                        detection.detectedValue = deviceString;
                        detection.description = vendor + L" display driver detected";
                        detection.source = L"Display Device Enumeration";
                        outDetections.push_back(detection);
                        found = true;
                        break;
                    }
                }
            }

            // ================================================================
            // 4. COLOR DEPTH CHECK
            // ================================================================
            HDC hdc = GetDC(nullptr);
            if (hdc) {
                int colorDepth = GetDeviceCaps(hdc, BITSPIXEL);
                int planes = GetDeviceCaps(hdc, PLANES);
                int totalBits = colorDepth * planes;
                ReleaseDC(nullptr, hdc);

                if (totalBits < 16) {
                    EnvironmentDetectedTechnique detection(EnvironmentEvasionTechnique::DISPLAY_UnusualColorDepth);
                    detection.confidence = 0.55;
                    detection.detectedValue = std::to_wstring(totalBits) + L" bit color";
                    detection.expectedValue = L">= 24 bit on modern systems";
                    detection.description = L"Low color depth (possible headless/VM)";
                    detection.source = L"Display Configuration";
                    outDetections.push_back(detection);
                    found = true;
                }
            }

            // ================================================================
            // 5. GRAPHICS ADAPTER REGISTRY CHECK
            // ================================================================
            HKEY hVideoKey;
            if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"HARDWARE\\DEVICEMAP\\VIDEO", 0, KEY_READ, &hVideoKey) == ERROR_SUCCESS) {
                wchar_t valueData[512] = {};
                DWORD dataSize = sizeof(valueData);
                DWORD type = REG_SZ;
                
                if (RegQueryValueExW(hVideoKey, L"\\Device\\Video0", nullptr, &type, 
                    reinterpret_cast<LPBYTE>(valueData), &dataSize) == ERROR_SUCCESS) {
                    std::wstring videoPath(valueData);
                    
                    for (const auto& [pattern, vendor] : vmDisplayPatterns) {
                        if (m_impl->ContainsSubstringCI(videoPath, pattern)) {
                            EnvironmentDetectedTechnique detection(EnvironmentEvasionTechnique::DISPLAY_VMGraphicsAdapter);
                            detection.confidence = 0.85;
                            detection.detectedValue = videoPath;
                            detection.description = vendor + L" graphics adapter in registry";
                            detection.source = L"Registry - Video Device Map";
                            outDetections.push_back(detection);
                            found = true;
                            break;
                        }
                    }
                }
                RegCloseKey(hVideoKey);
            }

            return found;
        }
        catch (const std::exception& e) {
            SS_LOG_ERROR(L"EnvironmentEvasionDetector", L"CheckDisplayConfiguration failed: %hs", e.what());
            if (err) {
                err->win32Code = ERROR_INTERNAL_ERROR;
                err->message = L"Display configuration check failed";
            }
            return false;
        }
        catch (...) {
            if (err) {
                err->win32Code = ERROR_INTERNAL_ERROR;
                err->message = L"Unknown error in display check";
            }
            return false;
        }
    }

    // ========================================================================
    // COMPREHENSIVE BROWSER ARTIFACTS CHECKS
    // Enterprise-grade "lived-in" system detection through browser analysis
    // ========================================================================

    bool EnvironmentEvasionDetector::CheckBrowserArtifacts(
        std::vector<EnvironmentDetectedTechnique>& outDetections,
        EnvironmentError* err
    ) noexcept {
        try {
            bool found = false;
            bool anyBrowserFound = false;

            auto expandPath = [](const wchar_t* path) -> std::wstring {
                wchar_t expanded[MAX_PATH];
                ExpandEnvironmentStringsW(path, expanded, MAX_PATH);
                return expanded;
            };

            // ================================================================
            // 1. CHROME BROWSER CHECK
            // ================================================================
            std::wstring chromePath = expandPath(L"%LOCALAPPDATA%\\Google\\Chrome\\User Data\\Default");
            if (fs::exists(chromePath)) {
                anyBrowserFound = true;
                
                // Check for history
                if (!fs::exists(chromePath + L"\\History")) {
                    EnvironmentDetectedTechnique detection(EnvironmentEvasionTechnique::BROWSER_NoHistory);
                    detection.confidence = 0.45;
                    detection.detectedValue = L"Chrome - No History file";
                    detection.description = L"Chrome installed but no browsing history";
                    detection.source = L"Browser Artifacts";
                    outDetections.push_back(detection);
                    found = true;
                }

                // Check for bookmarks
                if (!fs::exists(chromePath + L"\\Bookmarks")) {
                    EnvironmentDetectedTechnique detection(EnvironmentEvasionTechnique::BROWSER_NoBookmarks);
                    detection.confidence = 0.35;
                    detection.detectedValue = L"Chrome - No Bookmarks";
                    detection.description = L"Chrome installed but no bookmarks";
                    detection.source = L"Browser Artifacts";
                    outDetections.push_back(detection);
                    found = true;
                }

                // Check for cookies
                if (!fs::exists(chromePath + L"\\Network\\Cookies")) {
                    EnvironmentDetectedTechnique detection(EnvironmentEvasionTechnique::BROWSER_NoCookies);
                    detection.confidence = 0.40;
                    detection.detectedValue = L"Chrome - No Cookies";
                    detection.description = L"Chrome installed but no cookies";
                    detection.source = L"Browser Artifacts";
                    outDetections.push_back(detection);
                    found = true;
                }

                // Check for extensions
                std::wstring extensionsPath = chromePath + L"\\Extensions";
                if (fs::exists(extensionsPath) && fs::is_directory(extensionsPath)) {
                    size_t extCount = 0;
                    try {
                        for (const auto& entry : fs::directory_iterator(extensionsPath)) {
                            if (entry.is_directory()) extCount++;
                            if (extCount > 3) break;
                        }
                    }
                    catch (...) {}

                    if (extCount < 2) {
                        EnvironmentDetectedTechnique detection(EnvironmentEvasionTechnique::BROWSER_NoExtensions);
                        detection.confidence = 0.35;
                        detection.detectedValue = std::to_wstring(extCount) + L" Chrome extensions";
                        detection.expectedValue = L">= 3 on typical system";
                        detection.description = L"Very few Chrome extensions";
                        detection.source = L"Browser Artifacts";
                        outDetections.push_back(detection);
                        found = true;
                    }
                }
            }

            // ================================================================
            // 2. EDGE BROWSER CHECK
            // ================================================================
            std::wstring edgePath = expandPath(L"%LOCALAPPDATA%\\Microsoft\\Edge\\User Data\\Default");
            if (fs::exists(edgePath)) {
                anyBrowserFound = true;
                
                if (!fs::exists(edgePath + L"\\History")) {
                    EnvironmentDetectedTechnique detection(EnvironmentEvasionTechnique::BROWSER_NoHistory);
                    detection.confidence = 0.40;
                    detection.detectedValue = L"Edge - No History file";
                    detection.description = L"Edge installed but no browsing history";
                    detection.source = L"Browser Artifacts";
                    outDetections.push_back(detection);
                    found = true;
                }
            }

            // ================================================================
            // 3. FIREFOX BROWSER CHECK
            // ================================================================
            std::wstring firefoxPath = expandPath(L"%APPDATA%\\Mozilla\\Firefox\\Profiles");
            if (fs::exists(firefoxPath) && fs::is_directory(firefoxPath)) {
                anyBrowserFound = true;
                
                // Count profiles
                size_t profileCount = 0;
                bool foundPlaces = false;
                try {
                    for (const auto& entry : fs::directory_iterator(firefoxPath)) {
                        if (entry.is_directory() && entry.path().filename().string().find(".default") != std::string::npos) {
                            profileCount++;
                            if (fs::exists(entry.path() / L"places.sqlite")) {
                                foundPlaces = true;
                            }
                        }
                    }
                }
                catch (...) {}

                if (profileCount > 0 && !foundPlaces) {
                    EnvironmentDetectedTechnique detection(EnvironmentEvasionTechnique::BROWSER_NoHistory);
                    detection.confidence = 0.45;
                    detection.detectedValue = L"Firefox - No places.sqlite";
                    detection.description = L"Firefox installed but no history database";
                    detection.source = L"Browser Artifacts";
                    outDetections.push_back(detection);
                    found = true;
                }
            }

            // ================================================================
            // 4. NO BROWSERS AT ALL CHECK
            // ================================================================
            if (!anyBrowserFound) {
                EnvironmentDetectedTechnique detection(EnvironmentEvasionTechnique::BROWSER_OnlyDefault);
                detection.confidence = 0.55;
                detection.detectedValue = L"No major browser profiles found";
                detection.description = L"No Chrome, Edge, or Firefox user data found";
                detection.source = L"Browser Artifacts";
                outDetections.push_back(detection);
                found = true;
            }

            return found;
        }
        catch (const std::exception& e) {
            SS_LOG_ERROR(L"EnvironmentEvasionDetector", L"CheckBrowserArtifacts failed: %hs", e.what());
            if (err) {
                err->win32Code = ERROR_INTERNAL_ERROR;
                err->message = L"Browser artifact check failed";
            }
            return false;
        }
        catch (...) {
            if (err) {
                err->win32Code = ERROR_INTERNAL_ERROR;
                err->message = L"Unknown error in browser check";
            }
            return false;
        }
    }

    // ========================================================================
    // COMPREHENSIVE PERIPHERAL HISTORY CHECKS
    // Enterprise-grade device history analysis
    // ========================================================================

    bool EnvironmentEvasionDetector::CheckPeripheralHistory(
        std::vector<EnvironmentDetectedTechnique>& outDetections,
        EnvironmentError* err
    ) noexcept {
        try {
            bool found = false;

            // ================================================================
            // 1. USB STORAGE DEVICE HISTORY
            // ================================================================
            HKEY hUsbStorKey;
            if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Enum\\USBSTOR", 0, KEY_READ, &hUsbStorKey) == ERROR_SUCCESS) {
                DWORD subKeyCount = 0;
                RegQueryInfoKeyW(hUsbStorKey, nullptr, nullptr, nullptr, &subKeyCount, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr);
                RegCloseKey(hUsbStorKey);

                if (subKeyCount < 1) {
                    EnvironmentDetectedTechnique detection(EnvironmentEvasionTechnique::PERIPHERAL_NoUSBHistory);
                    detection.confidence = 0.70;
                    detection.detectedValue = L"0 USB storage devices";
                    detection.expectedValue = L">= 3 on typical system";
                    detection.description = L"No USB storage device history found";
                    detection.source = L"Peripheral History";
                    outDetections.push_back(detection);
                    found = true;
                }
            }

            // ================================================================
            // 2. BLUETOOTH DEVICE HISTORY
            // ================================================================
            HKEY hBluetoothKey;
            if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\BTHPORT\\Parameters\\Devices", 0, KEY_READ, &hBluetoothKey) == ERROR_SUCCESS) {
                DWORD subKeyCount = 0;
                RegQueryInfoKeyW(hBluetoothKey, nullptr, nullptr, nullptr, &subKeyCount, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr);
                RegCloseKey(hBluetoothKey);

                if (subKeyCount < 1) {
                    EnvironmentDetectedTechnique detection(EnvironmentEvasionTechnique::PERIPHERAL_NoBluetoothPairings);
                    detection.confidence = 0.40;
                    detection.detectedValue = L"0 paired Bluetooth devices";
                    detection.description = L"No Bluetooth device pairing history";
                    detection.source = L"Peripheral History";
                    outDetections.push_back(detection);
                    found = true;
                }
            }

            // ================================================================
            // 3. PRINTER HISTORY
            // ================================================================
            HKEY hPrintersKey;
            if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Print\\Printers", 0, KEY_READ, &hPrintersKey) == ERROR_SUCCESS) {
                DWORD subKeyCount = 0;
                RegQueryInfoKeyW(hPrintersKey, nullptr, nullptr, nullptr, &subKeyCount, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr);
                RegCloseKey(hPrintersKey);

                if (subKeyCount < 1) {
                    EnvironmentDetectedTechnique detection(EnvironmentEvasionTechnique::PERIPHERAL_NoPrinters);
                    detection.confidence = 0.45;
                    detection.detectedValue = L"0 printers installed";
                    detection.description = L"No printers have ever been installed";
                    detection.source = L"Peripheral History";
                    outDetections.push_back(detection);
                    found = true;
                }
            }

            // ================================================================
            // 4. AUDIO DEVICE CHECK
            // ================================================================
            HKEY hAudioKey;
            if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Class\\{4d36e96c-e325-11ce-bfc1-08002be10318}", 0, KEY_READ, &hAudioKey) == ERROR_SUCCESS) {
                DWORD subKeyCount = 0;
                RegQueryInfoKeyW(hAudioKey, nullptr, nullptr, nullptr, &subKeyCount, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr);
                RegCloseKey(hAudioKey);

                if (subKeyCount < 2) {  // Usually at least default audio device
                    EnvironmentDetectedTechnique detection(EnvironmentEvasionTechnique::PERIPHERAL_NoAudioDevices);
                    detection.confidence = 0.50;
                    detection.detectedValue = std::to_wstring(subKeyCount) + L" audio devices";
                    detection.description = L"No or minimal audio devices found";
                    detection.source = L"Peripheral History";
                    outDetections.push_back(detection);
                    found = true;
                }
            }

            // ================================================================
            // 5. WEBCAM CHECK
            // ================================================================
            HKEY hCameraKey;
            if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Class\\{ca3e7ab9-b4c3-4ae6-8251-579ef933890f}", 0, KEY_READ, &hCameraKey) == ERROR_SUCCESS) {
                DWORD subKeyCount = 0;
                RegQueryInfoKeyW(hCameraKey, nullptr, nullptr, nullptr, &subKeyCount, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr);
                RegCloseKey(hCameraKey);

                if (subKeyCount < 1) {
                    EnvironmentDetectedTechnique detection(EnvironmentEvasionTechnique::PERIPHERAL_NoWebcam);
                    detection.confidence = 0.35;
                    detection.detectedValue = L"No camera devices";
                    detection.description = L"No webcam or camera detected";
                    detection.source = L"Peripheral History";
                    outDetections.push_back(detection);
                    found = true;
                }
            }

            return found;
        }
        catch (const std::exception& e) {
            SS_LOG_ERROR(L"EnvironmentEvasionDetector", L"CheckPeripheralHistory failed: %hs", e.what());
            if (err) {
                err->win32Code = ERROR_INTERNAL_ERROR;
                err->message = L"Peripheral history check failed";
            }
            return false;
        }
        catch (...) {
            if (err) {
                err->win32Code = ERROR_INTERNAL_ERROR;
                err->message = L"Unknown error in peripheral check";
            }
            return false;
        }
    }

    // ========================================================================
    // COMPREHENSIVE FILE NAMING CHECKS
    // Enterprise-grade analysis of file naming patterns
    // ========================================================================

    bool EnvironmentEvasionDetector::CheckFileNaming(
        uint32_t processId,
        FileNamingInfo& outNamingInfo,
        std::vector<EnvironmentDetectedTechnique>& outDetections,
        EnvironmentError* err
    ) noexcept {
        try {
            bool found = false;

            if (!outNamingInfo.valid) {
                ProcessEnvironmentInfo pEnv;
                m_impl->CollectProcessEnvironmentInfo(processId, pEnv);
                if (pEnv.valid && !pEnv.executablePath.empty()) {
                    m_impl->AnalyzeFileNaming(pEnv.executablePath, outNamingInfo);
                }
                else {
                    return false;
                }
            }

            // ================================================================
            // 1. HASH-BASED FILENAME CHECK
            // ================================================================
            if (outNamingInfo.isMD5) {
                EnvironmentDetectedTechnique detection(EnvironmentEvasionTechnique::FILENAME_MD5Hash);
                detection.confidence = 0.85;
                detection.detectedValue = outNamingInfo.fileName;
                detection.description = L"Filename is an MD5 hash (common in malware analysis)";
                detection.source = L"File Naming Analysis";
                detection.severity = EnvironmentEvasionSeverity::High;
                outDetections.push_back(detection);
                found = true;
            }
            else if (outNamingInfo.isSHA1) {
                EnvironmentDetectedTechnique detection(EnvironmentEvasionTechnique::FILENAME_SHA1Hash);
                detection.confidence = 0.85;
                detection.detectedValue = outNamingInfo.fileName;
                detection.description = L"Filename is a SHA1 hash (common in malware analysis)";
                detection.source = L"File Naming Analysis";
                detection.severity = EnvironmentEvasionSeverity::High;
                outDetections.push_back(detection);
                found = true;
            }
            else if (outNamingInfo.isSHA256) {
                EnvironmentDetectedTechnique detection(EnvironmentEvasionTechnique::FILENAME_SHA256Hash);
                detection.confidence = 0.90;
                detection.detectedValue = outNamingInfo.fileName;
                detection.description = L"Filename is a SHA256 hash (common in malware analysis)";
                detection.source = L"File Naming Analysis";
                detection.severity = EnvironmentEvasionSeverity::High;
                outDetections.push_back(detection);
                found = true;
            }

            // ================================================================
            // 2. GENERIC FILENAME CHECK
            // ================================================================
            if (outNamingInfo.isGeneric) {
                EnvironmentDetectedTechnique detection(EnvironmentEvasionTechnique::FILENAME_Generic);
                detection.confidence = 0.65;
                detection.detectedValue = outNamingInfo.baseName;
                detection.description = L"Generic filename detected (sample, malware, test, etc.)";
                detection.source = L"File Naming Analysis";
                outDetections.push_back(detection);
                found = true;
            }

            // ================================================================
            // 3. SUSPICIOUS LOCATION CHECK
            // ================================================================
            if (outNamingInfo.inSuspiciousLocation) {
                EnvironmentDetectedTechnique detection(EnvironmentEvasionTechnique::FILENAME_SuspiciousLocation);
                detection.confidence = 0.55;
                detection.detectedValue = outNamingInfo.directoryPath;
                detection.description = L"File located in suspicious directory";
                detection.source = L"File Naming Analysis";
                outDetections.push_back(detection);
                found = true;
            }

            // ================================================================
            // 4. ANALYSIS KEYWORDS IN PATH CHECK
            // ================================================================
            if (outNamingInfo.containsAnalysisKeywords) {
                EnvironmentDetectedTechnique detection(EnvironmentEvasionTechnique::FILENAME_AnalysisKeywords);
                detection.confidence = 0.70;
                detection.detectedValue = outNamingInfo.executablePath;
                detection.description = L"Analysis-related keywords found in path";
                detection.source = L"File Naming Analysis";
                outDetections.push_back(detection);
                found = true;
            }

            // ================================================================
            // 5. MULTIPLE EXTENSIONS CHECK
            // ================================================================
            if (outNamingInfo.hasMultipleExtensions) {
                EnvironmentDetectedTechnique detection(EnvironmentEvasionTechnique::FILENAME_MultipleExtensions);
                detection.confidence = 0.75;
                detection.detectedValue = outNamingInfo.fileName;
                detection.description = L"File has multiple extensions (possible extension spoofing)";
                detection.source = L"File Naming Analysis";
                detection.severity = EnvironmentEvasionSeverity::Medium;
                outDetections.push_back(detection);
                found = true;
            }

            // ================================================================
            // 6. RANDOM FILENAME PATTERN CHECK
            // ================================================================
            if (outNamingInfo.isRandomPattern) {
                EnvironmentDetectedTechnique detection(EnvironmentEvasionTechnique::FILENAME_RandomPattern);
                detection.confidence = 0.50;
                detection.detectedValue = outNamingInfo.baseName;
                detection.description = L"Filename appears randomly generated";
                detection.source = L"File Naming Analysis";
                outDetections.push_back(detection);
                found = true;
            }

            return found;
        }
        catch (const std::exception& e) {
            SS_LOG_ERROR(L"EnvironmentEvasionDetector", L"CheckFileNaming failed: %hs", e.what());
            if (err) {
                err->win32Code = ERROR_INTERNAL_ERROR;
                err->message = L"File naming check failed";
            }
            return false;
        }
        catch (...) {
            if (err) {
                err->win32Code = ERROR_INTERNAL_ERROR;
                err->message = L"Unknown error in file naming check";
            }
            return false;
        }
    }

    bool EnvironmentEvasionDetector::DetectFileNameHashMatch(
        std::wstring_view filePath,
        std::vector<EnvironmentDetectedTechnique>& outDetections,
        EnvironmentError* err
    ) noexcept {
        try {
            if (!fs::exists(filePath)) return false;

            // Calculate file hash
            std::vector<uint8_t> fileHashVector;
            Utils::HashUtils::Error hashErr; // Define an error object for hash calculation
            if (!Utils::HashUtils::ComputeFile(Utils::HashUtils::Algorithm::SHA256, filePath, fileHashVector, &hashErr)) {
                SS_LOG_ERROR(L"EnvironmentEvasionDetector", L"DetectFileNameHashMatch: Failed to compute file hash");
                return false; // Failed to compute hash
            }

            // Convert the binary hash to a lowercase hexadecimal string
            std::string fileHashHexStr = Utils::HashUtils::ToHexLower(fileHashVector);
            // Convert the hexadecimal string to a wide string for comparison
            std::wstring fileHashWideStr = ShadowStrike::Utils::StringUtils::ToWide(fileHashHexStr);

            // Get filename without extension
            fs::path p(filePath);
            std::wstring stem = p.stem().wstring();

            // Simple case-insensitive compare
            if (m_impl->ContainsSubstringCI(stem, fileHashWideStr)) {
                EnvironmentDetectedTechnique detection(EnvironmentEvasionTechnique::FILENAME_SHA256Hash);
                detection.confidence = 1.0;
                detection.detectedValue = stem;
                detection.expectedValue = fileHashWideStr;
                detection.description = L"Filename matches file content SHA256 hash";
                outDetections.push_back(detection);
                return true;
            }

            return false;
        }
        catch (...) {
            return false;
        }
    }

    // ========================================================================
    // BATCH ANALYSIS
    // ========================================================================

    EnvironmentBatchResult EnvironmentEvasionDetector::AnalyzeProcesses(
        const std::vector<uint32_t>& processIds,
        const EnvironmentAnalysisConfig& config,
        EnvironmentProgressCallback progressCallback,
        EnvironmentError* err
    ) noexcept {
        EnvironmentBatchResult batchResult;
        batchResult.startTime = std::chrono::system_clock::now();
        batchResult.totalProcesses = static_cast<uint32_t>(processIds.size());

        for (const auto pid : processIds) {
            auto result = AnalyzeProcess(pid, config, err);

            if (result.analysisComplete) {
                batchResult.results.push_back(std::move(result));

                if (result.isEvasive) {
                    batchResult.evasiveProcesses++;
                }
            }
            else {
                batchResult.failedProcesses++;
            }
        }

        batchResult.endTime = std::chrono::system_clock::now();
        batchResult.totalDurationMs = std::chrono::duration_cast<std::chrono::milliseconds>(
            batchResult.endTime - batchResult.startTime).count();

        return batchResult;
    }

    EnvironmentBatchResult EnvironmentEvasionDetector::AnalyzeAllProcesses(
        const EnvironmentAnalysisConfig& config,
        EnvironmentProgressCallback progressCallback,
        EnvironmentError* err
    ) noexcept {
        // Enumerate all processes and analyze them
        std::vector<uint32_t> allPids;

        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot != INVALID_HANDLE_VALUE) {
            PROCESSENTRY32W pe = {};
            pe.dwSize = sizeof(pe);

            if (Process32FirstW(hSnapshot, &pe)) {
                do {
                    allPids.push_back(pe.th32ProcessID);
                } while (Process32NextW(hSnapshot, &pe));
            }

            CloseHandle(hSnapshot);
        }

        return AnalyzeProcesses(allPids, config, progressCallback, err);
    }

    // ========================================================================
    // CALLBACK MANAGEMENT
    // ========================================================================

    void EnvironmentEvasionDetector::SetDetectionCallback(EnvironmentDetectionCallback callback) noexcept {
        std::unique_lock lock(m_impl->m_mutex);
        m_impl->m_detectionCallback = std::move(callback);
    }

    void EnvironmentEvasionDetector::ClearDetectionCallback() noexcept {
        std::unique_lock lock(m_impl->m_mutex);
        m_impl->m_detectionCallback = nullptr;
    }

    // ========================================================================
    // CACHE MANAGEMENT
    // ========================================================================

    std::optional<EnvironmentEvasionResult> EnvironmentEvasionDetector::GetCachedResult(uint32_t processId) const noexcept {
        std::shared_lock lock(m_impl->m_mutex);

        auto it = m_impl->m_resultCache.find(processId);
        if (it != m_impl->m_resultCache.end()) {
            return it->second.result;
        }

        return std::nullopt;
    }

    void EnvironmentEvasionDetector::InvalidateCache(uint32_t processId) noexcept {
        std::unique_lock lock(m_impl->m_mutex);
        m_impl->m_resultCache.erase(processId);
    }

    void EnvironmentEvasionDetector::ClearCache() noexcept {
        std::unique_lock lock(m_impl->m_mutex);
        m_impl->m_resultCache.clear();
    }

    size_t EnvironmentEvasionDetector::GetCacheSize() const noexcept {
        std::shared_lock lock(m_impl->m_mutex);
        return m_impl->m_resultCache.size();
    }

    void EnvironmentEvasionDetector::UpdateCache(
        uint32_t processId,
        const EnvironmentEvasionResult& result
    ) noexcept {
        try {
            std::unique_lock lock(m_impl->m_mutex);

            // Enforce cache size limit
            if (m_impl->m_resultCache.size() >= EnvironmentConstants::MAX_CACHE_ENTRIES) {
                // Remove oldest entry
                auto oldest = m_impl->m_resultCache.begin();
                for (auto it = m_impl->m_resultCache.begin(); it != m_impl->m_resultCache.end(); ++it) {
                    if (it->second.timestamp < oldest->second.timestamp) {
                        oldest = it;
                    }
                }
                m_impl->m_resultCache.erase(oldest);
            }

            Impl::CacheEntry entry;
            entry.result = result;
            entry.timestamp = std::chrono::steady_clock::now();

            m_impl->m_resultCache[processId] = std::move(entry);
        }
        catch (...) {
            // Cache update failure is non-fatal
        }
    }

    // ========================================================================
    // CONFIGURATION
    // ========================================================================

    void EnvironmentEvasionDetector::SetThreatIntelStore(
        std::shared_ptr<ThreatIntel::ThreatIntelStore> threatIntel
    ) noexcept {
        std::unique_lock lock(m_impl->m_mutex);
        m_impl->m_threatIntel = std::move(threatIntel);
    }

    void EnvironmentEvasionDetector::AddBlacklistedUsername(std::wstring_view username) noexcept {
        std::unique_lock lock(m_impl->m_mutex);
        m_impl->m_customBlacklistedUsernames.emplace_back(username);
    }

    void EnvironmentEvasionDetector::AddBlacklistedComputerName(std::wstring_view name) noexcept {
        std::unique_lock lock(m_impl->m_mutex);
        m_impl->m_customBlacklistedComputerNames.emplace_back(name);
    }

    void EnvironmentEvasionDetector::AddAnalysisToolProcess(std::wstring_view processName) noexcept {
        std::unique_lock lock(m_impl->m_mutex);
        m_impl->m_customAnalysisToolProcesses.emplace_back(processName);
    }

    void EnvironmentEvasionDetector::ClearCustomLists() noexcept {
        std::unique_lock lock(m_impl->m_mutex);
        m_impl->m_customBlacklistedUsernames.clear();
        m_impl->m_customBlacklistedComputerNames.clear();
        m_impl->m_customAnalysisToolProcesses.clear();
    }

    // ========================================================================
    // STATISTICS
    // ========================================================================

    const EnvironmentEvasionDetector::Statistics& EnvironmentEvasionDetector::GetStatistics() const noexcept {
        return m_impl->m_stats;
    }

    void EnvironmentEvasionDetector::ResetStatistics() noexcept {
        m_impl->m_stats.Reset();
    }

} // namespace ShadowStrike::AntiEvasion