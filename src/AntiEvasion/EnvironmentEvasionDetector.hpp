/**
 * @file EnvironmentEvasionDetector.hpp
 * @brief Enterprise-grade detection of environment-based sandbox/analysis evasion
 *
 * ShadowStrike AntiEvasion - Environment Evasion Detection Module
 * Copyright (c) 2026 ShadowStrike Security Suite. All rights reserved.
 *
 * ============================================================================
 * OVERVIEW
 * ============================================================================
 *
 * This module detects malware that attempts to evade analysis by checking
 * environmental characteristics that distinguish real user systems from
 * sandboxes, analysis VMs, and automated testing environments.
 *
 * Detected evasion categories:
 *
 * - User/Computer Name Checks: Blacklisted names (admin, test, sandbox, malware)
 * - File System Artifacts: Recent files, user documents, desktop items
 * - Registry Artifacts: Recently used programs, MRU lists, typed URLs
 * - Hardware Fingerprinting: CPU count, RAM size, disk capacity
 * - System Uptime: Fresh installs vs. lived-in systems
 * - Network Configuration: MAC addresses, network adapters, connectivity
 * - Installed Software: Browser history, email clients, productivity apps
 * - User Activity Indicators: Mouse movement, keyboard activity, window focus
 * - Process/Service Enumeration: Analysis tools, security software
 * - File Name Analysis: Hash-based naming, suspicious paths
 * - Environment Variables: Sandbox-specific variables, paths
 * - Locale/Regional Settings: Language, timezone, keyboard layout
 * - Display/Graphics: Resolution, multiple monitors, GPU presence
 * - USB/Peripheral History: Device connection history
 * - Browser Artifacts: Cookies, history, downloads, bookmarks
 *
 * ============================================================================
 * PERFORMANCE TARGETS
 * ============================================================================
 *
 * - Full environment analysis: < 200ms
 * - Quick check (name/uptime): < 10ms
 * - Hardware fingerprint: < 50ms
 * - File system artifact scan: < 100ms
 * - Registry artifact scan: < 100ms
 * - Batch analysis (100 processes): < 5 seconds
 *
 * ============================================================================
 * INTEGRATION POINTS
 * ============================================================================
 *
 * - Utils::SystemUtils - OS version, CPU info, memory info
 * - Utils::ProcessUtils - Process enumeration, environment block
 * - Utils::FileUtils - File system operations, file existence
 * - Utils::RegistryUtils - Registry queries
 * - Utils::NetworkUtils - Network adapter enumeration
 * - ThreatIntel - Known sandbox indicators correlation
 *
 * ============================================================================
 * MITRE ATT&CK COVERAGE
 * ============================================================================
 *
 * - T1497: Virtualization/Sandbox Evasion
 * - T1497.001: System Checks
 * - T1497.002: User Activity Based Checks
 * - T1497.003: Time Based Evasion
 * - T1082: System Information Discovery (detection of discovery attempts)
 * - T1016: System Network Configuration Discovery
 * - T1033: System Owner/User Discovery
 *
 * ============================================================================
 */

#pragma once

 // ============================================================================
 // STANDARD LIBRARY INCLUDES
 // ============================================================================

#include <cstdint>
#include <cstddef>
#include <string>
#include <string_view>
#include <vector>
#include <array>
#include <optional>
#include <memory>
#include <functional>
#include <chrono>
#include <atomic>
#include <mutex>
#include <shared_mutex>
#include <unordered_map>
#include <unordered_set>
#include <bitset>
#include <span>
#include <variant>
#include <set>
#include <regex>

// ============================================================================
// WINDOWS SDK INCLUDES
// ============================================================================

#ifdef _WIN32
#  ifndef NOMINMAX
#    define NOMINMAX
#  endif
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include <Windows.h>
#  include <winternl.h>
#  pragma comment(lib, "ntdll.lib")
#endif

// ============================================================================
// SHADOWSTRIKE INTERNAL INCLUDES
// ============================================================================

#include "../Utils/SystemUtils.hpp"
#include "../Utils/ProcessUtils.hpp"
#include "../Utils/FileUtils.hpp"
#include "../Utils/RegistryUtils.hpp"
#include "../Utils/Logger.hpp"

// Forward declarations
namespace ShadowStrike::ThreatIntel {
    class ThreatIntelStore;
}

namespace ShadowStrike {
    namespace AntiEvasion {

        // ============================================================================
        // CONSTANTS
        // ============================================================================

        namespace EnvironmentConstants {

            // ========================================================================
            // RESOURCE LIMITS
            // ========================================================================

            /// @brief Maximum environment variables to scan
            inline constexpr size_t MAX_ENV_VARS_TO_SCAN = 1024;

            /// @brief Maximum files to enumerate per directory
            inline constexpr size_t MAX_FILES_PER_DIRECTORY = 10000;

            /// @brief Maximum registry keys to enumerate
            inline constexpr size_t MAX_REGISTRY_KEYS = 5000;

            /// @brief Maximum processes to enumerate
            inline constexpr size_t MAX_PROCESSES_TO_ENUMERATE = 4096;

            /// @brief Default scan timeout in milliseconds
            inline constexpr uint32_t DEFAULT_SCAN_TIMEOUT_MS = 30000;

            /// @brief Cache entry TTL (seconds)
            inline constexpr uint32_t RESULT_CACHE_TTL_SECONDS = 120;

            /// @brief Maximum cache entries
            inline constexpr size_t MAX_CACHE_ENTRIES = 2048;

            // ========================================================================
            // EVASION THRESHOLDS
            // ========================================================================

            /// @brief Minimum uptime considered suspicious (5 minutes)
            inline constexpr uint64_t MIN_SUSPICIOUS_UPTIME_MS = 5 * 60 * 1000;

            /// @brief Maximum uptime considered suspicious for freshly booted sandbox (30 min)
            inline constexpr uint64_t MAX_FRESH_BOOT_UPTIME_MS = 30 * 60 * 1000;

            /// @brief Minimum processor count for non-suspicious system
            inline constexpr uint32_t MIN_NORMAL_PROCESSOR_COUNT = 2;

            /// @brief Minimum RAM size considered normal (2 GB)
            inline constexpr uint64_t MIN_NORMAL_RAM_BYTES = 2ULL * 1024 * 1024 * 1024;

            /// @brief Minimum disk size considered normal (40 GB)
            inline constexpr uint64_t MIN_NORMAL_DISK_BYTES = 40ULL * 1024 * 1024 * 1024;

            /// @brief Minimum screen resolution width
            inline constexpr uint32_t MIN_NORMAL_SCREEN_WIDTH = 800;

            /// @brief Minimum screen resolution height
            inline constexpr uint32_t MIN_NORMAL_SCREEN_HEIGHT = 600;

            /// @brief Minimum number of recent documents for "lived-in" system
            inline constexpr size_t MIN_RECENT_DOCUMENTS = 5;

            /// @brief Minimum number of installed programs for "lived-in" system
            inline constexpr size_t MIN_INSTALLED_PROGRAMS = 10;

            /// @brief Minimum browser history entries for "lived-in" system
            inline constexpr size_t MIN_BROWSER_HISTORY_ENTRIES = 50;

            // ========================================================================
            // SCORING WEIGHTS
            // ========================================================================

            /// @brief Weight for username/hostname checks
            inline constexpr double WEIGHT_NAME_CHECKS = 2.5;

            /// @brief Weight for hardware fingerprint checks
            inline constexpr double WEIGHT_HARDWARE_CHECKS = 2.0;

            /// @brief Weight for file system artifact checks
            inline constexpr double WEIGHT_FILESYSTEM_CHECKS = 1.5;

            /// @brief Weight for registry artifact checks
            inline constexpr double WEIGHT_REGISTRY_CHECKS = 1.5;

            /// @brief Weight for user activity checks
            inline constexpr double WEIGHT_USER_ACTIVITY_CHECKS = 2.0;

            /// @brief Weight for network configuration checks
            inline constexpr double WEIGHT_NETWORK_CHECKS = 1.8;

            /// @brief Weight for process enumeration checks
            inline constexpr double WEIGHT_PROCESS_CHECKS = 1.5;

            /// @brief Weight for timing-based checks
            inline constexpr double WEIGHT_TIMING_CHECKS = 2.2;

            /// @brief Weight for advanced/combined checks
            inline constexpr double WEIGHT_ADVANCED_CHECKS = 3.0;

            /// @brief High evasion score threshold
            inline constexpr double HIGH_EVASION_THRESHOLD = 70.0;

            /// @brief Critical evasion score threshold
            inline constexpr double CRITICAL_EVASION_THRESHOLD = 90.0;

            // ========================================================================
            // BLACKLISTED NAMES (commonly used in sandboxes/analysis)
            // ========================================================================

            /// @brief Known sandbox/analysis usernames
            inline constexpr std::array<std::wstring_view, 70> BLACKLISTED_USERNAMES = { {
                    // Generic analysis names
                    L"admin", L"administrator", L"user", L"test", L"sandbox",
                    L"malware", L"virus", L"sample", L"analysis", L"analyzer",
                    L"analyst", L"honey", L"honeypot", L"currentuser", L"vmware",
                    L"virtual", L"guest", L"john", L"johndoe", L"jane",

                    // Vendor-specific sandbox names
                    L"cuckoo", L"cuckoosandbox", L"cape", L"any.run", L"anyrun",
                    L"triage", L"hybrid", L"vxstream", L"falcon", L"crowdstrike",
                    L"wilbert", L"harley", L"abby", L"peter wilson", L"hwiteman",
                    L"user-pc", L"john doe", L"hal9th", L"habib", L"hong lee",
                    L"timmy", L"emily", L"eric johns", L"jerry", L"johnson",
                    L"miller", L"mueller", L"phil", L"walker", L"fred",

                    // Security researcher names
                    L"malwareresearcher", L"researcher", L"debug", L"debugger",
                    L"reverse", L"reverser", L"analysis", L"lab", L"labuser",
                    L"vbox", L"virtualbox", L"qemu", L"parallels", L"hyperv",

                    // Automated systems
                    L"system", L"defaultuser", L"defaultaccount", L"wdagutilityaccount"
                } };

            /// @brief Known sandbox/analysis computer names
            inline constexpr std::array<std::wstring_view, 70> BLACKLISTED_COMPUTER_NAMES = { {
                    // Generic analysis names
                    L"sandbox", L"malware", L"virus", L"sample", L"analysis",
                    L"test", L"testpc", L"testmachine", L"virtual", L"vm",
                    L"vmware", L"virtualbox", L"vbox", L"qemu", L"xen",

                    // Vendor sandbox names
                    L"cuckoo", L"cape", L"anyrun", L"hybrid-analysis", L"vxstream",
                    L"threatgrid", L"joe-sandbox", L"joesandbox", L"joebox",
                    L"sandcastle", L"deepguard", L"bitdefender", L"kaspersky",
                    L"fireye", L"fireeye", L"lastline", L"intezer", L"unpac.me",

                    // Common VM names
                    L"win-sandbox", L"windows-sandbox", L"desktop-", L"pc-",
                    L"workstation", L"server", L"dc", L"domaincontroller",
                    L"tequilaboomboom", L"klone_x64-pc", L"computer", L"comp",

                    // Specific sandbox patterns
                    L"hal9th", L"johnson-pc", L"miller-pc", L"phil-pc",
                    L"win7-pc", L"win10-pc", L"win11-pc", L"win7-analysis",
                    L"analysis-vm", L"malware-vm", L"sandbox-vm", L"test-vm",

                    // Automated systems
                    L"azure", L"aws", L"gcp", L"cloud", L"instance",
                    L"default", L"template", L"base", L"master", L"golden"
                } };

            /// @brief Known sandbox MAC address prefixes (OUI)
            inline constexpr std::array<std::array<uint8_t, 3>, 16> SANDBOX_MAC_PREFIXES = { {
                {0x00, 0x0C, 0x29},  // VMware
                {0x00, 0x50, 0x56},  // VMware
                {0x00, 0x05, 0x69},  // VMware
                {0x00, 0x1C, 0x14},  // VMware
                {0x00, 0x1C, 0x42},  // Parallels
                {0x00, 0x03, 0xFF},  // Microsoft Hyper-V
                {0x00, 0x15, 0x5D},  // Microsoft Hyper-V
                {0x08, 0x00, 0x27},  // VirtualBox
                {0x0A, 0x00, 0x27},  // VirtualBox
                {0x52, 0x54, 0x00},  // QEMU/KVM
                {0x00, 0x16, 0x3E},  // Xen
                {0x00, 0x1A, 0x4A},  // QEMU
                {0x00, 0x0F, 0x4B},  // Virtual Iron
                {0x00, 0x21, 0xF6},  // Virtual Iron
                {0x00, 0x14, 0x4F},  // Oracle VM
                {0x00, 0x0D, 0x3A}   // Microsoft Virtual PC
            } };

            /// @brief Known analysis tool process names
            inline constexpr std::array<std::wstring_view, 64> ANALYSIS_TOOL_PROCESSES = { {
                    // Debuggers
                    L"ollydbg.exe", L"x64dbg.exe", L"x32dbg.exe", L"windbg.exe",
                    L"idaq.exe", L"idaq64.exe", L"ida.exe", L"ida64.exe",
                    L"radare2.exe", L"immunity debugger.exe",

                    // Sysinternals
                    L"procmon.exe", L"procexp.exe", L"procexp64.exe", L"autoruns.exe",
                    L"tcpview.exe", L"strings.exe", L"listdlls.exe", L"handle.exe",

                    // Network analysis
                    L"wireshark.exe", L"tshark.exe", L"fiddler.exe", L"charles.exe",
                    L"burpsuite.exe", L"mitmproxy.exe", L"ettercap.exe",

                    // Sandbox agents
                    L"python.exe", L"pythonw.exe", L"python3.exe",  // Often used by sandbox
                    L"agent.exe", L"analyzer.exe", L"vbox*.exe",
                    L"vmtoolsd.exe", L"vmwaretray.exe", L"vmwareuser.exe",
                    L"vboxservice.exe", L"vboxtray.exe", L"xenservice.exe",

                    // API monitoring
                    L"apimonitor.exe", L"apispy.exe", L"importrec.exe",
                    L"petools.exe", L"lordpe.exe", L"pestudio.exe",

                    // .NET analysis
                    L"dnspy.exe", L"de4dot.exe", L"ilspy.exe", L"dotpeek.exe",
                    L"ildasm.exe", L"reflector.exe",

                    // Memory analysis
                    L"processhacker.exe", L"cheatengine.exe", L"hxd.exe",
                    L"winhex.exe", L"010editor.exe",

                    // Sandbox specific
                    L"cuckoomon.exe", L"capemon.exe", L"sandboxie*.exe",
                    L"sbiectrl.exe", L"sbiedll.dll"
                } };

            /// @brief Known sandbox-specific registry paths to check
            inline constexpr std::array<std::wstring_view, 32> SANDBOX_REGISTRY_KEYS = { {
                    // VMware
                    L"SOFTWARE\\VMware, Inc.\\VMware Tools",
                    L"SOFTWARE\\VMware, Inc.\\VMware VGAuth",
                    L"SYSTEM\\CurrentControlSet\\Services\\VMTools",
                    L"SYSTEM\\CurrentControlSet\\Services\\vmvss",

                    // VirtualBox
                    L"SOFTWARE\\Oracle\\VirtualBox Guest Additions",
                    L"SYSTEM\\CurrentControlSet\\Services\\VBoxGuest",
                    L"SYSTEM\\CurrentControlSet\\Services\\VBoxMouse",
                    L"SYSTEM\\CurrentControlSet\\Services\\VBoxService",
                    L"SYSTEM\\CurrentControlSet\\Services\\VBoxSF",
                    L"SYSTEM\\CurrentControlSet\\Services\\VBoxVideo",

                    // Hyper-V
                    L"SOFTWARE\\Microsoft\\Virtual Machine\\Guest\\Parameters",
                    L"SYSTEM\\CurrentControlSet\\Services\\vmicheartbeat",
                    L"SYSTEM\\CurrentControlSet\\Services\\vmickvpexchange",

                    // Parallels
                    L"SOFTWARE\\Parallels\\Parallels Tools",
                    L"SYSTEM\\CurrentControlSet\\Services\\prl_*",

                    // QEMU
                    L"SYSTEM\\CurrentControlSet\\Services\\QEMU*",
                    L"HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0",

                    // Wine
                    L"SOFTWARE\\Wine",

                    // Sandboxie
                    L"SOFTWARE\\Sandboxie",
                    L"SOFTWARE\\Sandboxie-Plus",

                    // Cuckoo/CAPE
                    L"SOFTWARE\\Cuckoo",
                    L"SOFTWARE\\CAPE",

                    // Generic VM indicators
                    L"HARDWARE\\ACPI\\DSDT\\VBOX__",
                    L"HARDWARE\\ACPI\\FADT\\VBOX__",
                    L"HARDWARE\\ACPI\\RSDT\\VBOX__",
                    L"SOFTWARE\\Classes\\CLSID\\{D86A61EF-F707-44ED-BD87-C15E0CC70F84}",  // Sandboxie
                    L"SYSTEM\\CurrentControlSet\\Enum\\IDE",
                    L"SYSTEM\\CurrentControlSet\\Enum\\SCSI"
                } };

            /// @brief Known sandbox-related environment variables
            inline constexpr std::array<std::wstring_view, 24> SANDBOX_ENV_VARIABLES = { {
                L"SANDBOX_INUSE",
                L"CUCKOO_SANDBOX",
                L"CAPE_SANDBOX",
                L"ANYRUN_SANDBOX",
                L"HYBRID_ANALYSIS",
                L"JOE_SANDBOX",
                L"THREATGRID",
                L"SANDCASTLE",
                L"MALWARE_ANALYSIS",
                L"VIRUS_ANALYSIS",
                L"SAMPLE_ANALYSIS",
                L"DEBUG_MODE",
                L"ANALYSIS_MODE",
                L"VIRTUAL_ENV",
                L"VM_PLATFORM",
                L"SANDBOXIE",
                L"WINE_PLATFORM",
                L"QEMU_PLATFORM",
                L"VMWARE_PLATFORM",
                L"VBOX_PLATFORM",
                L"HYPERV_PLATFORM",
                L"XEN_PLATFORM",
                L"PARALLELS_PLATFORM",
                L"DOCKER_CONTAINER"
            } };

            /// @brief File paths that indicate a "lived-in" system
            inline constexpr std::array<std::wstring_view, 24> USER_ACTIVITY_PATHS = { {
                L"%USERPROFILE%\\Documents",
                L"%USERPROFILE%\\Downloads",
                L"%USERPROFILE%\\Desktop",
                L"%USERPROFILE%\\Pictures",
                L"%USERPROFILE%\\Music",
                L"%USERPROFILE%\\Videos",
                L"%APPDATA%\\Microsoft\\Windows\\Recent",
                L"%LOCALAPPDATA%\\Microsoft\\Windows\\Explorer",
                L"%LOCALAPPDATA%\\Google\\Chrome\\User Data",
                L"%LOCALAPPDATA%\\Microsoft\\Edge\\User Data",
                L"%APPDATA%\\Mozilla\\Firefox\\Profiles",
                L"%APPDATA%\\Microsoft\\Office\\Recent",
                L"%LOCALAPPDATA%\\Microsoft\\Outlook",
                L"%APPDATA%\\Microsoft\\Teams",
                L"%APPDATA%\\Slack",
                L"%APPDATA%\\Discord",
                L"%APPDATA%\\Zoom",
                L"%LOCALAPPDATA%\\WhatsApp",
                L"%LOCALAPPDATA%\\Programs",
                L"%PROGRAMFILES%",
                L"%PROGRAMFILES(X86)%",
                L"%USERPROFILE%\\.ssh",
                L"%USERPROFILE%\\.gitconfig",
                L"%LOCALAPPDATA%\\Packages"
            } };

        } // namespace EnvironmentConstants

        // ============================================================================
        // ENUMERATIONS
        // ============================================================================

        /**
         * @brief Categories of environment evasion techniques
         */
        enum class EnvironmentEvasionCategory : uint8_t {
            /// @brief Username/hostname blacklist checks
            NameChecks = 0,

            /// @brief Hardware fingerprinting (CPU, RAM, disk)
            HardwareFingerprinting = 1,

            /// @brief File system artifact presence
            FileSystemArtifacts = 2,

            /// @brief Registry artifact presence
            RegistryArtifacts = 3,

            /// @brief User activity indicators
            UserActivityIndicators = 4,

            /// @brief Network configuration analysis
            NetworkConfiguration = 5,

            /// @brief Running process/service enumeration
            ProcessEnumeration = 6,

            /// @brief System uptime and timing
            TimingChecks = 7,

            /// @brief Environment variable analysis
            EnvironmentVariables = 8,

            /// @brief Display/graphics configuration
            DisplayConfiguration = 9,

            /// @brief Locale and regional settings
            LocaleSettings = 10,

            /// @brief Browser artifacts (history, cookies)
            BrowserArtifacts = 11,

            /// @brief Peripheral/USB device history
            PeripheralHistory = 12,

            /// @brief File naming patterns (hash-based)
            FileNamingPatterns = 13,

            /// @brief Multiple techniques combined
            Combined = 14,

            /// @brief Unknown category
            Unknown = 255
        };

        /**
         * @brief Specific environment evasion technique identifiers
         */
        enum class EnvironmentEvasionTechnique : uint16_t {
            /// @brief No technique detected
            None = 0,

            // ========================================================================
            // NAME CHECKS (1-20)
            // ========================================================================

            /// @brief Username matches known sandbox name
            NAME_BlacklistedUsername = 1,

            /// @brief Computer name matches known sandbox name
            NAME_BlacklistedComputerName = 2,

            /// @brief Domain name matches known sandbox domain
            NAME_BlacklistedDomain = 3,

            /// @brief Username is default/generic
            NAME_DefaultUsername = 4,

            /// @brief Computer name follows VM naming pattern
            NAME_VMNamingPattern = 5,

            /// @brief Username length check (too short/generic)
            NAME_SuspiciousLength = 6,

            // ========================================================================
            // HARDWARE FINGERPRINTING (21-50)
            // ========================================================================

            /// @brief Low processor count (< 2)
            HARDWARE_LowProcessorCount = 21,

            /// @brief Low RAM (< 2 GB)
            HARDWARE_LowRAM = 22,

            /// @brief Small disk capacity (< 40 GB)
            HARDWARE_SmallDisk = 23,

            /// @brief No secondary storage devices
            HARDWARE_SingleDisk = 24,

            /// @brief VM-specific disk vendor string
            HARDWARE_VMDiskVendor = 25,

            /// @brief VM-specific BIOS vendor
            HARDWARE_VMBIOSVendor = 26,

            /// @brief VM-specific system manufacturer
            HARDWARE_VMManufacturer = 27,

            /// @brief VM-specific product name
            HARDWARE_VMProductName = 28,

            /// @brief VM-specific CPU brand string
            HARDWARE_VMCPUBrand = 29,

            /// @brief Hypervisor bit set in CPUID
            HARDWARE_HypervisorBit = 30,

            /// @brief VM-specific motherboard
            HARDWARE_VMMotherboard = 31,

            /// @brief VM-specific GPU/display adapter
            HARDWARE_VMDisplayAdapter = 32,

            /// @brief SMBIOS VM indicators
            HARDWARE_SMBIOSVMIndicators = 33,

            /// @brief ACPI table VM indicators
            HARDWARE_ACPIVMIndicators = 34,

            // ========================================================================
            // FILE SYSTEM ARTIFACTS (51-80)
            // ========================================================================

            /// @brief VM guest tools directories exist
            FILESYSTEM_VMToolsDirectory = 51,

            /// @brief VM-specific drivers present
            FILESYSTEM_VMDrivers = 52,

            /// @brief Sandbox agent files present
            FILESYSTEM_SandboxAgentFiles = 53,

            /// @brief Analysis tool installation detected
            FILESYSTEM_AnalysisToolsInstalled = 54,

            /// @brief Empty Documents folder
            FILESYSTEM_EmptyDocuments = 55,

            /// @brief Empty Downloads folder
            FILESYSTEM_EmptyDownloads = 56,

            /// @brief Empty Desktop folder
            FILESYSTEM_EmptyDesktop = 57,

            /// @brief No recent files
            FILESYSTEM_NoRecentFiles = 58,

            /// @brief Missing user profile artifacts
            FILESYSTEM_MissingUserArtifacts = 59,

            /// @brief Suspicious temp directory contents
            FILESYSTEM_SuspiciousTempDir = 60,

            /// @brief Analysis-related files present
            FILESYSTEM_AnalysisFiles = 61,

            /// @brief VM shared folders mounted
            FILESYSTEM_VMSharedFolders = 62,

            /// @brief Unusually clean system directories
            FILESYSTEM_CleanSystemDirs = 63,

            // ========================================================================
            // REGISTRY ARTIFACTS (81-110)
            // ========================================================================

            /// @brief VMware registry keys present
            REGISTRY_VMwareKeys = 81,

            /// @brief VirtualBox registry keys present
            REGISTRY_VirtualBoxKeys = 82,

            /// @brief Hyper-V registry keys present
            REGISTRY_HyperVKeys = 83,

            /// @brief Parallels registry keys present
            REGISTRY_ParallelsKeys = 84,

            /// @brief QEMU/KVM registry keys present
            REGISTRY_QEMUKeys = 85,

            /// @brief Sandboxie registry keys present
            REGISTRY_SandboxieKeys = 86,

            /// @brief Wine registry keys present
            REGISTRY_WineKeys = 87,

            /// @brief Empty MRU (Most Recently Used) lists
            REGISTRY_EmptyMRULists = 88,

            /// @brief No typed URLs in browser history
            REGISTRY_NoTypedURLs = 89,

            /// @brief No recently used programs
            REGISTRY_NoRecentPrograms = 90,

            /// @brief Suspicious install date
            REGISTRY_SuspiciousInstallDate = 91,

            /// @brief Missing common software keys
            REGISTRY_MissingSoftwareKeys = 92,

            /// @brief VM guest tools services
            REGISTRY_VMServices = 93,

            // ========================================================================
            // USER ACTIVITY INDICATORS (111-140)
            // ========================================================================

            /// @brief No mouse movement detected
            ACTIVITY_NoMouseMovement = 111,

            /// @brief No keyboard activity detected
            ACTIVITY_NoKeyboardActivity = 112,

            /// @brief No window focus changes
            ACTIVITY_NoWindowFocus = 113,

            /// @brief Insufficient clipboard history
            ACTIVITY_NoClipboardHistory = 114,

            /// @brief No screenshots in user folders
            ACTIVITY_NoScreenshots = 115,

            /// @brief Empty recycle bin with no history
            ACTIVITY_EmptyRecycleBin = 116,

            /// @brief No printer history
            ACTIVITY_NoPrinterHistory = 117,

            /// @brief No mapped network drives
            ACTIVITY_NoNetworkDrives = 118,

            /// @brief No recent searches
            ACTIVITY_NoRecentSearches = 119,

            /// @brief Jump list is empty
            ACTIVITY_EmptyJumpLists = 120,

            /// @brief No notification history
            ACTIVITY_NoNotifications = 121,

            /// @brief User idle detection
            ACTIVITY_UserIdleDetection = 122,

            /// @brief Human interaction simulation check
            ACTIVITY_SimulationCheck = 123,

            // ========================================================================
            // NETWORK CONFIGURATION (141-170)
            // ========================================================================

            /// @brief VM MAC address prefix detected
            NETWORK_VMMACPrefix = 141,

            /// @brief Only loopback adapter present
            NETWORK_OnlyLoopback = 142,

            /// @brief VM network adapter name
            NETWORK_VMAdapterName = 143,

            /// @brief No WiFi adapter history
            NETWORK_NoWiFiHistory = 144,

            /// @brief Suspicious DNS configuration
            NETWORK_SuspiciousDNS = 145,

            /// @brief No network shares accessed
            NETWORK_NoNetworkShares = 146,

            /// @brief Sandbox-specific gateway IP
            NETWORK_SandboxGateway = 147,

            /// @brief NAT-only networking detected
            NETWORK_NATOnlyNetwork = 148,

            /// @brief No network drives mounted
            NETWORK_NoMountedDrives = 149,

            /// @brief Suspicious IP address range
            NETWORK_SuspiciousIPRange = 150,

            // ========================================================================
            // PROCESS ENUMERATION (171-200)
            // ========================================================================

            /// @brief Analysis tool process running
            PROCESS_AnalysisToolRunning = 171,

            /// @brief Debugger process running
            PROCESS_DebuggerRunning = 172,

            /// @brief VM guest tools process running
            PROCESS_VMToolsRunning = 173,

            /// @brief Sandbox agent process running
            PROCESS_SandboxAgentRunning = 174,

            /// @brief Suspicious service running
            PROCESS_SuspiciousService = 175,

            /// @brief Low number of running processes
            PROCESS_LowProcessCount = 176,

            /// @brief Missing expected system processes
            PROCESS_MissingSystemProcesses = 177,

            /// @brief Analysis-related window titles
            PROCESS_AnalysisWindowTitles = 178,

            /// @brief API hooking DLLs loaded
            PROCESS_HookingDLLs = 179,

            // ========================================================================
            // TIMING CHECKS (201-220)
            // ========================================================================

            /// @brief Very short system uptime
            TIMING_ShortUptime = 201,

            /// @brief Recent system install date
            TIMING_RecentInstall = 202,

            /// @brief No scheduled tasks
            TIMING_NoScheduledTasks = 203,

            /// @brief Event log recently cleared
            TIMING_EventLogCleared = 204,

            /// @brief Accelerated time detection
            TIMING_AcceleratedTime = 205,

            /// @brief Sleep skipping detection
            TIMING_SleepSkipping = 206,

            /// @brief Boot time anomaly
            TIMING_BootTimeAnomaly = 207,

            /// @brief File timestamp clustering
            TIMING_TimestampClustering = 208,

            // ========================================================================
            // ENVIRONMENT VARIABLES (221-240)
            // ========================================================================

            /// @brief Sandbox-specific env variable
            ENV_SandboxVariable = 221,

            /// @brief VM-specific env variable
            ENV_VMVariable = 222,

            /// @brief Analysis-specific env variable
            ENV_AnalysisVariable = 223,

            /// @brief Missing expected env variables
            ENV_MissingVariables = 224,

            /// @brief Suspicious PATH configuration
            ENV_SuspiciousPath = 225,

            /// @brief Unusual TEMP path
            ENV_UnusualTempPath = 226,

            // ========================================================================
            // DISPLAY CONFIGURATION (241-260)
            // ========================================================================

            /// @brief Low screen resolution
            DISPLAY_LowResolution = 241,

            /// @brief Only single monitor
            DISPLAY_SingleMonitor = 242,

            /// @brief VM display driver
            DISPLAY_VMDriver = 243,

            /// @brief Missing GPU
            DISPLAY_MissingGPU = 244,

            /// @brief Unusual color depth
            DISPLAY_UnusualColorDepth = 245,

            /// @brief VM graphics adapter
            DISPLAY_VMGraphicsAdapter = 246,

            // ========================================================================
            // LOCALE/REGIONAL (261-280)
            // ========================================================================

            /// @brief Default/neutral locale
            LOCALE_DefaultLocale = 261,

            /// @brief Mismatched timezone
            LOCALE_MismatchedTimezone = 262,

            /// @brief Single keyboard layout
            LOCALE_SingleKeyboard = 263,

            /// @brief Default language setting
            LOCALE_DefaultLanguage = 264,

            /// @brief Suspicious region/country
            LOCALE_SuspiciousRegion = 265,

            // ========================================================================
            // BROWSER ARTIFACTS (281-300)
            // ========================================================================

            /// @brief No browser history
            BROWSER_NoHistory = 281,

            /// @brief No bookmarks
            BROWSER_NoBookmarks = 282,

            /// @brief No cookies
            BROWSER_NoCookies = 283,

            /// @brief No saved passwords
            BROWSER_NoPasswords = 284,

            /// @brief No browser extensions
            BROWSER_NoExtensions = 285,

            /// @brief No download history
            BROWSER_NoDownloads = 286,

            /// @brief No form autofill data
            BROWSER_NoAutofill = 287,

            /// @brief Only default browser installed
            BROWSER_OnlyDefault = 288,

            // ========================================================================
            // PERIPHERAL HISTORY (301-320)
            // ========================================================================

            /// @brief No USB device history
            PERIPHERAL_NoUSBHistory = 301,

            /// @brief No Bluetooth pairings
            PERIPHERAL_NoBluetoothPairings = 302,

            /// @brief No printer installations
            PERIPHERAL_NoPrinters = 303,

            /// @brief No audio devices
            PERIPHERAL_NoAudioDevices = 304,

            /// @brief No webcam detected
            PERIPHERAL_NoWebcam = 305,

            /// @brief Missing typical peripherals
            PERIPHERAL_MissingDevices = 306,

            // ========================================================================
            // FILE NAMING PATTERNS (321-340)
            // ========================================================================

            /// @brief File name is MD5 hash
            FILENAME_MD5Hash = 321,

            /// @brief File name is SHA1 hash
            FILENAME_SHA1Hash = 322,

            /// @brief File name is SHA256 hash
            FILENAME_SHA256Hash = 323,

            /// @brief File name is generic (sample, malware, etc.)
            FILENAME_Generic = 324,

            /// @brief File in suspicious location
            FILENAME_SuspiciousLocation = 325,

            /// @brief File name contains analysis keywords
            FILENAME_AnalysisKeywords = 326,

            /// @brief Multiple file extensions
            FILENAME_MultipleExtensions = 327,

            /// @brief Randomly generated file name
            FILENAME_RandomPattern = 328,

            // ========================================================================
            // ADVANCED/COMBINED (341-360)
            // ========================================================================

            /// @brief Multiple evasion categories detected
            ADVANCED_MultiCategoryEvasion = 341,

            /// @brief Sophisticated fingerprinting code
            ADVANCED_SophisticatedFingerprinting = 342,

            /// @brief Polymorphic environment check
            ADVANCED_PolymorphicCheck = 343,

            /// @brief Encrypted environment data
            ADVANCED_EncryptedCheck = 344,

            /// @brief Time-delayed environment check
            ADVANCED_DelayedCheck = 345,

            /// @brief Anti-forensics detected
            ADVANCED_AntiForensics = 346,

            /// @brief Maximum technique ID (for bounds checking)
            _MaxTechniqueId = 360
        };

        /**
         * @brief Severity level of detected evasion
         */
        enum class EnvironmentEvasionSeverity : uint8_t {
            /// @brief Informational (common in legitimate software)
            Low = 0,

            /// @brief Moderate (suspicious but not definitive)
            Medium = 1,

            /// @brief High (strong indicator of evasion)
            High = 2,

            /// @brief Critical (definitive sandbox evasion)
            Critical = 3
        };

        /**
         * @brief Analysis depth for environment scanning
         */
        enum class EnvironmentAnalysisDepth : uint8_t {
            /// @brief Quick scan - names and basic hardware only
            Quick = 0,

            /// @brief Standard - adds file system and registry
            Standard = 1,

            /// @brief Deep - includes user activity and browser
            Deep = 2,

            /// @brief Comprehensive - all categories
            Comprehensive = 3
        };

        /**
         * @brief Analysis flags for selective scanning
         */
        enum class EnvironmentAnalysisFlags : uint32_t {
            None = 0,

            // Category flags
            ScanNameChecks = 1 << 0,
            ScanHardwareFingerprint = 1 << 1,
            ScanFileSystemArtifacts = 1 << 2,
            ScanRegistryArtifacts = 1 << 3,
            ScanUserActivity = 1 << 4,
            ScanNetworkConfig = 1 << 5,
            ScanProcessEnumeration = 1 << 6,
            ScanTimingChecks = 1 << 7,
            ScanEnvironmentVars = 1 << 8,
            ScanDisplayConfig = 1 << 9,
            ScanLocaleSettings = 1 << 10,
            ScanBrowserArtifacts = 1 << 11,
            ScanPeripheralHistory = 1 << 12,
            ScanFileNamingPatterns = 1 << 13,

            // Behavior flags
            EnableCaching = 1 << 20,
            EnableParallelScan = 1 << 21,
            EnableThreatIntelCorrelation = 1 << 22,
            StopOnFirstDetection = 1 << 23,
            IncludeSystemEnvironment = 1 << 24,

            // Presets
            QuickScan = ScanNameChecks | ScanHardwareFingerprint | ScanTimingChecks | EnableCaching,
            StandardScan = QuickScan | ScanFileSystemArtifacts | ScanRegistryArtifacts |
            ScanProcessEnumeration | ScanEnvironmentVars,
            DeepScan = StandardScan | ScanUserActivity | ScanNetworkConfig |
            ScanDisplayConfig | ScanBrowserArtifacts,
            ComprehensiveScan = 0x3FFF | EnableCaching | EnableParallelScan,

            Default = StandardScan
        };

        // Bitwise operators
        inline constexpr EnvironmentAnalysisFlags operator|(EnvironmentAnalysisFlags a, EnvironmentAnalysisFlags b) noexcept {
            return static_cast<EnvironmentAnalysisFlags>(static_cast<uint32_t>(a) | static_cast<uint32_t>(b));
        }

        inline constexpr EnvironmentAnalysisFlags operator&(EnvironmentAnalysisFlags a, EnvironmentAnalysisFlags b) noexcept {
            return static_cast<EnvironmentAnalysisFlags>(static_cast<uint32_t>(a) & static_cast<uint32_t>(b));
        }

        inline constexpr EnvironmentAnalysisFlags operator~(EnvironmentAnalysisFlags a) noexcept {
            return static_cast<EnvironmentAnalysisFlags>(~static_cast<uint32_t>(a));
        }

        inline constexpr bool HasFlag(EnvironmentAnalysisFlags flags, EnvironmentAnalysisFlags flag) noexcept {
            return (static_cast<uint32_t>(flags) & static_cast<uint32_t>(flag)) != 0;
        }

        // ============================================================================
        // UTILITY FUNCTIONS
        // ============================================================================

        /**
         * @brief Get string representation of evasion category
         */
        [[nodiscard]] constexpr const char* EnvironmentCategoryToString(EnvironmentEvasionCategory category) noexcept {
            switch (category) {
            case EnvironmentEvasionCategory::NameChecks:           return "Name Checks";
            case EnvironmentEvasionCategory::HardwareFingerprinting: return "Hardware Fingerprinting";
            case EnvironmentEvasionCategory::FileSystemArtifacts:  return "File System Artifacts";
            case EnvironmentEvasionCategory::RegistryArtifacts:    return "Registry Artifacts";
            case EnvironmentEvasionCategory::UserActivityIndicators: return "User Activity Indicators";
            case EnvironmentEvasionCategory::NetworkConfiguration: return "Network Configuration";
            case EnvironmentEvasionCategory::ProcessEnumeration:   return "Process Enumeration";
            case EnvironmentEvasionCategory::TimingChecks:         return "Timing Checks";
            case EnvironmentEvasionCategory::EnvironmentVariables: return "Environment Variables";
            case EnvironmentEvasionCategory::DisplayConfiguration: return "Display Configuration";
            case EnvironmentEvasionCategory::LocaleSettings:       return "Locale Settings";
            case EnvironmentEvasionCategory::BrowserArtifacts:     return "Browser Artifacts";
            case EnvironmentEvasionCategory::PeripheralHistory:    return "Peripheral History";
            case EnvironmentEvasionCategory::FileNamingPatterns:   return "File Naming Patterns";
            case EnvironmentEvasionCategory::Combined:             return "Combined";
            default:                                               return "Unknown";
            }
        }

        /**
         * @brief Get string representation of technique
         */
        [[nodiscard]] const wchar_t* EnvironmentTechniqueToString(EnvironmentEvasionTechnique technique) noexcept;

        /**
         * @brief Get MITRE ATT&CK ID for technique
         */
        [[nodiscard]] constexpr const char* EnvironmentTechniqueToMitreId(EnvironmentEvasionTechnique technique) noexcept {
            const auto id = static_cast<uint16_t>(technique);

            // System checks - T1497.001
            if ((id >= 21 && id <= 50) || (id >= 241 && id <= 280)) {
                return "T1497.001";
            }

            // User activity based - T1497.002
            if (id >= 111 && id <= 140) {
                return "T1497.002";
            }

            // Time based - T1497.003
            if (id >= 201 && id <= 220) {
                return "T1497.003";
            }

            // System information discovery - T1082
            if (id >= 1 && id <= 20) {
                return "T1082";
            }

            // Network configuration discovery - T1016
            if (id >= 141 && id <= 170) {
                return "T1016";
            }

            // Default to virtualization/sandbox evasion
            return "T1497";
        }

        /**
         * @brief Get category for technique
         */
        [[nodiscard]] constexpr EnvironmentEvasionCategory GetTechniqueCategory(EnvironmentEvasionTechnique technique) noexcept {
            const auto id = static_cast<uint16_t>(technique);

            if (id >= 1 && id <= 20)    return EnvironmentEvasionCategory::NameChecks;
            if (id >= 21 && id <= 50)   return EnvironmentEvasionCategory::HardwareFingerprinting;
            if (id >= 51 && id <= 80)   return EnvironmentEvasionCategory::FileSystemArtifacts;
            if (id >= 81 && id <= 110)  return EnvironmentEvasionCategory::RegistryArtifacts;
            if (id >= 111 && id <= 140) return EnvironmentEvasionCategory::UserActivityIndicators;
            if (id >= 141 && id <= 170) return EnvironmentEvasionCategory::NetworkConfiguration;
            if (id >= 171 && id <= 200) return EnvironmentEvasionCategory::ProcessEnumeration;
            if (id >= 201 && id <= 220) return EnvironmentEvasionCategory::TimingChecks;
            if (id >= 221 && id <= 240) return EnvironmentEvasionCategory::EnvironmentVariables;
            if (id >= 241 && id <= 260) return EnvironmentEvasionCategory::DisplayConfiguration;
            if (id >= 261 && id <= 280) return EnvironmentEvasionCategory::LocaleSettings;
            if (id >= 281 && id <= 300) return EnvironmentEvasionCategory::BrowserArtifacts;
            if (id >= 301 && id <= 320) return EnvironmentEvasionCategory::PeripheralHistory;
            if (id >= 321 && id <= 340) return EnvironmentEvasionCategory::FileNamingPatterns;
            if (id >= 341 && id <= 360) return EnvironmentEvasionCategory::Combined;

            return EnvironmentEvasionCategory::Unknown;
        }

        /**
         * @brief Get default severity for technique
         */
        [[nodiscard]] constexpr EnvironmentEvasionSeverity GetDefaultTechniqueSeverity(
            EnvironmentEvasionTechnique technique
        ) noexcept {
            switch (technique) {
                // Critical - definitive sandbox indicators
            case EnvironmentEvasionTechnique::NAME_BlacklistedUsername:
            case EnvironmentEvasionTechnique::NAME_BlacklistedComputerName:
            case EnvironmentEvasionTechnique::REGISTRY_VMwareKeys:
            case EnvironmentEvasionTechnique::REGISTRY_VirtualBoxKeys:
            case EnvironmentEvasionTechnique::REGISTRY_SandboxieKeys:
            case EnvironmentEvasionTechnique::PROCESS_SandboxAgentRunning:
            case EnvironmentEvasionTechnique::ENV_SandboxVariable:
            case EnvironmentEvasionTechnique::ADVANCED_MultiCategoryEvasion:
                return EnvironmentEvasionSeverity::Critical;

                // High - strong indicators
            case EnvironmentEvasionTechnique::HARDWARE_VMDiskVendor:
            case EnvironmentEvasionTechnique::HARDWARE_VMBIOSVendor:
            case EnvironmentEvasionTechnique::HARDWARE_HypervisorBit:
            case EnvironmentEvasionTechnique::NETWORK_VMMACPrefix:
            case EnvironmentEvasionTechnique::PROCESS_VMToolsRunning:
            case EnvironmentEvasionTechnique::FILESYSTEM_VMToolsDirectory:
            case EnvironmentEvasionTechnique::FILENAME_MD5Hash:
            case EnvironmentEvasionTechnique::FILENAME_SHA256Hash:
                return EnvironmentEvasionSeverity::High;

                // Medium - suspicious indicators
            case EnvironmentEvasionTechnique::HARDWARE_LowProcessorCount:
            case EnvironmentEvasionTechnique::HARDWARE_LowRAM:
            case EnvironmentEvasionTechnique::HARDWARE_SmallDisk:
            case EnvironmentEvasionTechnique::TIMING_ShortUptime:
            case EnvironmentEvasionTechnique::ACTIVITY_NoMouseMovement:
            case EnvironmentEvasionTechnique::BROWSER_NoHistory:
                return EnvironmentEvasionSeverity::Medium;

                // Low - common/benign indicators
            default:
                return EnvironmentEvasionSeverity::Low;
            }
        }

        // ============================================================================
        // DATA STRUCTURES
        // ============================================================================

        /**
         * @brief Error information for detector operations
         */
        struct EnvironmentError {
            DWORD win32Code = ERROR_SUCCESS;
            LONG ntStatus = 0;
            std::wstring message;
            std::wstring context;

            [[nodiscard]] bool HasError() const noexcept {
                return win32Code != ERROR_SUCCESS || ntStatus != 0;
            }

            void Clear() noexcept {
                win32Code = ERROR_SUCCESS;
                ntStatus = 0;
                message.clear();
                context.clear();
            }

            [[nodiscard]] static EnvironmentError FromWin32(DWORD code, std::wstring_view ctx = {}) noexcept {
                EnvironmentError err;
                err.win32Code = code;
                err.context = ctx;
                return err;
            }
        };

        /**
         * @brief Detailed detection information
         */
        struct EnvironmentDetectedTechnique {
            /// @brief Technique identifier
            EnvironmentEvasionTechnique technique = EnvironmentEvasionTechnique::None;

            /// @brief Category
            EnvironmentEvasionCategory category = EnvironmentEvasionCategory::Unknown;

            /// @brief Severity
            EnvironmentEvasionSeverity severity = EnvironmentEvasionSeverity::Low;

            /// @brief Confidence (0.0 - 1.0)
            double confidence = 0.0;

            /// @brief Weight for scoring
            double weight = 1.0;

            /// @brief Detected value (e.g., the suspicious username)
            std::wstring detectedValue;

            /// @brief Expected/normal value (for comparison)
            std::wstring expectedValue;

            /// @brief Human-readable description
            std::wstring description;

            /// @brief Technical details
            std::wstring technicalDetails;

            /// @brief MITRE ATT&CK ID
            std::string mitreId;

            /// @brief Source of detection (registry path, file path, etc.)
            std::wstring source;

            /// @brief Detection timestamp
            std::chrono::system_clock::time_point detectionTime;

            /// @brief Constructor with defaults
            EnvironmentDetectedTechnique() = default;

            /// @brief Constructor with technique
            explicit EnvironmentDetectedTechnique(EnvironmentEvasionTechnique tech) noexcept
                : technique(tech)
                , category(GetTechniqueCategory(tech))
                , severity(GetDefaultTechniqueSeverity(tech))
                , mitreId(EnvironmentTechniqueToMitreId(tech))
                , detectionTime(std::chrono::system_clock::now())
            {
            }
        };

        /**
         * @brief Hardware fingerprint information
         */
        struct HardwareFingerprintInfo {
            /// @brief Number of logical processors
            uint32_t processorCount = 0;

            /// @brief Total physical RAM in bytes
            uint64_t totalRAM = 0;

            /// @brief Total disk space in bytes
            uint64_t totalDiskSpace = 0;

            /// @brief Number of disk drives
            uint32_t diskDriveCount = 0;

            /// @brief Screen width
            uint32_t screenWidth = 0;

            /// @brief Screen height
            uint32_t screenHeight = 0;

            /// @brief Number of monitors
            uint32_t monitorCount = 0;

            /// @brief CPU brand string
            std::wstring cpuBrand;

            /// @brief BIOS vendor
            std::wstring biosVendor;

            /// @brief System manufacturer
            std::wstring manufacturer;

            /// @brief System product name
            std::wstring productName;

            /// @brief Disk vendor strings
            std::vector<std::wstring> diskVendors;

            /// @brief Display adapter names
            std::vector<std::wstring> displayAdapters;

            /// @brief Hypervisor bit detected
            bool hypervisorDetected = false;

            /// @brief Hardware analysis successful
            bool valid = false;

            /// @brief List of VM indicators found
            std::vector<std::wstring> vmIndicators;
        };

        /**
         * @brief System identity information
         */
        struct SystemIdentityInfo {
            /// @brief Current username
            std::wstring username;

            /// @brief Computer name
            std::wstring computerName;

            /// @brief Domain name
            std::wstring domainName;

            /// @brief User SID
            std::wstring userSID;

            /// @brief OS product name
            std::wstring osProductName;

            /// @brief OS version
            std::wstring osVersion;

            /// @brief Install date
            std::chrono::system_clock::time_point installDate;

            /// @brief Last boot time
            std::chrono::system_clock::time_point lastBootTime;

            /// @brief System uptime in milliseconds
            uint64_t uptimeMs = 0;

            /// @brief Successful retrieval
            bool valid = false;
        };

        /**
         * @brief Network configuration information
         */
        struct NetworkConfigInfo {
            /// @brief Network adapters
            struct AdapterInfo {
                std::wstring name;
                std::wstring description;
                std::array<uint8_t, 6> macAddress{};
                std::wstring macAddressString;
                std::wstring ipAddress;
                std::wstring subnetMask;
                std::wstring defaultGateway;
                bool isVMAdapter = false;
                bool isEnabled = true;
            };

            std::vector<AdapterInfo> adapters;

            /// @brief DNS servers
            std::vector<std::wstring> dnsServers;

            /// @brief Total adapter count
            uint32_t adapterCount = 0;

            /// @brief VM adapters detected
            uint32_t vmAdapterCount = 0;

            /// @brief WiFi adapter present
            bool hasWiFi = false;

            /// @brief Successful retrieval
            bool valid = false;
        };

        /**
         * @brief User activity artifacts
         */
        struct UserActivityInfo {
            /// @brief Recent documents count
            size_t recentDocumentsCount = 0;

            /// @brief Recent programs count
            size_t recentProgramsCount = 0;

            /// @brief Desktop items count
            size_t desktopItemsCount = 0;

            /// @brief Downloads folder items count
            size_t downloadsCount = 0;

            /// @brief Documents folder items count
            size_t documentsCount = 0;

            /// @brief Typed URLs count
            size_t typedUrlsCount = 0;

            /// @brief Browser history count
            size_t browserHistoryCount = 0;

            /// @brief Browser bookmarks count
            size_t browserBookmarksCount = 0;

            /// @brief USB device history count
            size_t usbDeviceCount = 0;

            /// @brief Printer history count
            size_t printerCount = 0;

            /// @brief Installed programs count
            size_t installedProgramsCount = 0;

            /// @brief Scheduled tasks count
            size_t scheduledTasksCount = 0;

            /// @brief Windows event log entries
            size_t eventLogEntries = 0;

            /// @brief Appears to be a lived-in system
            bool isLivedInSystem = false;

            /// @brief Successful analysis
            bool valid = false;
        };

        /**
         * @brief Process environment artifacts
         */
        struct ProcessEnvironmentInfo {
            /// @brief Environment variables
            std::unordered_map<std::wstring, std::wstring> environmentVars;

            /// @brief Sandbox-related variables found
            std::vector<std::wstring> suspiciousVariables;

            /// @brief Current directory
            std::wstring currentDirectory;

            /// @brief Executable path
            std::wstring executablePath;

            /// @brief Process creation time
            std::chrono::system_clock::time_point creationTime;

            /// @brief File name matches hash pattern
            bool fileNameIsHash = false;

            /// @brief Hash type if detected
            std::wstring hashType;

            /// @brief Successful retrieval
            bool valid = false;
        };

        // ============================================================================
        // ANTI-DEBUG TECHNIQUE ENUMERATION (Enterprise Enhancement)
        // ============================================================================

        /**
         * @brief Specific anti-debugging technique identifiers for code analysis
         *
         * These are used by the Zydis integration to identify anti-debug patterns
         * in process code. Categorized by detection method.
         */
        enum class AntiDebugTechnique : uint32_t {
            None = 0x00000000,

            // ====================================================================
            // API-BASED DETECTION (0x01xxxxxx)
            // ====================================================================

            /// @brief IsDebuggerPresent() API call
            IsDebuggerPresent = 0x01000001,

            /// @brief CheckRemoteDebuggerPresent() API call
            CheckRemoteDebuggerPresent = 0x01000002,

            /// @brief NtQueryInformationProcess with ProcessDebugPort/ProcessDebugFlags
            NtQueryInformationProcess = 0x01000004,

            /// @brief NtQuerySystemInformation for debugger detection
            NtQuerySystemInformation = 0x01000008,

            /// @brief OutputDebugString for debugger detection
            OutputDebugString = 0x01000010,

            /// @brief NtClose with invalid handle
            NtCloseInvalidHandle = 0x01000020,

            /// @brief CloseHandle with protected handle
            CloseHandleProtected = 0x01000040,

            /// @brief NtQueryObject for debug object detection
            NtQueryObject = 0x01000080,

            /// @brief FindWindow for debugger windows
            FindWindowDebugger = 0x01000100,

            /// @brief EnumWindows for analysis tools
            EnumWindowsAnalysis = 0x01000200,

            // ====================================================================
            // TIMING-BASED DETECTION (0x02xxxxxx)
            // ====================================================================

            /// @brief RDTSC timing delta check
            RDTSCDelta = 0x02000001,

            /// @brief RDTSCP timing check
            RDTSCPDelta = 0x02000002,

            /// @brief GetTickCount/GetTickCount64 delta
            GetTickCountDelta = 0x02000004,

            /// @brief QueryPerformanceCounter delta
            QueryPerformanceCounterDelta = 0x02000008,

            /// @brief timeGetTime delta check
            TimeGetTimeDelta = 0x02000010,

            /// @brief CPUID timing measurement
            CPUIDTiming = 0x02000020,

            /// @brief Sleep timing verification
            SleepTiming = 0x02000040,

            /// @brief NtDelayExecution timing
            NtDelayExecutionTiming = 0x02000080,

            // ====================================================================
            // EXCEPTION-BASED DETECTION (0x03xxxxxx)
            // ====================================================================

            /// @brief INT 3 (breakpoint) exception
            INT3Exception = 0x03000001,

            /// @brief INT 2D (kernel debugger) exception
            INT2DException = 0x03000002,

            /// @brief INT 1 (single-step) exception
            INT1Exception = 0x03000004,

            /// @brief RaiseException for debugger detection
            RaiseException = 0x03000008,

            /// @brief SetUnhandledExceptionFilter manipulation
            UnhandledExceptionFilter = 0x03000010,

            /// @brief VEH (Vectored Exception Handler) tricks
            VectoredExceptionHandler = 0x03000020,

            /// @brief ICE breakpoint (0xF1)
            ICEBreakpoint = 0x03000040,

            /// @brief UD2 instruction for exception
            UD2Exception = 0x03000080,

            /// @brief BOUND instruction exception
            BOUNDException = 0x03000100,

            // ====================================================================
            // HARDWARE-BASED DETECTION (0x04xxxxxx)
            // ====================================================================

            /// @brief Hardware breakpoint detection (DR0-DR3)
            HardwareBreakpoints = 0x04000001,

            /// @brief Debug register (DR7) check
            DebugRegisters = 0x04000002,

            /// @brief Single-step flag detection
            SingleStep = 0x04000004,

            /// @brief Trap flag (TF) manipulation
            TrapFlag = 0x04000008,

            /// @brief GetThreadContext for DR check
            GetThreadContextDR = 0x04000010,

            /// @brief SetThreadContext to clear DRs
            SetThreadContextDR = 0x04000020,

            /// @brief NtGetContextThread for DR check
            NtGetContextThread = 0x04000040,

            /// @brief NtSetContextThread to modify DRs
            NtSetContextThread = 0x04000080,

            // ====================================================================
            // MEMORY/PEB-BASED DETECTION (0x05xxxxxx)
            // ====================================================================

            /// @brief PEB.BeingDebugged flag check
            PEBBeingDebugged = 0x05000001,

            /// @brief PEB.NtGlobalFlag check (heap flags)
            NtGlobalFlag = 0x05000002,

            /// @brief Process heap flags check
            HeapFlags = 0x05000004,

            /// @brief ProcessHeap.ForceFlags check
            HeapForceFlags = 0x05000008,

            /// @brief Heap tail checking detection
            HeapTailCheck = 0x05000010,

            /// @brief NtQueryInformationProcess ProcessBasicInformation
            ProcessBasicInformation = 0x05000020,

            /// @brief Memory breakpoint detection
            MemoryBreakpoints = 0x05000040,

            /// @brief Page guard detection
            PageGuardDetection = 0x05000080,

            // ====================================================================
            // ADVANCED TECHNIQUES (0x06xxxxxx)
            // ====================================================================

            /// @brief ThreadHideFromDebugger
            ThreadHideFromDebugger = 0x06000001,

            /// @brief NtSetInformationThread to hide
            NtSetInformationThread = 0x06000002,

            /// @brief BlockInput to prevent interaction
            BlockInput = 0x06000004,

            /// @brief Self-debugging (debug own process)
            SelfDebugging = 0x06000008,

            /// @brief Parent process check
            ParentProcessCheck = 0x06000010,

            /// @brief Debug object handle check
            DebugObjectHandle = 0x06000020,

            /// @brief NtCreateDebugObject detection
            NtCreateDebugObject = 0x06000040,

            /// @brief Process job object check
            ProcessJobCheck = 0x06000080,

            /// @brief TLS callback anti-debug
            TLSCallbackAntiDebug = 0x06000100,

            /// @brief Timing attack using WaitForDebugEvent
            WaitForDebugEvent = 0x06000200,

            /// @brief Process instrumentation callback
            InstrumentationCallback = 0x06000400,

            /// @brief Syscall-based detection
            DirectSyscall = 0x06000800,
        };

        // Bitwise operators for AntiDebugTechnique
        inline constexpr AntiDebugTechnique operator|(AntiDebugTechnique a, AntiDebugTechnique b) noexcept {
            return static_cast<AntiDebugTechnique>(static_cast<uint32_t>(a) | static_cast<uint32_t>(b));
        }

        inline constexpr AntiDebugTechnique operator&(AntiDebugTechnique a, AntiDebugTechnique b) noexcept {
            return static_cast<AntiDebugTechnique>(static_cast<uint32_t>(a) & static_cast<uint32_t>(b));
        }

        inline constexpr bool HasAntiDebugTechnique(AntiDebugTechnique flags, AntiDebugTechnique flag) noexcept {
            return (static_cast<uint32_t>(flags) & static_cast<uint32_t>(flag)) != 0;
        }

        // ============================================================================
        // ZYDIS INTEGRATION STRUCTURES (Enterprise Enhancement)
        // ============================================================================

        /**
         * @brief Disassembled instruction with anti-debug context
         */
        struct DisassembledInstruction {
            /// @brief Virtual address of instruction
            uint64_t address = 0;

            /// @brief Instruction length in bytes
            size_t length = 0;

            /// @brief Raw instruction bytes
            std::array<uint8_t, 15> bytes{};

            /// @brief Disassembled mnemonic (e.g., "RDTSC", "CPUID")
            std::string mnemonic;

            /// @brief Full instruction text
            std::string instructionText;

            /// @brief Is this a privileged instruction?
            bool isPrivileged = false;

            /// @brief Is this a timing-related instruction?
            bool isTimingInstruction = false;

            /// @brief Is this an anti-debug instruction?
            bool isAntiDebugInstruction = false;

            /// @brief Associated anti-debug technique (if any)
            AntiDebugTechnique technique = AntiDebugTechnique::None;

            /// @brief Confidence score (0.0 - 1.0)
            double confidence = 0.0;

            /// @brief Context (surrounding instructions summary)
            std::string context;
        };

        /**
         * @brief Result of Zydis-based code pattern analysis
         */
        struct EnvironmentCodeAnalysisResult {
            /// @brief Instructions identified as anti-debug
            std::vector<DisassembledInstruction> antiDebugInstructions;

            /// @brief Instructions identified as anti-sandbox
            std::vector<DisassembledInstruction> antiSandboxInstructions;

            /// @brief Total instructions analyzed
            size_t totalInstructionsAnalyzed = 0;

            /// @brief RDTSC instruction count
            size_t rdtscCount = 0;

            /// @brief RDTSCP instruction count
            size_t rdtscpCount = 0;

            /// @brief CPUID instruction count
            size_t cpuidCount = 0;

            /// @brief INT instruction count (INT 1, INT 2D, INT 3)
            size_t intCount = 0;

            /// @brief IN/OUT instruction count (I/O port access)
            size_t ioInstructionCount = 0;

            /// @brief Debug API call count
            size_t debugApiCount = 0;

            /// @brief Suspicious call count (to known anti-debug APIs)
            size_t suspiciousCallCount = 0;

            /// @brief SIDT/SGDT/SLDT/STR instruction count
            size_t descriptorTableAccessCount = 0;

            /// @brief Has timing loop pattern detected
            bool hasTimingLoop = false;

            /// @brief Has exception-based anti-debug pattern
            bool hasExceptionAbuse = false;

            /// @brief Has PEB/TEB access pattern
            bool hasPEBAccess = false;

            /// @brief Has debug register access pattern
            bool hasDebugRegisterAccess = false;

            /// @brief Has self-modifying code detected
            bool hasSelfModifyingCode = false;

            /// @brief Combined anti-debug techniques detected
            AntiDebugTechnique detectedTechniques = AntiDebugTechnique::None;

            /// @brief Overall evasion score from code analysis (0.0 - 100.0)
            float evasionScore = 0.0f;

            /// @brief Analysis was successful
            bool valid = false;

            /// @brief Error message if analysis failed
            std::wstring errorMessage;

            /// @brief Analysis duration in microseconds
            uint64_t analysisDurationUs = 0;
        };

        // ============================================================================
        // PEPARSER INTEGRATION STRUCTURES (Enterprise Enhancement)
        // ============================================================================

        /**
         * @brief Suspicious import for anti-debug detection
         */
        struct SuspiciousAntiDebugImport {
            /// @brief DLL name (e.g., "kernel32.dll", "ntdll.dll")
            std::string dllName;

            /// @brief Function name (e.g., "IsDebuggerPresent")
            std::string functionName;

            /// @brief Import address table entry RVA
            uint32_t iatRva = 0;

            /// @brief Associated anti-debug technique
            AntiDebugTechnique technique = AntiDebugTechnique::None;

            /// @brief Risk level (0.0 - 1.0)
            double riskLevel = 0.0;

            /// @brief Description of why this import is suspicious
            std::string description;
        };

        /**
         * @brief Suspicious import for anti-sandbox detection
         */
        struct SuspiciousAntiSandboxImport {
            /// @brief DLL name
            std::string dllName;

            /// @brief Function name
            std::string functionName;

            /// @brief Import address table entry RVA
            uint32_t iatRva = 0;

            /// @brief Associated environment technique
            EnvironmentEvasionTechnique technique = EnvironmentEvasionTechnique::None;

            /// @brief Risk level (0.0 - 1.0)
            double riskLevel = 0.0;

            /// @brief Description
            std::string description;
        };

        /**
         * @brief Result of PE import/section analysis
         */
        struct EnvironmentPEAnalysisResult {
            /// @brief Anti-debug imports found
            std::vector<SuspiciousAntiDebugImport> antiDebugImports;

            /// @brief Anti-sandbox imports found
            std::vector<SuspiciousAntiSandboxImport> antiSandboxImports;

            /// @brief IsDebuggerPresent import count
            size_t isDebuggerPresentCount = 0;

            /// @brief CheckRemoteDebuggerPresent import count
            size_t checkRemoteDebuggerPresentCount = 0;

            /// @brief NtQueryInformationProcess import count
            size_t ntQueryInformationProcessCount = 0;

            /// @brief NtQuerySystemInformation import count
            size_t ntQuerySystemInformationCount = 0;

            /// @brief GetTickCount/GetTickCount64 import count
            size_t getTickCountCount = 0;

            /// @brief QueryPerformanceCounter import count
            size_t queryPerformanceCounterCount = 0;

            /// @brief GetSystemInfo import count
            size_t getSystemInfoCount = 0;

            /// @brief Total suspicious import count
            size_t totalSuspiciousImports = 0;

            /// @brief Has TLS callbacks
            bool hasTLSCallbacks = false;

            /// @brief Number of TLS callbacks
            size_t tlsCallbackCount = 0;

            /// @brief Has anti-debug section (suspicious section names)
            bool hasAntiDebugSection = false;

            /// @brief Suspicious section names found
            std::vector<std::string> suspiciousSectionNames;

            /// @brief Has executable .data section
            bool hasExecutableDataSection = false;

            /// @brief Has writable .text section
            bool hasWritableCodeSection = false;

            /// @brief Entry point is outside .text section
            bool entryPointOutsideCode = false;

            /// @brief Has overlay data
            bool hasOverlay = false;

            /// @brief Overlay size if present
            size_t overlaySize = 0;

            /// @brief Combined anti-debug techniques detected from imports
            AntiDebugTechnique detectedTechniques = AntiDebugTechnique::None;

            /// @brief Overall risk score (0.0 - 100.0)
            float riskScore = 0.0f;

            /// @brief Analysis was successful
            bool valid = false;

            /// @brief Error message if analysis failed
            std::wstring errorMessage;
        };

        // ============================================================================
        // EXTENDED ANALYSIS CONFIGURATION (Enterprise Enhancement)
        // ============================================================================

        /**
         * @brief Extended configuration for Zydis/PEParser analysis
         */
        struct ExtendedEnvironmentAnalysisConfig {
            /// @brief Enable Zydis disassembly analysis
            bool enableZydisAnalysis = true;

            /// @brief Enable PE import/section analysis
            bool enablePEAnalysis = true;

            /// @brief Enable advanced timing analysis (assembly-level)
            bool enableTimingAnalysis = true;

            /// @brief Enable hardware breakpoint detection
            bool enableHardwareBreakpointDetection = true;

            /// @brief Enable PEB/TEB flag detection
            bool enablePEBFlagDetection = true;

            /// @brief Enable exception-based detection
            bool enableExceptionDetection = true;

            /// @brief Maximum instructions to analyze per region
            size_t maxInstructionsToAnalyze = 50000;

            /// @brief Maximum code regions to scan
            size_t maxCodeRegions = 64;

            /// @brief Maximum import entries to analyze
            size_t maxImportsToAnalyze = 10000;

            /// @brief Analysis timeout in milliseconds
            uint32_t timeoutMs = 60000;

            /// @brief Minimum instruction confidence to report
            double minInstructionConfidence = 0.5;

            /// @brief Minimum import risk level to report
            double minImportRiskLevel = 0.3;

            /// @brief Follow indirect calls for analysis
            bool followIndirectCalls = false;

            /// @brief Analyze only entry point region
            bool analyzeEntryPointOnly = false;

            /// @brief Include API hook detection
            bool detectAPIHooks = true;

            /// @brief Include inline hook detection
            bool detectInlineHooks = true;
        };

        /**
         * @brief Combined extended analysis result
         */
        struct ExtendedEnvironmentAnalysisResult {
            /// @brief Code analysis result (Zydis)
            EnvironmentCodeAnalysisResult codeAnalysis;

            /// @brief PE analysis result (PEParser)
            EnvironmentPEAnalysisResult peAnalysis;

            /// @brief Descriptor table analysis results
            struct DescriptorTableInfo {
                uint64_t idtBase = 0;
                uint16_t idtLimit = 0;
                uint64_t gdtBase = 0;
                uint16_t gdtLimit = 0;
                uint16_t ldtSelector = 0;
                uint16_t trSelector = 0;
                bool idtRelocated = false;  ///< IDT at unusual address
                bool gdtRelocated = false;  ///< GDT at unusual address
                bool valid = false;
            } descriptorTables;

            /// @brief Debug detection results
            struct DebugDetectionInfo {
                bool beingDebugged = false;             ///< PEB.BeingDebugged
                uint32_t ntGlobalFlag = 0;              ///< PEB.NtGlobalFlag
                uint32_t heapFlags = 0;                 ///< Process heap flags
                bool hardwareBreakpointsDetected = false;
                bool singleStepDetected = false;
                bool trapFlagSet = false;
                uint64_t dr0 = 0, dr1 = 0, dr2 = 0, dr3 = 0, dr6 = 0, dr7 = 0;
                bool valid = false;
            } debugDetection;

            /// @brief Timing analysis results
            struct TimingAnalysisInfo {
                uint64_t rdtscDelta = 0;            ///< RDTSC timing delta
                uint64_t rdtscpDelta = 0;           ///< RDTSCP timing delta
                uint64_t cpuidTiming = 0;           ///< CPUID instruction timing
                uint64_t exceptionTiming = 0;       ///< Exception handling timing
                bool timingAnomalyDetected = false; ///< Abnormal timing detected
                double averageCyclesPerMeasurement = 0.0;
                bool valid = false;
            } timingAnalysis;

            /// @brief Combined score from all analyses (0.0 - 100.0)
            double combinedEvasionScore = 0.0;

            /// @brief Analysis completed successfully
            bool valid = false;

            /// @brief Total analysis duration in milliseconds
            uint64_t totalDurationMs = 0;
        };

        /**
         * @brief File naming analysis
         */
        struct FileNamingInfo {
            /// @brief Executable path
            std::wstring executablePath;

            /// @brief File name only
            std::wstring fileName;

            /// @brief File name without extension
            std::wstring baseName;

            /// @brief File extension
            std::wstring extension;

            /// @brief Directory path
            std::wstring directoryPath;

            /// @brief File name looks like MD5 hash
            bool isMD5 = false;

            /// @brief File name looks like SHA1 hash
            bool isSHA1 = false;

            /// @brief File name looks like SHA256 hash
            bool isSHA256 = false;

            /// @brief File name is generic (sample, malware, etc.)
            bool isGeneric = false;

            /// @brief File name appears randomly generated
            bool isRandomPattern = false;

            /// @brief Has multiple extensions
            bool hasMultipleExtensions = false;

            /// @brief In suspicious location
            bool inSuspiciousLocation = false;

            /// @brief Contains analysis keywords
            bool containsAnalysisKeywords = false;

            /// @brief Successful analysis
            bool valid = false;
        };

        /**
         * @brief Analysis configuration
         */
        struct EnvironmentAnalysisConfig {
            /// @brief Analysis depth
            EnvironmentAnalysisDepth depth = EnvironmentAnalysisDepth::Standard;

            /// @brief Analysis flags
            EnvironmentAnalysisFlags flags = EnvironmentAnalysisFlags::Default;

            /// @brief Timeout in milliseconds
            uint32_t timeoutMs = EnvironmentConstants::DEFAULT_SCAN_TIMEOUT_MS;

            /// @brief Enable caching
            bool enableCaching = true;

            /// @brief Cache TTL in seconds
            uint32_t cacheTtlSeconds = EnvironmentConstants::RESULT_CACHE_TTL_SECONDS;

            /// @brief Custom blacklisted usernames (additional)
            std::vector<std::wstring> customBlacklistedUsernames;

            /// @brief Custom blacklisted computer names (additional)
            std::vector<std::wstring> customBlacklistedComputerNames;

            /// @brief Custom analysis tool process names (additional)
            std::vector<std::wstring> customAnalysisToolProcesses;

            /// @brief Minimum confidence threshold
            double minConfidenceThreshold = 0.3;

            /// @brief Include system-wide environment scan
            bool includeSystemEnvironment = true;

            /// @brief Skip current process
            bool skipCurrentProcess = false;
        };

        /**
         * @brief Comprehensive analysis result
         */
        struct EnvironmentEvasionResult {
            // ========================================================================
            // IDENTIFICATION
            // ========================================================================

            /// @brief Target process ID (0 for system-wide)
            uint32_t targetPid = 0;

            /// @brief Target process name
            std::wstring processName;

            /// @brief Target process path
            std::wstring processPath;

            // ========================================================================
            // DETECTION SUMMARY
            // ========================================================================

            /// @brief Were evasion techniques detected?
            bool isEvasive = false;

            /// @brief Overall evasion score (0.0 - 100.0)
            double evasionScore = 0.0;

            /// @brief Highest severity detected
            EnvironmentEvasionSeverity maxSeverity = EnvironmentEvasionSeverity::Low;

            /// @brief Total techniques detected
            uint32_t totalDetections = 0;

            /// @brief Categories with detections (bitfield)
            uint32_t detectedCategories = 0;

            // ========================================================================
            // DETAILED FINDINGS
            // ========================================================================

            /// @brief All detected techniques
            std::vector<EnvironmentDetectedTechnique> detectedTechniques;

            /// @brief Hardware fingerprint
            HardwareFingerprintInfo hardwareInfo;

            /// @brief System identity
            SystemIdentityInfo identityInfo;

            /// @brief Network configuration
            NetworkConfigInfo networkInfo;

            /// @brief User activity artifacts
            UserActivityInfo activityInfo;

            /// @brief Process environment
            ProcessEnvironmentInfo processEnvInfo;

            /// @brief File naming analysis
            FileNamingInfo fileNamingInfo;

            // ========================================================================
            // VM/SANDBOX INDICATORS
            // ========================================================================

            /// @brief VM indicators found (strings)
            std::vector<std::wstring> vmIndicators;

            /// @brief Sandbox indicators found (strings)
            std::vector<std::wstring> sandboxIndicators;

            /// @brief Analysis tool indicators
            std::vector<std::wstring> analysisToolIndicators;

            // ========================================================================
            // STATISTICS
            // ========================================================================

            /// @brief Categories checked
            uint32_t categoriesChecked = 0;

            /// @brief Techniques checked
            uint32_t techniquesChecked = 0;

            /// @brief Registry keys enumerated
            uint32_t registryKeysChecked = 0;

            /// @brief Files checked
            uint32_t filesChecked = 0;

            /// @brief Processes enumerated
            uint32_t processesChecked = 0;

            // ========================================================================
            // TIMING & METADATA
            // ========================================================================

            /// @brief Analysis start time
            std::chrono::system_clock::time_point analysisStartTime;

            /// @brief Analysis end time
            std::chrono::system_clock::time_point analysisEndTime;

            /// @brief Total duration in milliseconds
            uint64_t analysisDurationMs = 0;

            /// @brief Configuration used
            EnvironmentAnalysisConfig config;

            /// @brief Errors encountered
            std::vector<EnvironmentError> errors;

            /// @brief Analysis completed successfully
            bool analysisComplete = false;

            /// @brief From cache
            bool fromCache = false;

            // ========================================================================
            // METHODS
            // ========================================================================

            /**
             * @brief Check if category was detected
             */
            [[nodiscard]] bool HasCategory(EnvironmentEvasionCategory category) const noexcept {
                return (detectedCategories & (1u << static_cast<uint32_t>(category))) != 0;
            }

            /**
             * @brief Check if specific technique was detected
             */
            [[nodiscard]] bool HasTechnique(EnvironmentEvasionTechnique technique) const noexcept {
                for (const auto& det : detectedTechniques) {
                    if (det.technique == technique) return true;
                }
                return false;
            }

            /**
             * @brief Get count by category
             */
            [[nodiscard]] size_t GetCategoryCount(EnvironmentEvasionCategory category) const noexcept {
                size_t count = 0;
                for (const auto& det : detectedTechniques) {
                    if (det.category == category) ++count;
                }
                return count;
            }

            /**
             * @brief Get detections by minimum severity
             */
            [[nodiscard]] std::vector<const EnvironmentDetectedTechnique*> GetBySeverity(
                EnvironmentEvasionSeverity minSeverity
            ) const noexcept {
                std::vector<const EnvironmentDetectedTechnique*> filtered;
                for (const auto& det : detectedTechniques) {
                    if (det.severity >= minSeverity) {
                        filtered.push_back(&det);
                    }
                }
                return filtered;
            }

            /**
             * @brief Clear all data
             */
            void Clear() noexcept {
                targetPid = 0;
                processName.clear();
                processPath.clear();
                isEvasive = false;
                evasionScore = 0.0;
                maxSeverity = EnvironmentEvasionSeverity::Low;
                totalDetections = 0;
                detectedCategories = 0;
                detectedTechniques.clear();
                hardwareInfo = {};
                identityInfo = {};
                networkInfo = {};
                activityInfo = {};
                processEnvInfo = {};
                fileNamingInfo = {};
                vmIndicators.clear();
                sandboxIndicators.clear();
                analysisToolIndicators.clear();
                categoriesChecked = 0;
                techniquesChecked = 0;
                registryKeysChecked = 0;
                filesChecked = 0;
                processesChecked = 0;
                analysisStartTime = {};
                analysisEndTime = {};
                analysisDurationMs = 0;
                config = {};
                errors.clear();
                analysisComplete = false;
                fromCache = false;
            }
        };

        /**
         * @brief Batch analysis result
         */
        struct EnvironmentBatchResult {
            /// @brief Individual results
            std::vector<EnvironmentEvasionResult> results;

            /// @brief Total processes analyzed
            uint32_t totalProcesses = 0;

            /// @brief Evasive processes found
            uint32_t evasiveProcesses = 0;

            /// @brief Failed analyses
            uint32_t failedProcesses = 0;

            /// @brief Total duration in milliseconds
            uint64_t totalDurationMs = 0;

            /// @brief Start time
            std::chrono::system_clock::time_point startTime;

            /// @brief End time
            std::chrono::system_clock::time_point endTime;
        };

        /**
         * @brief Progress callback
         */
        using EnvironmentProgressCallback = std::function<void(
            uint32_t pid,
            EnvironmentEvasionCategory currentCategory,
            uint32_t techniquesChecked,
            uint32_t totalTechniques
            )>;

        /**
         * @brief Detection callback
         */
        using EnvironmentDetectionCallback = std::function<void(
            uint32_t pid,
            const EnvironmentDetectedTechnique& detection
            )>;

        // ============================================================================
        // MAIN DETECTOR CLASS
        // ============================================================================

        /**
         * @brief Enterprise-grade environment evasion detection engine
         *
         * Detects malware that checks environmental characteristics to identify
         * sandbox/analysis environments. Thread-safe for concurrent analysis.
         *
         * Usage example:
         * @code
         *     auto detector = std::make_unique<EnvironmentEvasionDetector>();
         *     if (!detector->Initialize()) {
         *         // Handle failure
         *     }
         *
         *     EnvironmentAnalysisConfig config;
         *     config.depth = EnvironmentAnalysisDepth::Deep;
         *
         *     // Analyze specific process
         *     auto result = detector->AnalyzeProcess(targetPid, config);
         *
         *     // Or analyze system environment
         *     auto sysResult = detector->AnalyzeSystemEnvironment(config);
         *
         *     if (result.isEvasive) {
         *         for (const auto& tech : result.detectedTechniques) {
         *             // Process detection
         *         }
         *     }
         * @endcode
         */
        class EnvironmentEvasionDetector {
        public:
            // ========================================================================
            // CONSTRUCTION & LIFECYCLE
            // ========================================================================

            /**
             * @brief Default constructor
             */
            EnvironmentEvasionDetector() noexcept;

            /**
             * @brief Constructor with threat intel
             * @param threatIntel Optional threat intel store for correlation
             */
            explicit EnvironmentEvasionDetector(
                std::shared_ptr<ThreatIntel::ThreatIntelStore> threatIntel
            ) noexcept;

            /**
             * @brief Destructor
             */
            ~EnvironmentEvasionDetector();

            // Non-copyable, movable
            EnvironmentEvasionDetector(const EnvironmentEvasionDetector&) = delete;
            EnvironmentEvasionDetector& operator=(const EnvironmentEvasionDetector&) = delete;
            EnvironmentEvasionDetector(EnvironmentEvasionDetector&&) noexcept;
            EnvironmentEvasionDetector& operator=(EnvironmentEvasionDetector&&) noexcept;

            // ========================================================================
            // INITIALIZATION
            // ========================================================================

            /**
             * @brief Initialize the detector
             * @param err Optional error output
             * @return true on success
             */
            [[nodiscard]] bool Initialize(EnvironmentError* err = nullptr) noexcept;

            /**
             * @brief Shutdown and release resources
             */
            void Shutdown() noexcept;

            /**
             * @brief Check if initialized
             */
            [[nodiscard]] bool IsInitialized() const noexcept;

            // ========================================================================
            // PROCESS-SPECIFIC ANALYSIS
            // ========================================================================

            /**
             * @brief Analyze process for environment evasion
             * @param processId Target process ID
             * @param config Analysis configuration
             * @param err Optional error output
             * @return Analysis result
             */
            [[nodiscard]] EnvironmentEvasionResult AnalyzeProcess(
                uint32_t processId,
                const EnvironmentAnalysisConfig& config = EnvironmentAnalysisConfig{},
                EnvironmentError* err = nullptr
            ) noexcept;

            /**
             * @brief Analyze process using handle
             * @param hProcess Process handle
             * @param config Analysis configuration
             * @param err Optional error output
             * @return Analysis result
             */
            [[nodiscard]] EnvironmentEvasionResult AnalyzeProcess(
                HANDLE hProcess,
                const EnvironmentAnalysisConfig& config = EnvironmentAnalysisConfig{},
                EnvironmentError* err = nullptr
            ) noexcept;

            // ========================================================================
            // SYSTEM-WIDE ANALYSIS
            // ========================================================================

            /**
             * @brief Analyze system environment (not process-specific)
             * @param config Analysis configuration
             * @param err Optional error output
             * @return Analysis result
             */
            [[nodiscard]] EnvironmentEvasionResult AnalyzeSystemEnvironment(
                const EnvironmentAnalysisConfig& config = EnvironmentAnalysisConfig{},
                EnvironmentError* err = nullptr
            ) noexcept;

            // ========================================================================
            // BATCH ANALYSIS
            // ========================================================================

            /**
             * @brief Analyze multiple processes
             * @param processIds Process IDs to analyze
             * @param config Analysis configuration
             * @param progressCallback Optional progress callback
             * @param err Optional error output
             * @return Batch result
             */
            [[nodiscard]] EnvironmentBatchResult AnalyzeProcesses(
                const std::vector<uint32_t>& processIds,
                const EnvironmentAnalysisConfig& config = EnvironmentAnalysisConfig{},
                EnvironmentProgressCallback progressCallback = nullptr,
                EnvironmentError* err = nullptr
            ) noexcept;

            /**
             * @brief Analyze all running processes
             * @param config Analysis configuration
             * @param progressCallback Optional progress callback
             * @param err Optional error output
             * @return Batch result
             */
            [[nodiscard]] EnvironmentBatchResult AnalyzeAllProcesses(
                const EnvironmentAnalysisConfig& config = EnvironmentAnalysisConfig{},
                EnvironmentProgressCallback progressCallback = nullptr,
                EnvironmentError* err = nullptr
            ) noexcept;

            // ========================================================================
            // SPECIFIC CATEGORY CHECKS
            // ========================================================================

            /**
             * @brief Check username and hostname against blacklists
             * @param outDetections Output detections
             * @param err Optional error output
             * @return true if blacklisted names found
             */
            [[nodiscard]] bool CheckBlacklistedNames(
                std::vector<EnvironmentDetectedTechnique>& outDetections,
                EnvironmentError* err = nullptr
            ) noexcept;

            /**
             * @brief Check hardware fingerprint for VM indicators
             * @param outHardwareInfo Output hardware info
             * @param outDetections Output detections
             * @param err Optional error output
             * @return true if VM indicators found
             */
            [[nodiscard]] bool CheckHardwareFingerprint(
                HardwareFingerprintInfo& outHardwareInfo,
                std::vector<EnvironmentDetectedTechnique>& outDetections,
                EnvironmentError* err = nullptr
            ) noexcept;

            /**
             * @brief Check file system for VM/sandbox artifacts
             * @param outDetections Output detections
             * @param err Optional error output
             * @return true if artifacts found
             */
            [[nodiscard]] bool CheckFileSystemArtifacts(
                std::vector<EnvironmentDetectedTechnique>& outDetections,
                EnvironmentError* err = nullptr
            ) noexcept;

            /**
             * @brief Check registry for VM/sandbox keys
             * @param outDetections Output detections
             * @param err Optional error output
             * @return true if VM keys found
             */
            [[nodiscard]] bool CheckRegistryArtifacts(
                std::vector<EnvironmentDetectedTechnique>& outDetections,
                EnvironmentError* err = nullptr
            ) noexcept;

            /**
             * @brief Check user activity artifacts
             * @param outActivityInfo Output activity info
             * @param outDetections Output detections
             * @param err Optional error output
             * @return true if lack of activity detected
             */
            [[nodiscard]] bool CheckUserActivity(
                UserActivityInfo& outActivityInfo,
                std::vector<EnvironmentDetectedTechnique>& outDetections,
                EnvironmentError* err = nullptr
            ) noexcept;

            /**
             * @brief Check network configuration for VM indicators
             * @param outNetworkInfo Output network info
             * @param outDetections Output detections
             * @param err Optional error output
             * @return true if VM network found
             */
            [[nodiscard]] bool CheckNetworkConfiguration(
                NetworkConfigInfo& outNetworkInfo,
                std::vector<EnvironmentDetectedTechnique>& outDetections,
                EnvironmentError* err = nullptr
            ) noexcept;

            /**
             * @brief Check running processes for analysis tools
             * @param outDetections Output detections
             * @param err Optional error output
             * @return true if analysis tools found
             */
            [[nodiscard]] bool CheckRunningProcesses(
                std::vector<EnvironmentDetectedTechnique>& outDetections,
                EnvironmentError* err = nullptr
            ) noexcept;

            /**
             * @brief Check system timing (uptime, install date)
             * @param outDetections Output detections
             * @param err Optional error output
             * @return true if suspicious timing found
             */
            [[nodiscard]] bool CheckTimingIndicators(
                std::vector<EnvironmentDetectedTechnique>& outDetections,
                EnvironmentError* err = nullptr
            ) noexcept;

            /**
             * @brief Check process environment variables
             * @param processId Process ID
             * @param outEnvInfo Output environment info
             * @param outDetections Output detections
             * @param err Optional error output
             * @return true if suspicious variables found
             */
            [[nodiscard]] bool CheckEnvironmentVariables(
                uint32_t processId,
                ProcessEnvironmentInfo& outEnvInfo,
                std::vector<EnvironmentDetectedTechnique>& outDetections,
                EnvironmentError* err = nullptr
            ) noexcept;

            /**
             * @brief Check display configuration
             * @param outDetections Output detections
             * @param err Optional error output
             * @return true if VM display detected
             */
            [[nodiscard]] bool CheckDisplayConfiguration(
                std::vector<EnvironmentDetectedTechnique>& outDetections,
                EnvironmentError* err = nullptr
            ) noexcept;

            /**
             * @brief Check browser artifacts
             * @param outDetections Output detections
             * @param err Optional error output
             * @return true if lack of artifacts detected
             */
            [[nodiscard]] bool CheckBrowserArtifacts(
                std::vector<EnvironmentDetectedTechnique>& outDetections,
                EnvironmentError* err = nullptr
            ) noexcept;

            /**
             * @brief Check peripheral device history
             * @param outDetections Output detections
             * @param err Optional error output
             * @return true if lack of peripherals detected
             */
            [[nodiscard]] bool CheckPeripheralHistory(
                std::vector<EnvironmentDetectedTechnique>& outDetections,
                EnvironmentError* err = nullptr
            ) noexcept;

            /**
             * @brief Check if file name is hash-based or suspicious
             * @param processId Process ID
             * @param outNamingInfo Output naming info
             * @param outDetections Output detections
             * @param err Optional error output
             * @return true if suspicious naming found
             */
            [[nodiscard]] bool CheckFileNaming(
                uint32_t processId,
                FileNamingInfo& outNamingInfo,
                std::vector<EnvironmentDetectedTechnique>& outDetections,
                EnvironmentError* err = nullptr
            ) noexcept;

            /**
             * @brief Check if file name matches its hash
             * @param filePath File path to check
             * @param outDetections Output detections
             * @param err Optional error output
             * @return true if file name matches hash
             */
            [[nodiscard]] bool DetectFileNameHashMatch(
                std::wstring_view filePath,
                std::vector<EnvironmentDetectedTechnique>& outDetections,
                EnvironmentError* err = nullptr
            ) noexcept;

            // ========================================================================
            // REAL-TIME DETECTION
            // ========================================================================

            /**
             * @brief Set detection callback
             * @param callback Callback function
             */
            void SetDetectionCallback(EnvironmentDetectionCallback callback) noexcept;

            /**
             * @brief Clear detection callback
             */
            void ClearDetectionCallback() noexcept;

            // ========================================================================
            // CACHING
            // ========================================================================

            /**
             * @brief Get cached result
             * @param processId Process ID (0 for system)
             * @return Cached result if available
             */
            [[nodiscard]] std::optional<EnvironmentEvasionResult> GetCachedResult(
                uint32_t processId
            ) const noexcept;

            /**
             * @brief Invalidate cache entry
             * @param processId Process ID (0 for system)
             */
            void InvalidateCache(uint32_t processId) noexcept;

            /**
             * @brief Clear all cache entries
             */
            void ClearCache() noexcept;

            /**
             * @brief Get cache size
             */
            [[nodiscard]] size_t GetCacheSize() const noexcept;

            // ========================================================================
           // ADVANCED FEATURES
           // ========================================================================
            /**
             * @brief Check advanced CPUID indicators
             * @param outDetections Output detections
             * @param err Optional error output
             * @return true if advanced CPUID anomalies found
             */
            [[nodiscard]] bool CheckAdvancedCPUIDIndicators(
                std::vector<EnvironmentDetectedTechnique>& outDetections,
                EnvironmentError* err
            ) noexcept;

            /**
             * @brief Check API hooking indicators
             * @param outDetections Output detections
             * @param err Optional error output
             * @return true if API hooking detected
             */
            [[nodiscard]] bool CheckAPIHookingIndicators(
                std::vector<EnvironmentDetectedTechnique>& outDetections,
                EnvironmentError* err
            ) noexcept;

			/**
             * @brief Analyze process PE structure for evasion indicators
             * @param processId Process ID
             * @param outDetections Output detections
             * @param err Optional error output
             * @return true if PE evasion indicators found
             */
            [[nodiscard]] bool AnalyzeProcessPeForEvasion(
                uint32_t processId,
                std::vector<EnvironmentDetectedTechnique>& outDetections,
                EnvironmentError* err
            ) noexcept;


            // ========================================================================
            // CONFIGURATION
            // ========================================================================

            /**
             * @brief Set threat intel store
             * @param threatIntel Threat intel store instance
             */
            void SetThreatIntelStore(
                std::shared_ptr<ThreatIntel::ThreatIntelStore> threatIntel
            ) noexcept;

            /**
             * @brief Add custom blacklisted username
             * @param username Username to add
             */
            void AddBlacklistedUsername(std::wstring_view username) noexcept;

            /**
             * @brief Add custom blacklisted computer name
             * @param name Computer name to add
             */
            void AddBlacklistedComputerName(std::wstring_view name) noexcept;

            /**
             * @brief Add custom analysis tool process name
             * @param processName Process name to add
             */
            void AddAnalysisToolProcess(std::wstring_view processName) noexcept;

            /**
             * @brief Clear custom lists
             */
            void ClearCustomLists() noexcept;

            // ========================================================================
            // STATISTICS
            // ========================================================================

            /**
             * @brief Detector statistics
             */
            struct Statistics {
                /// @brief Total analyses
                std::atomic<uint64_t> totalAnalyses{ 0 };

                /// @brief Evasive processes found
                std::atomic<uint64_t> evasiveProcesses{ 0 };

                /// @brief Total detections
                std::atomic<uint64_t> totalDetections{ 0 };

                /// @brief Cache hits
                std::atomic<uint64_t> cacheHits{ 0 };

                /// @brief Cache misses
                std::atomic<uint64_t> cacheMisses{ 0 };

                /// @brief Analysis errors
                std::atomic<uint64_t> analysisErrors{ 0 };

                /// @brief Total analysis time (microseconds)
                std::atomic<uint64_t> totalAnalysisTimeUs{ 0 };

                /// @brief Per-category detections
                std::array<std::atomic<uint64_t>, 16> categoryDetections{};

                void Reset() noexcept {
                    totalAnalyses = 0;
                    evasiveProcesses = 0;
                    totalDetections = 0;
                    cacheHits = 0;
                    cacheMisses = 0;
                    analysisErrors = 0;
                    totalAnalysisTimeUs = 0;
                    for (auto& cat : categoryDetections) {
                        cat = 0;
                    }
                }
            };

            /**
             * @brief Get statistics
             */
            [[nodiscard]] const Statistics& GetStatistics() const noexcept;

            /**
             * @brief Reset statistics
             */
            void ResetStatistics() noexcept;

        private:
            // ========================================================================
            // IMPLEMENTATION
            // ========================================================================

            class Impl;
            std::unique_ptr<Impl> m_impl;

            // ========================================================================
            // INTERNAL METHODS
            // ========================================================================

            void AnalyzeProcessInternal(
                HANDLE hProcess,
                uint32_t processId,
                const EnvironmentAnalysisConfig& config,
                EnvironmentEvasionResult& result
            ) noexcept;

            void AnalyzeSystemInternal(
                const EnvironmentAnalysisConfig& config,
                EnvironmentEvasionResult& result
            ) noexcept;

            void CollectHardwareInfo(
                HardwareFingerprintInfo& info
            ) noexcept;

            void CollectIdentityInfo(
                SystemIdentityInfo& info
            ) noexcept;

            void CollectNetworkInfo(
                NetworkConfigInfo& info
            ) noexcept;

            void CollectUserActivityInfo(
                UserActivityInfo& info
            ) noexcept;

            void AnalyzeFileNaming(
                std::wstring_view filePath,
                FileNamingInfo& info
            ) noexcept;

            void CalculateEvasionScore(
                EnvironmentEvasionResult& result
            ) noexcept;

            void AddDetection(
                EnvironmentEvasionResult& result,
                EnvironmentDetectedTechnique detection
            ) noexcept;

            [[nodiscard]] bool IsBlacklistedUsername(std::wstring_view name) const noexcept;
            [[nodiscard]] bool IsBlacklistedComputerName(std::wstring_view name) const noexcept;
            [[nodiscard]] bool IsAnalysisToolProcess(std::wstring_view name) const noexcept;
            [[nodiscard]] bool IsVMMACAddress(const std::array<uint8_t, 6>& mac) const noexcept;
            [[nodiscard]] bool LooksLikeHash(std::wstring_view name, std::wstring& hashType) const noexcept;

            void UpdateCache(
                uint32_t processId,
                const EnvironmentEvasionResult& result
            ) noexcept;
        };

        /**
         * @brief Helper class for building detections
         */
        class EnvironmentDetectionBuilder {
        public:
            EnvironmentDetectionBuilder() = default;

            EnvironmentDetectionBuilder& Technique(EnvironmentEvasionTechnique tech) noexcept {
                m_detection.technique = tech;
                m_detection.category = GetTechniqueCategory(tech);
                m_detection.severity = GetDefaultTechniqueSeverity(tech);
                m_detection.mitreId = EnvironmentTechniqueToMitreId(tech);
                return *this;
            }

            EnvironmentDetectionBuilder& Confidence(double conf) noexcept {
                m_detection.confidence = conf;
                return *this;
            }

            EnvironmentDetectionBuilder& DetectedValue(std::wstring_view value) noexcept {
                m_detection.detectedValue = value;
                return *this;
            }

            EnvironmentDetectionBuilder& ExpectedValue(std::wstring_view value) noexcept {
                m_detection.expectedValue = value;
                return *this;
            }

            EnvironmentDetectionBuilder& Description(std::wstring_view desc) noexcept {
                m_detection.description = desc;
                return *this;
            }

            EnvironmentDetectionBuilder& Source(std::wstring_view src) noexcept {
                m_detection.source = src;
                return *this;
            }

            EnvironmentDetectionBuilder& Severity(EnvironmentEvasionSeverity sev) noexcept {
                m_detection.severity = sev;
                return *this;
            }

            [[nodiscard]] EnvironmentDetectedTechnique Build() noexcept {
                m_detection.detectionTime = std::chrono::system_clock::now();
                return std::move(m_detection);
            }

        private:
            EnvironmentDetectedTechnique m_detection;
        };

    } // namespace AntiEvasion
} // namespace ShadowStrike