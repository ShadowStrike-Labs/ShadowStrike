/**
 * @file SandboxEvasionDetector.cpp
 * @brief Enterprise-grade detection of automated malware analysis sandbox evasion
 *
 * ShadowStrike AntiEvasion - Sandbox Evasion Detection Module
 * Copyright (c) 2026 ShadowStrike Security Suite. All rights reserved.
 *
 * This module provides comprehensive detection of malware checking for automated
 * analysis sandboxes (Cuckoo, Joe Sandbox, ANY.RUN, VirusTotal, etc.).
 *
 * Implementation follows enterprise C++20 standards:
 * - PIMPL pattern for ABI stability
 * - Thread-safe with std::shared_mutex
 * - Exception-safe with comprehensive error handling
 * - Statistics tracking for all operations
 * - Memory-safe with smart pointers only
 * - Infrastructure reuse (Utils/, PatternStore)
 */

#include "pch.h"
#include "SandboxEvasionDetector.hpp"

// ============================================================================
// STANDARD LIBRARY INCLUDES
// ============================================================================

#include <algorithm>
#include <cmath>
#include <execution>
#include <numeric>
#include <queue>
#include <sstream>
#include <fstream>
#include <unordered_set>

// ============================================================================
// WINDOWS SDK INCLUDES
// ============================================================================

#include <psapi.h>
#pragma comment(lib, "psapi.lib")

#include <setupapi.h>
#pragma comment(lib, "setupapi.lib")

#include <wtsapi32.h>
#pragma comment(lib, "wtsapi32.lib")

#include <shlobj.h>
#pragma comment(lib, "shell32.lib")

#include <mmsystem.h>
#pragma comment(lib, "winmm.lib")

// For EnumDisplayDevices
#include <winuser.h>
#pragma comment(lib, "user32.lib")

// ============================================================================
// SHADOWSTRIKE INTERNAL INCLUDES
// ============================================================================

#include "../Utils/StringUtils.hpp"
#include "../Utils/Logger.hpp"
#include "../Utils/ProcessUtils.hpp"
#include "../Utils/SystemUtils.hpp"
#include "../Utils/RegistryUtils.hpp"
#include "../Utils/FileUtils.hpp"
#include "../PatternStore/PatternStore.hpp"

namespace ShadowStrike::AntiEvasion {

    // ========================================================================
    // HELPER FUNCTIONS
    // ========================================================================

    /**
     * @brief Get display name for sandbox product
     */
    [[nodiscard]] const wchar_t* SandboxProductToString(SandboxProduct product) noexcept {
        switch (product) {
            // Open source
        case SandboxProduct::Cuckoo: return L"Cuckoo Sandbox";
        case SandboxProduct::CAPE: return L"CAPE Sandbox";
        case SandboxProduct::Drakvuf: return L"Drakvuf Sandbox";
        case SandboxProduct::LiSa: return L"LiSa Sandbox";

            // Commercial
        case SandboxProduct::JoeSandbox: return L"Joe Sandbox";
        case SandboxProduct::AnyRun: return L"ANY.RUN";
        case SandboxProduct::HybridAnalysis: return L"Hybrid Analysis";
        case SandboxProduct::VirusTotal: return L"VirusTotal Sandbox";
        case SandboxProduct::VMRay: return L"VMRay Analyzer";
        case SandboxProduct::FireEyeAX: return L"FireEye AX";
        case SandboxProduct::WildFire: return L"Palo Alto WildFire";
        case SandboxProduct::ThreatGrid: return L"Cisco Threat Grid";
        case SandboxProduct::Triage: return L"Triage (Hatching)";
        case SandboxProduct::Intezer: return L"Intezer Analyze";
        case SandboxProduct::Lastline: return L"Lastline Analyst";
        case SandboxProduct::RecordedFuture: return L"Recorded Future Sandbox";

            // Desktop
        case SandboxProduct::Sandboxie: return L"Sandboxie";
        case SandboxProduct::WindowsSandbox: return L"Windows Sandbox";
        case SandboxProduct::ComodoSandbox: return L"Comodo Virtual Desktop";
        case SandboxProduct::AvastDeepScreen: return L"Avast DeepScreen";
        case SandboxProduct::BitdefenderATC: return L"Bitdefender Active Threat Control";
        case SandboxProduct::KasperskySafeRun: return L"Kaspersky Safe Run";
        case SandboxProduct::NortonSandbox: return L"Norton Sandbox";
        case SandboxProduct::ESETLiveGuard: return L"ESET LiveGuard";

            // Enterprise
        case SandboxProduct::FalconSandbox: return L"CrowdStrike Falcon Sandbox";
        case SandboxProduct::DefenderATP: return L"Microsoft Defender for Endpoint";
        case SandboxProduct::CarbonBlack: return L"Carbon Black Cloud";
        case SandboxProduct::SentinelOne: return L"SentinelOne Deep Visibility";
        case SandboxProduct::Cybereason: return L"Cybereason Sandbox";
        case SandboxProduct::SophosInterceptX: return L"Sophos Intercept X";
        case SandboxProduct::TrendMicroDD: return L"Trend Micro Deep Discovery";
        case SandboxProduct::McAfeeATD: return L"McAfee Advanced Threat Defense";

            // Other
        case SandboxProduct::GenericAnalysis: return L"Generic Analysis Environment";
        case SandboxProduct::CustomSandbox: return L"Custom Sandbox";
        case SandboxProduct::Multiple: return L"Multiple Sandboxes";

        default: return L"Unknown";
        }
    }

    /**
     * @brief Get display name for indicator category
     */
    [[nodiscard]] const wchar_t* SandboxIndicatorCategoryToString(SandboxIndicatorCategory category) noexcept {
        switch (category) {
        case SandboxIndicatorCategory::HumanInteraction: return L"Human Interaction";
        case SandboxIndicatorCategory::Hardware: return L"Hardware Fingerprinting";
        case SandboxIndicatorCategory::WearAndTear: return L"System Wear and Tear";
        case SandboxIndicatorCategory::Timing: return L"Timing Analysis";
        case SandboxIndicatorCategory::Artifact: return L"Sandbox Artifact";
        case SandboxIndicatorCategory::Environment: return L"Environment Check";
        case SandboxIndicatorCategory::Network: return L"Network Characteristics";
        case SandboxIndicatorCategory::FileSystem: return L"File System Analysis";
        default: return L"Unknown";
        }
    }

    // ========================================================================
    // PIMPL IMPLEMENTATION CLASS
    // ========================================================================

    class SandboxEvasionDetector::Impl {
    public:
        // ====================================================================
        // MEMBERS
        // ====================================================================

        /// @brief Thread synchronization
        mutable std::shared_mutex m_mutex;

        /// @brief Initialization state
        std::atomic<bool> m_initialized{ false };

        /// @brief Pattern store for sandbox signatures
        std::shared_ptr<PatternStore::PatternStore> m_patternStore;

        /// @brief Detection callback
        SandboxDetectionCallback m_detectionCallback;

        /// @brief Statistics
        SandboxEvasionDetector::Statistics m_stats;

        /// @brief Result cache
        struct CacheEntry {
            SandboxEvasionResult result;
            std::chrono::steady_clock::time_point timestamp;
        };
        std::unordered_map<uint32_t, CacheEntry> m_resultCache;

        /// @brief Human interaction tracking
        struct InteractionTracker {
            std::vector<POINT> mousePositions;
            std::vector<std::chrono::system_clock::time_point> mouseTimestamps;
            uint32_t keyPresses = 0;
            uint32_t mouseClicks = 0;
            std::chrono::system_clock::time_point monitoringStartTime;
        };
        std::unordered_map<uint32_t, InteractionTracker> m_interactionTracking;

        /// @brief Known sandbox DLLs
        std::unordered_set<std::wstring> m_knownSandboxDLLs = {
            L"sbiedll.dll",      // Sandboxie
            L"dbghelp.dll",      // Debug hooks
            L"api_log.dll",      // API logging
            L"dir_watch.dll",    // Directory monitoring
            L"pstorec.dll",      // Protected storage
            L"vmcheck.dll",      // VM check
            L"wpespy.dll",       // Packet sniffer
            L"cuckoomon.dll",    // Cuckoo monitor
            L"snxhk.dll"         // Avast hooks
        };

        /// @brief Known sandbox processes
        std::unordered_set<std::wstring> m_knownSandboxProcesses = {
            L"vboxservice.exe",     // VirtualBox
            L"vboxtray.exe",        // VirtualBox
            L"vmtoolsd.exe",        // VMware Tools
            L"joeboxserver.exe",    // Joe Sandbox
            L"joeboxcontrol.exe",   // Joe Sandbox
            L"wireshark.exe",       // Network analysis
            L"procmon.exe",         // Process Monitor
            L"procexp.exe",         // Process Explorer
            L"regmon.exe",          // Registry Monitor
            L"filemon.exe",         // File Monitor
            L"ProcessHacker.exe",   // Process Hacker
            L"ollydbg.exe",         // OllyDbg debugger
            L"idaq.exe",            // IDA Pro
            L"idaq64.exe",          // IDA Pro 64-bit
            L"x64dbg.exe",          // x64dbg
            L"windbg.exe",          // WinDbg
            L"immunitydebugger.exe" // Immunity Debugger
        };

        /// @brief Known sandbox registry keys
        std::vector<std::wstring> m_knownSandboxRegKeys = {
            L"SOFTWARE\\Oracle\\VirtualBox Guest Additions",
            L"SOFTWARE\\VMware, Inc.\\VMware Tools",
            L"SYSTEM\\ControlSet001\\Services\\VBoxGuest",
            L"SYSTEM\\ControlSet001\\Services\\VBoxMouse",
            L"SYSTEM\\ControlSet001\\Services\\VBoxService",
            L"SOFTWARE\\Microsoft\\Virtual Machine\\Guest\\Parameters",
            L"SYSTEM\\CurrentControlSet\\Control\\CrashControl\\CrashDumpEnabled",
            L"SOFTWARE\\Wine"  // Wine (Windows emulation on Linux)
        };

        // ====================================================================
        // METHODS
        // ====================================================================

        Impl() = default;
        ~Impl() = default;

        [[nodiscard]] bool Initialize(SandboxEvasionError* err) noexcept;
        void Shutdown() noexcept;

        // Hardware checks
        [[nodiscard]] bool CheckLowRAM(uint64_t& ramBytes) const noexcept;
        [[nodiscard]] bool CheckLowCPU(uint32_t& coreCount) const noexcept;
        [[nodiscard]] bool CheckSmallDisk(uint64_t& diskBytes) const noexcept;
        [[nodiscard]] bool CheckSuspiciousGPU(bool& hasDedicatedGPU, std::wstring& gpuName) const noexcept;

        // Timing checks
        [[nodiscard]] bool CheckShortUptime(uint64_t& uptimeMs) const noexcept;
        [[nodiscard]] bool CheckRecentInstall(uint32_t& installAgeDays) const noexcept;

        // Wear and tear
        [[nodiscard]] uint32_t CountRecentDocuments() const noexcept;
        [[nodiscard]] uint32_t CountDesktopFiles() const noexcept;
        [[nodiscard]] uint32_t CountInstalledPrograms() const noexcept;
        [[nodiscard]] uint32_t CountTempFiles() const noexcept;

        // Environment
        [[nodiscard]] bool CheckSuspiciousScreenResolution(uint32_t& width, uint32_t& height) const noexcept;
        [[nodiscard]] bool CheckLowColorDepth(uint32_t& colorDepth) const noexcept;

        // Artifacts
        [[nodiscard]] bool IsSandboxDLL(std::wstring_view dllName) const noexcept;
        [[nodiscard]] bool IsSandboxProcess(std::wstring_view processName) const noexcept;
        [[nodiscard]] bool IsSandboxRegKey(std::wstring_view regKey) const noexcept;

        // Human interaction analysis
        [[nodiscard]] double AnalyzeMouseMovements(const std::vector<POINT>& positions) const noexcept;
    };

    // ========================================================================
    // IMPL: INITIALIZATION
    // ========================================================================

    bool SandboxEvasionDetector::Impl::Initialize(SandboxEvasionError* err) noexcept {
        try {
            if (m_initialized.exchange(true)) {
                return true; // Already initialized
            }

            SS_LOG_INFO(L"AntiEvasion", L"SandboxEvasionDetector: Initializing...");

            // PatternStore is optional (can be set later)
            if (m_patternStore) {
                SS_LOG_INFO(L"AntiEvasion", L"SandboxEvasionDetector: Initialized with PatternStore");
            } else {
                SS_LOG_INFO(L"AntiEvasion", L"SandboxEvasionDetector: Initialized (PatternStore pending)");
            }

            SS_LOG_INFO(L"AntiEvasion", L"SandboxEvasionDetector: Initialized successfully");
            return true;

        }
        catch (const std::exception& e) {
            SS_LOG_ERROR(L"AntiEvasion", L"SandboxEvasionDetector initialization failed: %ls", Utils::StringUtils::ToWide(e.what()).c_str());

            if (err) {
                err->win32Code = ERROR_INTERNAL_ERROR;
                err->message = L"Initialization failed";
                err->context = Utils::StringUtils::ToWide(e.what());
            }

            m_initialized = false;
            return false;
        }
        catch (...) {
            SS_LOG_FATAL(L"AntiEvasion", L"SandboxEvasionDetector: Unknown initialization error");

            if (err) {
                err->win32Code = ERROR_INTERNAL_ERROR;
                err->message = L"Unknown initialization error";
            }

            m_initialized = false;
            return false;
        }
    }

    void SandboxEvasionDetector::Impl::Shutdown() noexcept {
        try {
            std::unique_lock lock(m_mutex);

            if (!m_initialized.exchange(false)) {
                return; // Already shutdown
            }

            SS_LOG_INFO(L"AntiEvasion", L"SandboxEvasionDetector: Shutting down...");

            // Clear caches
            m_resultCache.clear();
            m_interactionTracking.clear();

            // Clear callback
            m_detectionCallback = nullptr;

            SS_LOG_INFO(L"AntiEvasion", L"SandboxEvasionDetector: Shutdown complete");
        }
        catch (...) {
            SS_LOG_ERROR(L"AntiEvasion", L"SandboxEvasionDetector: Exception during shutdown");
        }
    }

    // ========================================================================
    // IMPL: HARDWARE CHECKS
    // ========================================================================

    bool SandboxEvasionDetector::Impl::CheckLowRAM(uint64_t& ramBytes) const noexcept {
        try {
            MEMORYSTATUSEX memInfo = {};
            memInfo.dwLength = sizeof(memInfo);

            if (!GlobalMemoryStatusEx(&memInfo)) {
                SS_LOG_WARN(L"AntiEvasion", L"CheckLowRAM: GlobalMemoryStatusEx failed: %d", GetLastError());
                return false;
            }

            ramBytes = memInfo.ullTotalPhys;

            // Check against thresholds
            if (ramBytes < SandboxConstants::SUSPICIOUS_RAM_BYTES) {
                return true; // Very suspicious
            }

            if (ramBytes < SandboxConstants::MIN_RAM_BYTES) {
                return true; // Suspicious
            }

            return false;
        }
        catch (...) {
            SS_LOG_ERROR(L"AntiEvasion", L"CheckLowRAM: Exception");
            return false;
        }
    }

    bool SandboxEvasionDetector::Impl::CheckLowCPU(uint32_t& coreCount) const noexcept {
        try {
            SYSTEM_INFO sysInfo = {};
            GetSystemInfo(&sysInfo);

            coreCount = sysInfo.dwNumberOfProcessors;

            // Check against thresholds
            if (coreCount <= SandboxConstants::SUSPICIOUS_CPU_CORES) {
                return true; // Very suspicious (1 core)
            }

            if (coreCount < SandboxConstants::MIN_CPU_CORES) {
                return true; // Suspicious (<2 cores)
            }

            return false;
        }
        catch (...) {
            SS_LOG_ERROR(L"AntiEvasion", L"CheckLowCPU: Exception");
            return false;
        }
    }

    bool SandboxEvasionDetector::Impl::CheckSmallDisk(uint64_t& diskBytes) const noexcept {
        try {
            // Get system drive (usually C:)
            wchar_t systemDrive[MAX_PATH] = {};
            if (GetSystemDirectoryW(systemDrive, MAX_PATH) == 0) {
                return false;
            }

            // Extract drive letter (e.g., "C:\")
            std::wstring drivePath = std::wstring(systemDrive, 3);

            ULARGE_INTEGER freeBytesAvailable = {};
            ULARGE_INTEGER totalNumberOfBytes = {};
            ULARGE_INTEGER totalNumberOfFreeBytes = {};

            if (!GetDiskFreeSpaceExW(drivePath.c_str(),
                &freeBytesAvailable,
                &totalNumberOfBytes,
                &totalNumberOfFreeBytes)) {
                SS_LOG_WARN(L"AntiEvasion", L"CheckSmallDisk: GetDiskFreeSpaceEx failed: %d", GetLastError());
                return false;
            }

            diskBytes = totalNumberOfBytes.QuadPart;

            // Check against thresholds
            if (diskBytes < SandboxConstants::SUSPICIOUS_DISK_BYTES) {
                return true; // Very suspicious (<40GB)
            }

            if (diskBytes < SandboxConstants::MIN_DISK_BYTES) {
                return true; // Suspicious (<80GB)
            }

            return false;
        }
        catch (...) {
            SS_LOG_ERROR(L"AntiEvasion", L"CheckSmallDisk: Exception");
            return false;
        }
    }

    bool SandboxEvasionDetector::Impl::CheckSuspiciousGPU(bool& hasDedicatedGPU, std::wstring& gpuName) const noexcept {
        try {
            hasDedicatedGPU = false;
            gpuName.clear();

            DISPLAY_DEVICEW dd = {};
            dd.cb = sizeof(dd);

            // Enumerate primary display device
            if (!EnumDisplayDevicesW(nullptr, 0, &dd, 0)) {
                SS_LOG_WARN(L"AntiEvasion", L"CheckSuspiciousGPU: EnumDisplayDevicesW failed: %d", GetLastError());
                return false;
            }

            gpuName = dd.DeviceString;
            std::wstring lowerName = gpuName;
            std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(), ::towlower);

            // Check for known VM/Sandbox adapters
            const std::vector<std::wstring> suspiciousGPUs = {
                L"vmware",
                L"virtualbox",
                L"vbox",
                L"basic render driver",
                L"standard vga",
                L"microsoft basic display adapter",
                L"citrix",
                L"parallels",
                L"qemu",
                L"red hat",
                L"bochs",
                L"xen"
            };

            bool isSuspicious = false;
            for (const auto& susp : suspiciousGPUs) {
                if (lowerName.find(susp) != std::wstring::npos) {
                    isSuspicious = true;
                    break;
                }
            }

            // Check for known dedicated GPU vendors
            const std::vector<std::wstring> dedicatedVendors = {
                L"nvidia",
                L"amd",
                L"radeon",
                L"geforce",
                L"intel", // Intel Integrated is still better than Basic Render
                L"iris",
                L"arc"
            };

            for (const auto& vendor : dedicatedVendors) {
                if (lowerName.find(vendor) != std::wstring::npos) {
                    hasDedicatedGPU = true;
                    // If it matches a dedicated vendor but ALSO suspicious (rare but possible), prioritize suspicious?
                    // Usually "VMware SVGA 3D" won't match "nvidia" unless passthrough.
                    // If passthrough, it's a "good" VM or real hardware.
                    if (isSuspicious) isSuspicious = false;
                    break;
                }
            }

            // If we didn't find a dedicated vendor, and it's not explicitly suspicious, it might still be suspicious
            // if it's just "Microsoft Corporation" or similar generic names.
            if (!hasDedicatedGPU && !isSuspicious) {
                // Enterprise Grade: Check PCI Vendor IDs in DeviceID string for stronger detection
                // Format: PCI\VEN_xxxx&DEV_xxxx...
                std::wstring deviceId = dd.DeviceID;
                std::transform(deviceId.begin(), deviceId.end(), deviceId.begin(), ::towupper);

                // Known Virtualization Vendor IDs
                if (deviceId.find(L"VEN_15AD") != std::wstring::npos) isSuspicious = true;      // VMware
                else if (deviceId.find(L"VEN_80EE") != std::wstring::npos) isSuspicious = true; // VirtualBox
                else if (deviceId.find(L"VEN_1AF4") != std::wstring::npos) isSuspicious = true; // VirtIO / Red Hat
                else if (deviceId.find(L"VEN_1AB8") != std::wstring::npos) isSuspicious = true; // Parallels
                else if (deviceId.find(L"VEN_1414") != std::wstring::npos) isSuspicious = true; // Microsoft Basic Render / RemoteFX
                else if (deviceId.find(L"VEN_5853") != std::wstring::npos) isSuspicious = true; // Citrix
                else if (deviceId.find(L"VEN_1234") != std::wstring::npos) isSuspicious = true; // Bochs / QEMU
            }

            return isSuspicious;
        }
        catch (...) {
            SS_LOG_ERROR(L"AntiEvasion", L"CheckSuspiciousGPU: Exception");
            return false;
        }
    }

    // ========================================================================
    // IMPL: TIMING CHECKS
    // ========================================================================

    bool SandboxEvasionDetector::Impl::CheckShortUptime(uint64_t& uptimeMs) const noexcept {
        try {
            uptimeMs = GetTickCount64();

            // Check against thresholds
            if (uptimeMs < SandboxConstants::VERY_SUSPICIOUS_UPTIME_MS) {
                return true; // Very suspicious (<2 minutes)
            }

            if (uptimeMs < SandboxConstants::SUSPICIOUS_UPTIME_MS) {
                return true; // Suspicious (<5 minutes)
            }

            if (uptimeMs < SandboxConstants::MIN_UPTIME_MS) {
                return true; // Low confidence (<10 minutes)
            }

            return false;
        }
        catch (...) {
            SS_LOG_ERROR(L"AntiEvasion", L"CheckShortUptime: Exception");
            return false;
        }
    }

    bool SandboxEvasionDetector::Impl::CheckRecentInstall(uint32_t& installAgeDays) const noexcept {
        try {
            // Query registry for Windows install date
            HKEY hKey = nullptr;
            if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
                0,
                KEY_READ,
                &hKey) != ERROR_SUCCESS) {
                return false;
            }

            DWORD installDateValue = 0;
            DWORD dataSize = sizeof(installDateValue);

            const LONG result = RegQueryValueExW(hKey,
                L"InstallDate",
                nullptr,
                nullptr,
                reinterpret_cast<LPBYTE>(&installDateValue),
                &dataSize);

            RegCloseKey(hKey);

            if (result != ERROR_SUCCESS) {
                return false;
            }

            // Calculate age in days
            const auto now = std::chrono::system_clock::now();
            const auto installTime = std::chrono::system_clock::from_time_t(static_cast<time_t>(installDateValue));
            const auto age = std::chrono::duration_cast<std::chrono::hours>(now - installTime);

            installAgeDays = static_cast<uint32_t>(age.count() / 24);

            // Check against threshold
            if (installAgeDays < SandboxConstants::MIN_INSTALL_AGE_DAYS) {
                return true; // Suspicious (installed <7 days ago)
            }

            return false;
        }
        catch (...) {
            SS_LOG_ERROR(L"AntiEvasion", L"CheckRecentInstall: Exception");
            return false;
        }
    }

    // ========================================================================
    // IMPL: WEAR AND TEAR
    // ========================================================================

    uint32_t SandboxEvasionDetector::Impl::CountRecentDocuments() const noexcept {
        try {
            // Get Recent folder path
            wchar_t recentPath[MAX_PATH] = {};
            if (SHGetFolderPathW(nullptr, CSIDL_RECENT, nullptr, 0, recentPath) != S_OK) {
                return 0;
            }

            // Count files
            uint32_t count = 0;
            WIN32_FIND_DATAW findData = {};
            std::wstring searchPath = std::wstring(recentPath) + L"\\*";

            HANDLE hFind = FindFirstFileW(searchPath.c_str(), &findData);
            if (hFind != INVALID_HANDLE_VALUE) {
                do {
                    if (!(findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
                        count++;
                    }
                } while (FindNextFileW(hFind, &findData) != 0);

                FindClose(hFind);
            }

            return count;
        }
        catch (...) {
            SS_LOG_ERROR(L"AntiEvasion", L"CountRecentDocuments: Exception");
            return 0;
        }
    }

    uint32_t SandboxEvasionDetector::Impl::CountDesktopFiles() const noexcept {
        try {
            // Get Desktop folder path
            wchar_t desktopPath[MAX_PATH] = {};
            if (SHGetFolderPathW(nullptr, CSIDL_DESKTOP, nullptr, 0, desktopPath) != S_OK) {
                return 0;
            }

            // Count files
            uint32_t count = 0;
            WIN32_FIND_DATAW findData = {};
            std::wstring searchPath = std::wstring(desktopPath) + L"\\*";

            HANDLE hFind = FindFirstFileW(searchPath.c_str(), &findData);
            if (hFind != INVALID_HANDLE_VALUE) {
                do {
                    if (!(findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
                        count++;
                    }
                } while (FindNextFileW(hFind, &findData) != 0);

                FindClose(hFind);
            }

            return count;
        }
        catch (...) {
            SS_LOG_ERROR(L"AntiEvasion", L"CountDesktopFiles: Exception");
            return 0;
        }
    }

    uint32_t SandboxEvasionDetector::Impl::CountInstalledPrograms() const noexcept {
        try {
            uint32_t count = 0;

            // Query registry for installed programs (64-bit)
            HKEY hKey = nullptr;
            if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
                0,
                KEY_READ | KEY_WOW64_64KEY,
                &hKey) == ERROR_SUCCESS) {

                DWORD subkeyCount = 0;
                if (RegQueryInfoKeyW(hKey, nullptr, nullptr, nullptr, &subkeyCount,
                    nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr) == ERROR_SUCCESS) {
                    count += subkeyCount;
                }

                RegCloseKey(hKey);
            }

            // Query registry for installed programs (32-bit on 64-bit Windows)
            if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                L"SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
                0,
                KEY_READ,
                &hKey) == ERROR_SUCCESS) {

                DWORD subkeyCount = 0;
                if (RegQueryInfoKeyW(hKey, nullptr, nullptr, nullptr, &subkeyCount,
                    nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr) == ERROR_SUCCESS) {
                    count += subkeyCount;
                }

                RegCloseKey(hKey);
            }

            return count;
        }
        catch (...) {
            SS_LOG_ERROR(L"AntiEvasion", L"CountInstalledPrograms: Exception");
            return 0;
        }
    }

    uint32_t SandboxEvasionDetector::Impl::CountTempFiles() const noexcept {
        try {
            // Get Temp folder path
            wchar_t tempPath[MAX_PATH] = {};
            if (GetTempPathW(MAX_PATH, tempPath) == 0) {
                return 0;
            }

            // Count files
            uint32_t count = 0;
            WIN32_FIND_DATAW findData = {};
            std::wstring searchPath = std::wstring(tempPath) + L"*";

            HANDLE hFind = FindFirstFileW(searchPath.c_str(), &findData);
            if (hFind != INVALID_HANDLE_VALUE) {
                do {
                    if (!(findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
                        count++;
                    }
                } while (FindNextFileW(hFind, &findData) != 0);

                FindClose(hFind);
            }

            return count;
        }
        catch (...) {
            SS_LOG_ERROR(L"AntiEvasion", L"CountTempFiles: Exception");
            return 0;
        }
    }

    // ========================================================================
    // IMPL: ENVIRONMENT CHECKS
    // ========================================================================

    bool SandboxEvasionDetector::Impl::CheckSuspiciousScreenResolution(
        uint32_t& width,
        uint32_t& height
    ) const noexcept {
        try {
            width = static_cast<uint32_t>(GetSystemMetrics(SM_CXSCREEN));
            height = static_cast<uint32_t>(GetSystemMetrics(SM_CYSCREEN));

            // Check for common sandbox resolutions
            if (width == SandboxConstants::VERY_SUSPICIOUS_SCREEN_WIDTH &&
                height == SandboxConstants::VERY_SUSPICIOUS_SCREEN_HEIGHT) {
                return true; // 800x600 - very suspicious
            }

            if (width == SandboxConstants::SUSPICIOUS_SCREEN_WIDTH &&
                height == SandboxConstants::SUSPICIOUS_SCREEN_HEIGHT) {
                return true; // 1024x768 - suspicious
            }

            return false;
        }
        catch (...) {
            SS_LOG_ERROR(L"AntiEvasion", L"CheckSuspiciousScreenResolution: Exception");
            return false;
        }
    }

    bool SandboxEvasionDetector::Impl::CheckLowColorDepth(uint32_t& colorDepth) const noexcept {
        try {
            HDC hdc = GetDC(nullptr);
            if (!hdc) {
                return false;
            }

            colorDepth = static_cast<uint32_t>(GetDeviceCaps(hdc, BITSPIXEL));
            ReleaseDC(nullptr, hdc);

            // Check against threshold
            if (colorDepth < SandboxConstants::MIN_COLOR_DEPTH) {
                return true; // <24-bit color
            }

            return false;
        }
        catch (...) {
            SS_LOG_ERROR(L"AntiEvasion", L"CheckLowColorDepth: Exception");
            return false;
        }
    }

    // ========================================================================
    // IMPL: ARTIFACT CHECKS
    // ========================================================================

    bool SandboxEvasionDetector::Impl::IsSandboxDLL(std::wstring_view dllName) const noexcept {
        std::wstring lowerName(dllName);
        std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(), ::towlower);

        return m_knownSandboxDLLs.find(lowerName) != m_knownSandboxDLLs.end();
    }

    bool SandboxEvasionDetector::Impl::IsSandboxProcess(std::wstring_view processName) const noexcept {
        std::wstring lowerName(processName);
        std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(), ::towlower);

        return m_knownSandboxProcesses.find(lowerName) != m_knownSandboxProcesses.end();
    }

    bool SandboxEvasionDetector::Impl::IsSandboxRegKey(std::wstring_view regKey) const noexcept {
        std::wstring upperKey(regKey);
        std::transform(upperKey.begin(), upperKey.end(), upperKey.begin(), ::towupper);

        for (const auto& knownKey : m_knownSandboxRegKeys) {
            std::wstring upperKnown(knownKey);
            std::transform(upperKnown.begin(), upperKnown.end(), upperKnown.begin(), ::towupper);

            if (upperKey.find(upperKnown) != std::wstring::npos) {
                return true;
            }
        }

        return false;
    }

    // ========================================================================
    // IMPL: HUMAN INTERACTION ANALYSIS
    // ========================================================================

    double SandboxEvasionDetector::Impl::AnalyzeMouseMovements(
        const std::vector<POINT>& positions
    ) const noexcept {
        if (positions.size() < 2) {
            return 0.0; // No movement data
        }

        try {
            // Calculate total distance
            double totalDistance = 0.0;
            for (size_t i = 1; i < positions.size(); ++i) {
                const double dx = static_cast<double>(positions[i].x - positions[i - 1].x);
                const double dy = static_cast<double>(positions[i].y - positions[i - 1].y);
                totalDistance += std::sqrt(dx * dx + dy * dy);
            }

            // Calculate straight-line distance (start to end)
            const double dx = static_cast<double>(positions.back().x - positions.front().x);
            const double dy = static_cast<double>(positions.back().y - positions.front().y);
            const double straightLineDistance = std::sqrt(dx * dx + dy * dy);

            // Calculate ratio (1.0 = perfectly straight, 0.0 = very curved)
            const double ratio = (totalDistance > 0.0) ? (straightLineDistance / totalDistance) : 0.0;

            // Bots tend to move in straight lines (ratio close to 1.0)
            // Humans have more curved movements (ratio closer to 0.0)
            if (ratio >= SandboxConstants::MAX_STRAIGHT_LINE_RATIO) {
                return 0.9; // Bot-like (90% confidence)
            }

            return ratio; // Return ratio as confidence
        }
        catch (...) {
            SS_LOG_ERROR(L"AntiEvasion", L"AnalyzeMouseMovements: Exception");
            return 0.0;
        }
    }

    // ========================================================================
    // PUBLIC API IMPLEMENTATION
    // ========================================================================

    SandboxEvasionDetector::SandboxEvasionDetector() noexcept
        : m_impl(std::make_unique<Impl>()) {
    }

    SandboxEvasionDetector::SandboxEvasionDetector(
        std::shared_ptr<PatternStore::PatternStore> patternStore
    ) noexcept
        : m_impl(std::make_unique<Impl>()) {
        m_impl->m_patternStore = std::move(patternStore);
    }

    SandboxEvasionDetector::~SandboxEvasionDetector() {
        if (m_impl) {
            m_impl->Shutdown();
        }
    }

    SandboxEvasionDetector::SandboxEvasionDetector(SandboxEvasionDetector&&) noexcept = default;
    SandboxEvasionDetector& SandboxEvasionDetector::operator=(SandboxEvasionDetector&&) noexcept = default;

    bool SandboxEvasionDetector::Initialize(SandboxEvasionError* err) noexcept {
        if (!m_impl) {
            if (err) {
                err->win32Code = ERROR_INVALID_HANDLE;
                err->message = L"Invalid detector instance";
            }
            return false;
        }
        return m_impl->Initialize(err);
    }

    void SandboxEvasionDetector::Shutdown() noexcept {
        if (m_impl) {
            m_impl->Shutdown();
        }
    }

    bool SandboxEvasionDetector::IsInitialized() const noexcept {
        return m_impl && m_impl->m_initialized.load();
    }

    // ========================================================================
    // SYSTEM ANALYSIS
    // ========================================================================

    SandboxEvasionResult SandboxEvasionDetector::AnalyzeSystem(
        const SandboxAnalysisConfig& config,
        SandboxEvasionError* err
    ) noexcept {
        SandboxEvasionResult result;
        result.config = config;

        try {
            if (!IsInitialized()) {
                if (err) {
                    err->win32Code = ERROR_NOT_READY;
                    err->message = L"Detector not initialized";
                }
                return result;
            }

            const auto startTime = std::chrono::high_resolution_clock::now();
            result.analysisStartTime = std::chrono::system_clock::now();

            // Perform analysis
            AnalyzeSystemInternal(config, result);

            const auto endTime = std::chrono::high_resolution_clock::now();
            const auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime);

            result.analysisDurationMs = duration.count();
            result.analysisEndTime = std::chrono::system_clock::now();
            result.analysisComplete = true;

            m_impl->m_stats.totalAnalyses++;
            m_impl->m_stats.totalAnalysisTimeUs += std::chrono::duration_cast<std::chrono::microseconds>(duration).count();

            if (result.isSandbox) {
                m_impl->m_stats.sandboxesDetected++;
            }

            return result;
        }
        catch (const std::exception& e) {
            SS_LOG_ERROR(L"AntiEvasion", L"AnalyzeSystem failed: %ls", Utils::StringUtils::ToWide(e.what()).c_str());

            if (err) {
                err->win32Code = ERROR_INTERNAL_ERROR;
                err->message = L"Analysis failed";
                err->context = Utils::StringUtils::ToWide(e.what());
            }

            m_impl->m_stats.analysisErrors++;
            return result;
        }
        catch (...) {
            SS_LOG_FATAL(L"AntiEvasion", L"AnalyzeSystem: Unknown error");

            if (err) {
                err->win32Code = ERROR_INTERNAL_ERROR;
                err->message = L"Unknown analysis error";
            }

            m_impl->m_stats.analysisErrors++;
            return result;
        }
    }

    // ========================================================================
    // PROCESS ANALYSIS
    // ========================================================================

    SandboxEvasionResult SandboxEvasionDetector::AnalyzeProcess(
        uint32_t processId,
        const SandboxAnalysisConfig& config,
        SandboxEvasionError* err
    ) noexcept {
        SandboxEvasionResult result;
        result.processId = processId;
        result.config = config;

        try {
            if (!IsInitialized()) {
                if (err) {
                    err->win32Code = ERROR_NOT_READY;
                    err->message = L"Detector not initialized";
                }
                return result;
            }

            // Check cache first
            if (HasFlag(config.flags, SandboxAnalysisFlags::EnableCaching)) {
                std::shared_lock lock(m_impl->m_mutex);
                auto it = m_impl->m_resultCache.find(processId);

                if (it != m_impl->m_resultCache.end()) {
                    const auto age = std::chrono::steady_clock::now() - it->second.timestamp;

                    if (age < SandboxConstants::RESULT_CACHE_TTL) {
                        m_impl->m_stats.cacheHits++;
                        result = it->second.result;
                        result.fromCache = true;
                        return result;
                    }
                }
                m_impl->m_stats.cacheMisses++;
            }

            // Perform system-wide analysis
            result = AnalyzeSystem(config, err);

            // Update cache
            if (HasFlag(config.flags, SandboxAnalysisFlags::EnableCaching)) {
                UpdateCache(processId, result);
            }

            return result;
        }
        catch (const std::exception& e) {
            SS_LOG_ERROR(L"AntiEvasion", L"AnalyzeProcess failed: %ls", Utils::StringUtils::ToWide(e.what()).c_str());

            if (err) {
                err->win32Code = ERROR_INTERNAL_ERROR;
                err->message = L"Process analysis failed";
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

    // ========================================================================
    // SPECIFIC DETECTION METHODS
    // ========================================================================

    bool SandboxEvasionDetector::CheckHumanInteraction(
        uint32_t monitoringDurationMs,
        HumanInteractionInfo& outInfo,
        SandboxEvasionError* err
    ) noexcept {
        try {
            outInfo = HumanInteractionInfo{};

            // Validate duration
            if (monitoringDurationMs < SandboxConstants::MIN_INTERACTION_MONITOR_MS ||
                monitoringDurationMs > SandboxConstants::MAX_INTERACTION_MONITOR_MS) {
                monitoringDurationMs = SandboxConstants::DEFAULT_INTERACTION_MONITOR_MS;
            }

            const auto startTime = std::chrono::system_clock::now();
            std::vector<POINT> mousePositions;
            POINT lastPos = {};
            GetCursorPos(&lastPos);
            mousePositions.push_back(lastPos);

            // Monitor for specified duration
            const auto endTime = startTime + std::chrono::milliseconds(monitoringDurationMs);
            uint32_t movements = 0;

            while (std::chrono::system_clock::now() < endTime) {
                Sleep(100); // 100ms polling interval

                POINT currentPos = {};
                GetCursorPos(&currentPos);

                if (currentPos.x != lastPos.x || currentPos.y != lastPos.y) {
                    mousePositions.push_back(currentPos);
                    movements++;
                    lastPos = currentPos;
                }

                // Check for mouse clicks (GetAsyncKeyState)
                if (GetAsyncKeyState(VK_LBUTTON) & 0x8000) {
                    outInfo.mouseClicks++;
                }

                // Check for keyboard input
                for (int vk = 0; vk < 256; ++vk) {
                    if (GetAsyncKeyState(vk) & 0x8000) {
                        outInfo.keyPresses++;
                    }
                }
            }

            outInfo.mouseMovements = movements;

            // Calculate total distance
            for (size_t i = 1; i < mousePositions.size(); ++i) {
                const double dx = static_cast<double>(mousePositions[i].x - mousePositions[i - 1].x);
                const double dy = static_cast<double>(mousePositions[i].y - mousePositions[i - 1].y);
                outInfo.totalMouseDistance += std::sqrt(dx * dx + dy * dy);
            }

            // Analyze movements
            outInfo.botLikeBehavior = (m_impl->AnalyzeMouseMovements(mousePositions) >= 0.9);

            // Determine if human present
            outInfo.hasHumanInteraction = (outInfo.mouseMovements >= SandboxConstants::MIN_MOUSE_MOVEMENTS ||
                outInfo.totalMouseDistance >= SandboxConstants::MIN_MOUSE_DISTANCE ||
                outInfo.keyPresses > 0 ||
                outInfo.mouseClicks > 0);

            outInfo.valid = true;
            return !outInfo.hasHumanInteraction; // True if no human detected (sandbox)
        }
        catch (const std::exception& e) {
            SS_LOG_ERROR(L"AntiEvasion", L"CheckHumanInteraction failed: %ls", Utils::StringUtils::ToWide(e.what()).c_str());

            if (err) {
                err->win32Code = ERROR_INTERNAL_ERROR;
                err->message = L"Human interaction check failed";
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

    bool SandboxEvasionDetector::CheckHardwareProfile(
        HardwareProfileInfo& outInfo,
        SandboxEvasionError* err
    ) noexcept {
        try {
            outInfo = HardwareProfileInfo{};

            // RAM check
            outInfo.hasLowRAM = m_impl->CheckLowRAM(outInfo.ramBytes);

            // CPU check
            outInfo.hasLowCPUCores = m_impl->CheckLowCPU(outInfo.cpuCores);

            // Disk check
            outInfo.hasSmallDisk = m_impl->CheckSmallDisk(outInfo.diskBytes);

            // GPU check (Full implementation)
            std::wstring gpuName;
            bool isSuspiciousGPU = m_impl->CheckSuspiciousGPU(outInfo.hasGPU, gpuName);

            // Note: outInfo.hasGPU in the struct might refer to "Has Dedicated/Real GPU"
            // If we found a dedicated GPU, hasGPU = true.
            // If we found a generic/VM GPU, hasGPU = false (assuming struct semantics).
            // If isSuspiciousGPU is true, it strongly implies a sandbox.

            outInfo.valid = true;

            // Determine if suspicious hardware profile
            const uint32_t suspiciousFlags = (outInfo.hasLowRAM ? 1 : 0) +
                (outInfo.hasLowCPUCores ? 1 : 0) +
                (outInfo.hasSmallDisk ? 1 : 0) +
                (!outInfo.hasGPU ? 1 : 0) +
                (isSuspiciousGPU ? 1 : 0);

            return (suspiciousFlags >= 2); // 2+ suspicious indicators
        }
        catch (const std::exception& e) {
            SS_LOG_ERROR(L"AntiEvasion", L"CheckHardwareProfile failed: %ls", Utils::StringUtils::ToWide(e.what()).c_str());

            if (err) {
                err->win32Code = ERROR_INTERNAL_ERROR;
                err->message = L"Hardware profile check failed";
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

    bool SandboxEvasionDetector::CheckSystemWearAndTear(
        WearAndTearInfo& outInfo,
        SandboxEvasionError* err
    ) noexcept {
        try {
            outInfo = WearAndTearInfo{};

            // Count various indicators
            outInfo.recentDocumentCount = m_impl->CountRecentDocuments();
            outInfo.desktopFileCount = m_impl->CountDesktopFiles();
            outInfo.installedProgramCount = m_impl->CountInstalledPrograms();
            outInfo.tempFileCount = m_impl->CountTempFiles();

            outInfo.valid = true;

            // Determine if pristine/fresh system
            outInfo.isPristineSystem = (outInfo.recentDocumentCount < SandboxConstants::MIN_RECENT_DOCUMENTS &&
                outInfo.desktopFileCount < SandboxConstants::MIN_DESKTOP_FILES &&
                outInfo.installedProgramCount < SandboxConstants::MIN_INSTALLED_PROGRAMS &&
                outInfo.tempFileCount < SandboxConstants::MIN_TEMP_FILES);

            return outInfo.isPristineSystem;
        }
        catch (const std::exception& e) {
            SS_LOG_ERROR(L"AntiEvasion", L"CheckSystemWearAndTear failed: %ls", Utils::StringUtils::ToWide(e.what()).c_str());

            if (err) {
                err->win32Code = ERROR_INTERNAL_ERROR;
                err->message = L"Wear and tear check failed";
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

    bool SandboxEvasionDetector::CheckTimingCharacteristics(
        TimingInfo& outInfo,
        SandboxEvasionError* err
    ) noexcept {
        try {
            outInfo = TimingInfo{};

            // Uptime check
            outInfo.hasShortUptime = m_impl->CheckShortUptime(outInfo.uptimeMs);

            // Install date check
            outInfo.isRecentInstall = m_impl->CheckRecentInstall(outInfo.installAgeDays);

            outInfo.valid = true;

            return (outInfo.hasShortUptime || outInfo.isRecentInstall);
        }
        catch (const std::exception& e) {
            SS_LOG_ERROR(L"AntiEvasion", L"CheckTimingCharacteristics failed: %ls", Utils::StringUtils::ToWide(e.what()).c_str());

            if (err) {
                err->win32Code = ERROR_INTERNAL_ERROR;
                err->message = L"Timing check failed";
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

    bool SandboxEvasionDetector::DetectSandboxArtifacts(
        std::vector<SandboxArtifact>& outArtifacts,
        SandboxEvasionError* err
    ) noexcept {
        try {
            outArtifacts.clear();

            // Check for sandbox DLLs in current process
            HMODULE hModules[1024] = {};
            DWORD cbNeeded = 0;

            if (EnumProcessModules(GetCurrentProcess(), hModules, sizeof(hModules), &cbNeeded)) {
                const DWORD moduleCount = cbNeeded / sizeof(HMODULE);

                for (DWORD i = 0; i < moduleCount; ++i) {
                    wchar_t moduleName[MAX_PATH] = {};
                    if (GetModuleFileNameExW(GetCurrentProcess(), hModules[i], moduleName, MAX_PATH) > 0) {
                        const std::wstring moduleNameStr(moduleName);
                        const size_t lastSlash = moduleNameStr.find_last_of(L"\\/");
                        const std::wstring dllName = (lastSlash != std::wstring::npos)
                            ? moduleNameStr.substr(lastSlash + 1)
                            : moduleNameStr;

                        if (m_impl->IsSandboxDLL(dllName)) {
                            SandboxArtifact artifact;
                            artifact.type = SandboxArtifactType::DLL;
                            artifact.name = dllName;
                            artifact.path = moduleName;
                            artifact.confidence = 0.9;
                            outArtifacts.push_back(artifact);

                            m_impl->m_stats.artifactsDetected++;
                        }
                    }
                }
            }

            // Check for sandbox processes
            DWORD processes[1024] = {};
            DWORD cbProcesses = 0;

            if (EnumProcesses(processes, sizeof(processes), &cbProcesses)) {
                const DWORD processCount = cbProcesses / sizeof(DWORD);

                for (DWORD i = 0; i < processCount; ++i) {
                    if (processes[i] == 0) continue;

                    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, processes[i]);
                    if (hProcess) {
                        wchar_t processName[MAX_PATH] = {};
                        if (GetModuleBaseNameW(hProcess, nullptr, processName, MAX_PATH) > 0) {
                            if (m_impl->IsSandboxProcess(processName)) {
                                SandboxArtifact artifact;
                                artifact.type = SandboxArtifactType::Process;
                                artifact.name = processName;
                                artifact.confidence = 0.95;
                                outArtifacts.push_back(artifact);

                                m_impl->m_stats.artifactsDetected++;
                            }
                        }
                        CloseHandle(hProcess);
                    }
                }
            }

            // Check for sandbox registry keys
            for (const auto& regKey : m_impl->m_knownSandboxRegKeys) {
                // Parse registry key (HKLM\SOFTWARE\...)
                HKEY rootKey = HKEY_LOCAL_MACHINE;
                std::wstring subKey = regKey;

                // Simple check if key exists
                HKEY hKey = nullptr;
                if (RegOpenKeyExW(rootKey, subKey.c_str(), 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
                    SandboxArtifact artifact;
                    artifact.type = SandboxArtifactType::RegistryKey;
                    artifact.name = regKey;
                    artifact.confidence = 0.85;
                    outArtifacts.push_back(artifact);

                    RegCloseKey(hKey);
                    m_impl->m_stats.artifactsDetected++;
                }
            }

            return !outArtifacts.empty();
        }
        catch (const std::exception& e) {
            SS_LOG_ERROR(L"AntiEvasion", L"DetectSandboxArtifacts failed: %ls", Utils::StringUtils::ToWide(e.what()).c_str());

            if (err) {
                err->win32Code = ERROR_INTERNAL_ERROR;
                err->message = L"Artifact detection failed";
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

    bool SandboxEvasionDetector::CheckEnvironmentCharacteristics(
        EnvironmentInfo& outInfo,
        SandboxEvasionError* err
    ) noexcept {
        try {
            outInfo = EnvironmentInfo{};

            // Screen resolution check
            outInfo.hasSuspiciousScreen = m_impl->CheckSuspiciousScreenResolution(
                outInfo.screenWidth,
                outInfo.screenHeight
            );

            // Color depth check
            outInfo.hasLowColorDepth = m_impl->CheckLowColorDepth(outInfo.colorDepth);

            // Audio device check
            outInfo.hasAudioDevice = (waveOutGetNumDevs() > 0);

            // Monitor count
            outInfo.monitorCount = static_cast<uint32_t>(GetSystemMetrics(SM_CMONITORS));

            outInfo.valid = true;

            return (outInfo.hasSuspiciousScreen || outInfo.hasLowColorDepth || !outInfo.hasAudioDevice);
        }
        catch (const std::exception& e) {
            SS_LOG_ERROR(L"AntiEvasion", L"CheckEnvironmentCharacteristics failed: %ls", Utils::StringUtils::ToWide(e.what()).c_str());

            if (err) {
                err->win32Code = ERROR_INTERNAL_ERROR;
                err->message = L"Environment check failed";
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

    std::optional<SandboxProduct> SandboxEvasionDetector::IdentifySandboxProduct(
        const std::vector<SandboxArtifact>& artifacts
    ) noexcept {
        try {
            // Identify based on artifacts
            for (const auto& artifact : artifacts) {
                const std::wstring lowerName = [&]() {
                    std::wstring name = artifact.name;
                    std::transform(name.begin(), name.end(), name.begin(), ::towlower);
                    return name;
                    }();

                // Cuckoo
                if (lowerName.find(L"cuckoo") != std::wstring::npos) {
                    return SandboxProduct::Cuckoo;
                }

                // CAPE
                if (lowerName.find(L"cape") != std::wstring::npos) {
                    return SandboxProduct::CAPE;
                }

                // Joe Sandbox
                if (lowerName.find(L"joebox") != std::wstring::npos) {
                    return SandboxProduct::JoeSandbox;
                }

                // VMRay
                if (lowerName.find(L"vmray") != std::wstring::npos) {
                    return SandboxProduct::VMRay;
                }

                // Sandboxie
                if (lowerName.find(L"sbie") != std::wstring::npos) {
                    return SandboxProduct::Sandboxie;
                }

                // Windows Sandbox
                if (lowerName.find(L"windowssandbox") != std::wstring::npos) {
                    return SandboxProduct::WindowsSandbox;
                }

                // Avast DeepScreen
                if (lowerName.find(L"snxhk") != std::wstring::npos) {
                    return SandboxProduct::AvastDeepScreen;
                }

                // Comodo
                if (lowerName.find(L"comodo") != std::wstring::npos || lowerName.find(L"cmdvirth") != std::wstring::npos) {
                    return SandboxProduct::ComodoSandbox;
                }
            }

            return std::nullopt; // Unknown sandbox
        }
        catch (...) {
            SS_LOG_ERROR(L"AntiEvasion", L"IdentifySandboxProduct: Exception");
            return std::nullopt;
        }
    }

    // ========================================================================
    // CALLBACKS
    // ========================================================================

    void SandboxEvasionDetector::SetDetectionCallback(SandboxDetectionCallback callback) noexcept {
        std::unique_lock lock(m_impl->m_mutex);
        m_impl->m_detectionCallback = std::move(callback);
    }

    void SandboxEvasionDetector::ClearDetectionCallback() noexcept {
        std::unique_lock lock(m_impl->m_mutex);
        m_impl->m_detectionCallback = nullptr;
    }

    // ========================================================================
    // CACHING
    // ========================================================================

    std::optional<SandboxEvasionResult> SandboxEvasionDetector::GetCachedResult(
        uint32_t processId
    ) const noexcept {
        std::shared_lock lock(m_impl->m_mutex);

        auto it = m_impl->m_resultCache.find(processId);
        if (it != m_impl->m_resultCache.end()) {
            return it->second.result;
        }

        return std::nullopt;
    }

    void SandboxEvasionDetector::InvalidateCache(uint32_t processId) noexcept {
        std::unique_lock lock(m_impl->m_mutex);
        m_impl->m_resultCache.erase(processId);
    }

    void SandboxEvasionDetector::ClearCache() noexcept {
        std::unique_lock lock(m_impl->m_mutex);
        m_impl->m_resultCache.clear();
    }

    size_t SandboxEvasionDetector::GetCacheSize() const noexcept {
        std::shared_lock lock(m_impl->m_mutex);
        return m_impl->m_resultCache.size();
    }

    void SandboxEvasionDetector::UpdateCache(
        uint32_t processId,
        const SandboxEvasionResult& result
    ) noexcept {
        try {
            std::unique_lock lock(m_impl->m_mutex);

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

    void SandboxEvasionDetector::SetPatternStore(
        std::shared_ptr<PatternStore::PatternStore> patternStore
    ) noexcept {
        std::unique_lock lock(m_impl->m_mutex);
        m_impl->m_patternStore = std::move(patternStore);
    }

    void SandboxEvasionDetector::AddCustomSandboxDLL(std::wstring_view dllName) noexcept {
        std::unique_lock lock(m_impl->m_mutex);
        m_impl->m_knownSandboxDLLs.insert(std::wstring(dllName));
    }

    void SandboxEvasionDetector::AddCustomSandboxProcess(std::wstring_view processName) noexcept {
        std::unique_lock lock(m_impl->m_mutex);
        m_impl->m_knownSandboxProcesses.insert(std::wstring(processName));
    }

    void SandboxEvasionDetector::AddCustomSandboxRegKey(std::wstring_view regKey) noexcept {
        std::unique_lock lock(m_impl->m_mutex);
        m_impl->m_knownSandboxRegKeys.push_back(std::wstring(regKey));
    }

    void SandboxEvasionDetector::ClearCustomPatterns() noexcept {
        std::unique_lock lock(m_impl->m_mutex);
        // Note: This implementation currently uses a unified list for known DLLs/Processes.
        // Clearing custom patterns here is a no-op to preserve built-in signatures.
        // In a future refactor, we should separate Default vs Custom lists.
        SS_LOG_INFO(L"AntiEvasion", L"SandboxEvasionDetector: ClearCustomPatterns called (Hardcoded patterns preserved)");
    }

    // ========================================================================
    // STATISTICS
    // ========================================================================

    const SandboxEvasionDetector::Statistics& SandboxEvasionDetector::GetStatistics() const noexcept {
        return m_impl->m_stats;
    }

    void SandboxEvasionDetector::ResetStatistics() noexcept {
        m_impl->m_stats.Reset();
    }

    // ========================================================================
    // INTERNAL ANALYSIS METHODS
    // ========================================================================

    void SandboxEvasionDetector::AnalyzeSystemInternal(
        const SandboxAnalysisConfig& config,
        SandboxEvasionResult& result
    ) noexcept {
        try {
            // Hardware profile
            if (HasFlag(config.flags, SandboxAnalysisFlags::CheckHardware)) {
                if (CheckHardwareProfile(result.hardwareInfo, nullptr)) {
                    AddIndicator(result, SandboxIndicatorCategory::Hardware, L"Suspicious hardware profile detected");
                }
            }

            // Timing characteristics
            if (HasFlag(config.flags, SandboxAnalysisFlags::CheckTiming)) {
                if (CheckTimingCharacteristics(result.timingInfo, nullptr)) {
                    AddIndicator(result, SandboxIndicatorCategory::Timing, L"Suspicious timing characteristics");
                }
            }

            // Wear and tear
            if (HasFlag(config.flags, SandboxAnalysisFlags::CheckWearAndTear)) {
                if (CheckSystemWearAndTear(result.wearAndTearInfo, nullptr)) {
                    AddIndicator(result, SandboxIndicatorCategory::WearAndTear, L"Pristine system detected");
                }
            }

            // Artifacts
            if (HasFlag(config.flags, SandboxAnalysisFlags::CheckArtifacts)) {
                if (DetectSandboxArtifacts(result.artifacts, nullptr)) {
                    AddIndicator(result, SandboxIndicatorCategory::Artifact, L"Sandbox artifacts detected");
                }
            }

            // Environment
            if (HasFlag(config.flags, SandboxAnalysisFlags::CheckEnvironment)) {
                if (CheckEnvironmentCharacteristics(result.environmentInfo, nullptr)) {
                    AddIndicator(result, SandboxIndicatorCategory::Environment, L"Suspicious environment detected");
                }
            }

            // Human interaction (optional, expensive)
            if (HasFlag(config.flags, SandboxAnalysisFlags::CheckHumanInteraction)) {
                if (CheckHumanInteraction(config.interactionMonitorMs, result.interactionInfo, nullptr)) {
                    AddIndicator(result, SandboxIndicatorCategory::HumanInteraction, L"No human interaction detected");
                }
            }

            // Identify sandbox product
            result.detectedProduct = IdentifySandboxProduct(result.artifacts).value_or(SandboxProduct::Unknown);
            result.productName = SandboxProductToString(result.detectedProduct);

            // Calculate final score
            CalculateSandboxProbability(result);
        }
        catch (...) {
            SS_LOG_ERROR(L"AntiEvasion", L"AnalyzeSystemInternal: Exception");
        }
    }

    void SandboxEvasionDetector::CalculateSandboxProbability(SandboxEvasionResult& result) noexcept {
        try {
            double score = 0.0;

            // Weight by category
            for (const auto& indicator : result.indicators) {
                double categoryWeight = 1.0;

                switch (indicator.category) {
                case SandboxIndicatorCategory::HumanInteraction: categoryWeight = 15.0; break;
                case SandboxIndicatorCategory::Hardware: categoryWeight = 10.0; break;
                case SandboxIndicatorCategory::WearAndTear: categoryWeight = 8.0; break;
                case SandboxIndicatorCategory::Timing: categoryWeight = 12.0; break;
                case SandboxIndicatorCategory::Artifact: categoryWeight = 20.0; break; // Highest weight
                case SandboxIndicatorCategory::Environment: categoryWeight = 7.0; break;
                case SandboxIndicatorCategory::Network: categoryWeight = 5.0; break;
                case SandboxIndicatorCategory::FileSystem: categoryWeight = 5.0; break;
                default: categoryWeight = 1.0; break;
                }

                score += (categoryWeight * indicator.confidence);
            }

            // Normalize to 0-100
            result.sandboxProbability = static_cast<float>(std::min(score, 100.0));

            // Determine if sandbox
            result.isSandbox = (result.sandboxProbability >= SandboxConstants::SANDBOX_PROBABILITY_THRESHOLD);

            // Determine confidence level
            if (result.sandboxProbability >= SandboxConstants::HIGH_CONFIDENCE_THRESHOLD) {
                result.confidenceLevel = L"High";
            }
            else if (result.sandboxProbability >= SandboxConstants::SANDBOX_PROBABILITY_THRESHOLD) {
                result.confidenceLevel = L"Medium";
            }
            else if (result.sandboxProbability >= 40.0f) {
                result.confidenceLevel = L"Low";
            }
            else {
                result.confidenceLevel = L"Very Low";
            }
        }
        catch (...) {
            SS_LOG_ERROR(L"AntiEvasion", L"CalculateSandboxProbability: Exception");
        }
    }

    void SandboxEvasionDetector::AddIndicator(
        SandboxEvasionResult& result,
        SandboxIndicatorCategory category,
        std::wstring_view description
    ) noexcept {
        try {
            SandboxIndicator indicator;
            indicator.category = category;
            indicator.description = description;
            indicator.confidence = 0.8; // Default confidence
            indicator.timestamp = std::chrono::system_clock::now();

            result.indicators.push_back(std::move(indicator));
            result.totalIndicators++;

            // Set category bit
            const auto catIdx = static_cast<uint32_t>(category);
            if (catIdx < 32) {
                result.detectedCategories |= (1u << catIdx);
                m_impl->m_stats.categoryDetections[catIdx % 8]++;
            }

            m_impl->m_stats.totalDetections++;

            // Invoke callback if set
            if (m_impl->m_detectionCallback) {
                try {
                    m_impl->m_detectionCallback(indicator);
                }
                catch (...) {
                    // Swallow callback exceptions
                }
            }
        }
        catch (...) {
            SS_LOG_ERROR(L"AntiEvasion", L"AddIndicator: Exception");
        }
    }

} // namespace ShadowStrike::AntiEvasion
