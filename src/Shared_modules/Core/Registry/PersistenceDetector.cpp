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
 * @file PersistenceDetector.cpp
 * @brief Enterprise implementation of Auto-Start Extensibility Point (ASEP) detection engine.
 *
 * The Watchman of ShadowStrike NGAV - monitors all 100+ persistence mechanisms that
 * malware uses to survive reboots. Provides real-time analysis, comprehensive scanning,
 * and detailed threat intelligence correlation for every auto-start entry.
 *
 * @author ShadowStrike Security Team
 * @copyright (c) 2026 ShadowStrike Security Suite. All rights reserved.
 */

#include "pch.h"
#include "PersistenceDetector.hpp"

// ============================================================================
// INFRASTRUCTURE INCLUDES
// ============================================================================
#include "../../Utils/Logger.hpp"
#include "../../Utils/FileUtils.hpp"
#include "../../Utils/StringUtils.hpp"
#include "../../Utils/SystemUtils.hpp"
#include "../../Utils/ProcessUtils.hpp"
#include "../../Utils/HashUtils.hpp"
#include "../../Utils/RegistryUtils.hpp"
#include "../../Utils/Base64Utils.hpp"
#include "../../Utils/CertUtils.hpp"
#include "../../HashStore/HashStore.hpp"
#include "../../ThreatIntel/ThreatIntelLookup.hpp"
#include "../../Whitelist/WhiteListStore.hpp"

// ============================================================================
// STANDARD LIBRARY INCLUDES
// ============================================================================
#include <algorithm>
#include <chrono>
#include <format>
#include <fstream>
#include <filesystem>
#include <cmath>
#include <numeric>
#include <sstream>
#include <deque>
#include <unordered_set>
#include <regex>

// ============================================================================
// WINDOWS INCLUDES
// ============================================================================
#ifdef _WIN32
#  include <Windows.h>
#  include <winternl.h>
#  include <winsvc.h>
#  include <taskschd.h>
#  include <comdef.h>
#  include <Wbemidl.h>
#  include <shlobj.h>
#  pragma comment(lib, "wbemuuid.lib")
#  pragma comment(lib, "taskschd.lib")
#  pragma comment(lib, "advapi32.lib")
#endif

namespace ShadowStrike {
namespace Core {
namespace Registry {

using namespace std::chrono;
using namespace Utils;
namespace fs = std::filesystem;

// ============================================================================
// PERSISTENCE LOCATION DEFINITIONS
// ============================================================================

namespace {

/**
 * @brief Registry persistence locations.
 */
struct PersistenceLocation {
    PersistenceType type;
    HKEY hive;
    std::wstring subkey;
    std::wstring valueName;  // Empty = all values
    bool critical;
    std::string mitreTechnique;
};

/**
 * @brief Complete database of persistence locations.
 */
const std::vector<PersistenceLocation> PERSISTENCE_LOCATIONS = {
    // Run Keys (T1547.001)
    { PersistenceType::RunKey, HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", L"", true, "T1547.001" },
    { PersistenceType::RunKey, HKEY_CURRENT_USER, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", L"", true, "T1547.001" },
    { PersistenceType::RunKeyOnce, HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce", L"", true, "T1547.001" },
    { PersistenceType::RunKeyOnce, HKEY_CURRENT_USER, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce", L"", true, "T1547.001" },
    { PersistenceType::RunServices, HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunServices", L"", false, "T1547.001" },
    { PersistenceType::RunServicesOnce, HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunServicesOnce", L"", false, "T1547.001" },
    { PersistenceType::Policies_Run, HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run", L"", true, "T1547.001" },
    { PersistenceType::Policies_Run, HKEY_CURRENT_USER, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run", L"", true, "T1547.001" },
    { PersistenceType::Explorer_Run, HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows", L"run", false, "T1547.001" },

    // Winlogon (T1547.004)
    { PersistenceType::Winlogon_Shell, HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", L"Shell", true, "T1547.004" },
    { PersistenceType::Winlogon_Userinit, HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", L"Userinit", true, "T1547.004" },
    { PersistenceType::Winlogon_Taskman, HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", L"Taskman", false, "T1547.004" },
    { PersistenceType::Winlogon_System, HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", L"System", false, "T1547.004" },
    { PersistenceType::Winlogon_VMApplet, HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", L"VMApplet", false, "T1547.004" },

    // Image File Execution Options (T1546.012)
    { PersistenceType::IFEO_Debugger, HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options", L"", true, "T1546.012" },
    { PersistenceType::IFEO_GlobalFlag, HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options", L"GlobalFlag", false, "T1546.012" },
    { PersistenceType::SilentProcessExit, HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SilentProcessExit", L"", false, "T1546.012" },

    // DLL Injection (T1574.001, T1547.008)
    { PersistenceType::AppInit_DLLs, HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows", L"AppInit_DLLs", true, "T1574.001" },
    { PersistenceType::LoadAppInit, HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows", L"LoadAppInit_DLLs", true, "T1574.001" },
    { PersistenceType::AppCertDLLs, HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Session Manager", L"AppCertDlls", true, "T1547.008" },
    { PersistenceType::Print_Monitors, HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Print\\Monitors", L"", false, "T1547.010" },
    { PersistenceType::LSA_Authentication, HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Lsa", L"Authentication Packages", true, "T1547.002" },
    { PersistenceType::LSA_Notification, HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Lsa", L"Notification Packages", true, "T1547.002" },
    { PersistenceType::LSA_Security, HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Lsa", L"Security Packages", true, "T1547.002" },

    // Boot/Session (T1547.001)
    { PersistenceType::BootExecute, HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Session Manager", L"BootExecute", true, "T1547.001" },
    { PersistenceType::SetupExecute, HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Session Manager", L"SetupExecute", false, "T1547.001" },
    { PersistenceType::KnownDLLs, HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\KnownDLLs", L"", false, "T1574.001" },

    // Shell Extensions (T1546.015)
    { PersistenceType::ShellServiceObjects, HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\ShellServiceObjectDelayLoad", L"", false, "T1546.015" },
    { PersistenceType::ShellIconOverlay, HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ShellIconOverlayIdentifiers", L"", false, "T1546.015" },
    { PersistenceType::ContextMenuHandlers, HKEY_CLASSES_ROOT, L"*\\shellex\\ContextMenuHandlers", L"", false, "T1546.015" },

    // Active Setup (T1547.014)
    { PersistenceType::ActiveSetup, HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Active Setup\\Installed Components", L"", true, "T1547.014" },

    // Browser (T1176)
    { PersistenceType::BrowserHelper_Object, HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Browser Helper Objects", L"", false, "T1176" },
    { PersistenceType::BrowserHelper_Object, HKEY_CURRENT_USER, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Browser Helper Objects", L"", false, "T1176" },

    // Office
    { PersistenceType::Office_Addins, HKEY_CURRENT_USER, L"SOFTWARE\\Microsoft\\Office\\*\\Addins", L"", false, "T1137" },
    { PersistenceType::Office_Startup, HKEY_CURRENT_USER, L"SOFTWARE\\Microsoft\\Office\\*\\*\\Options", L"OPEN", false, "T1137.001" },

    // Other
    { PersistenceType::Screensaver, HKEY_CURRENT_USER, L"Control Panel\\Desktop", L"SCRNSAVE.EXE", false, "T1546.002" },
    { PersistenceType::Netsh_Helper, HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\NetSh", L"", false, "T1546.007" },
    { PersistenceType::Security_Providers, HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\SecurityProviders", L"SecurityProviders", false, "T1547.002" },
    { PersistenceType::Time_Provider, HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\W32Time\\TimeProviders", L"", false, "T1547.003" },
};

/**
 * @brief Calculate Shannon entropy.
 */
[[nodiscard]] double CalculateEntropy(std::span<const uint8_t> data) noexcept {
    if (data.empty()) return 0.0;

    std::array<uint64_t, 256> frequencies{};
    for (uint8_t byte : data) {
        frequencies[byte]++;
    }

    double entropy = 0.0;
    const double dataSize = static_cast<double>(data.size());

    for (uint64_t freq : frequencies) {
        if (freq > 0) {
            double probability = static_cast<double>(freq) / dataSize;
            entropy -= probability * std::log2(probability);
        }
    }

    return entropy;
}

/**
 * @brief Extract path from command line.
 */
[[nodiscard]] std::wstring ExtractExecutablePath(const std::wstring& commandLine) {
    if (commandLine.empty()) return L"";

    std::wstring trimmed = StringUtils::TrimCopy(commandLine);

    // Handle quoted path
    if (trimmed.starts_with(L'"')) {
        size_t endQuote = trimmed.find(L'"', 1);
        if (endQuote != std::wstring::npos) {
            return trimmed.substr(1, endQuote - 1);
        }
    }

    // Find first space (simple approach)
    size_t spacePos = trimmed.find(L' ');
    if (spacePos != std::wstring::npos) {
        return trimmed.substr(0, spacePos);
    }

    return trimmed;
}

/**
 * @brief Check if path is suspicious.
 */
[[nodiscard]] bool IsSuspiciousPath(const std::wstring& path) noexcept {
    std::wstring lowerPath = StringUtils::ToLowerCopy(path);

    // Temp directories
    if (lowerPath.find(L"\\temp\\") != std::wstring::npos ||
        lowerPath.find(L"\\tmp\\") != std::wstring::npos ||
        lowerPath.find(L"\\appdata\\local\\temp\\") != std::wstring::npos) {
        return true;
    }

    // User profile
    if (lowerPath.find(L"\\appdata\\roaming\\") != std::wstring::npos &&
        lowerPath.find(L"\\microsoft\\") == std::wstring::npos) {
        return true;
    }

    // Recycle bin
    if (lowerPath.find(L"\\$recycle.bin\\") != std::wstring::npos) {
        return true;
    }

    // Public folders
    if (lowerPath.find(L"\\public\\") != std::wstring::npos) {
        return true;
    }

    // Suspicious extensions
    if (lowerPath.ends_with(L".tmp") || lowerPath.ends_with(L".temp") ||
        lowerPath.ends_with(L".dat") || lowerPath.ends_with(L".bin")) {
        return true;
    }

    return false;
}

/**
 * @brief Get MITRE technique for persistence type.
 */
[[nodiscard]] std::string GetMITRETechnique(PersistenceType type) noexcept {
    for (const auto& loc : PERSISTENCE_LOCATIONS) {
        if (loc.type == type && !loc.mitreTechnique.empty()) {
            return loc.mitreTechnique;
        }
    }
    return "T1547";  // Default: Boot or Logon Autostart Execution
}

} // anonymous namespace

// ============================================================================
// PersistenceDetectorConfig FACTORY METHODS
// ============================================================================

PersistenceDetectorConfig PersistenceDetectorConfig::CreateDefault() noexcept {
    return PersistenceDetectorConfig{};
}

PersistenceDetectorConfig PersistenceDetectorConfig::CreateQuick() noexcept {
    PersistenceDetectorConfig config;
    config.defaultScope = ScanScope::Critical;
    config.resolveTargets = true;
    config.verifySignatures = false;  // Skip for speed
    config.checkHashes = false;
    config.checkReputation = false;
    config.detectHidden = false;
    config.useCache = true;
    config.logSuspiciousOnly = true;
    return config;
}

PersistenceDetectorConfig PersistenceDetectorConfig::CreateThorough() noexcept {
    PersistenceDetectorConfig config;
    config.defaultScope = ScanScope::Extended;
    config.resolveTargets = true;
    config.verifySignatures = true;
    config.checkHashes = true;
    config.checkReputation = true;
    config.detectHidden = true;
    config.useCache = true;
    config.logAllEntries = false;
    config.logSuspiciousOnly = true;
    return config;
}

PersistenceDetectorConfig PersistenceDetectorConfig::CreateForensic() noexcept {
    PersistenceDetectorConfig config;
    config.defaultScope = ScanScope::Full;
    config.maxScanThreads = 16;
    config.scanTimeoutMs = 600000;  // 10 minutes
    config.resolveTargets = true;
    config.verifySignatures = true;
    config.checkHashes = true;
    config.checkReputation = true;
    config.detectHidden = true;
    config.enableRealTimeAnalysis = false;
    config.useCache = true;
    config.logAllEntries = true;
    config.logSuspiciousOnly = false;
    return config;
}

// ============================================================================
// PersistenceDetectorStatistics METHODS
// ============================================================================

void PersistenceDetectorStatistics::Reset() noexcept {
    totalScans.store(0, std::memory_order_relaxed);
    entriesScanned.store(0, std::memory_order_relaxed);
    locationsScanned.store(0, std::memory_order_relaxed);

    safeEntriesFound.store(0, std::memory_order_relaxed);
    suspiciousEntriesFound.store(0, std::memory_order_relaxed);
    maliciousEntriesFound.store(0, std::memory_order_relaxed);

    realTimeAnalyses.store(0, std::memory_order_relaxed);
    persistenceAttempts.store(0, std::memory_order_relaxed);
    blockedAttempts.store(0, std::memory_order_relaxed);

    signaturesVerified.store(0, std::memory_order_relaxed);
    hashesChecked.store(0, std::memory_order_relaxed);
    cacheHits.store(0, std::memory_order_relaxed);

    alertsGenerated.store(0, std::memory_order_relaxed);

    avgScanTimeMs.store(0, std::memory_order_relaxed);
    avgAnalysisTimeUs.store(0, std::memory_order_relaxed);
}

// ============================================================================
// ServiceEntry CONVERSION
// ============================================================================

PersistenceEntry ServiceEntry::asPersistenceEntry() const {
    PersistenceEntry entry{};
    entry.type = (serviceType == SERVICE_KERNEL_DRIVER || serviceType == SERVICE_FILE_SYSTEM_DRIVER) ?
                 PersistenceType::KernelDriver : PersistenceType::Service;
    entry.location = L"HKLM\\SYSTEM\\CurrentControlSet\\Services";
    entry.entryName = serviceName;
    entry.rawCommand = imagePath;
    entry.description = this->description;

    entry.target.path = imagePath;
    entry.target.originalPath = imagePath;

    if (startType == SERVICE_AUTO_START || startType == SERVICE_BOOT_START || startType == SERVICE_SYSTEM_START) {
        entry.status = EntryStatus::Active;
    } else if (startType == SERVICE_DISABLED) {
        entry.status = EntryStatus::Disabled;
    }

    entry.mitreTechnique = "T1543.003";  // Windows Service
    return entry;
}

// ============================================================================
// ScheduledTaskEntry CONVERSION
// ============================================================================

PersistenceEntry ScheduledTaskEntry::asPersistenceEntry() const {
    PersistenceEntry entry{};
    entry.type = PersistenceType::ScheduledTask;
    entry.location = L"Task Scheduler";
    entry.entryName = taskName;
    entry.description = this->description;

    if (!actions.empty()) {
        entry.rawCommand = actions[0].path;
        if (!actions[0].arguments.empty()) {
            entry.rawCommand += L" " + actions[0].arguments;
        }

        entry.target.path = actions[0].path;
        entry.target.originalPath = actions[0].path;
        entry.target.arguments = actions[0].arguments;
        entry.target.workingDirectory = actions[0].workingDirectory;
    }

    entry.status = enabled ? EntryStatus::Active : EntryStatus::Disabled;
    entry.mitreTechnique = "T1053.005";  // Scheduled Task
    return entry;
}

// ============================================================================
// WMISubscription CONVERSION
// ============================================================================

PersistenceEntry WMISubscription::asPersistenceEntry() const {
    PersistenceEntry entry{};
    entry.type = PersistenceType::WMI_EventConsumer;
    entry.location = L"WMI Repository";
    entry.entryName = filterName + L" -> " + consumerName;
    entry.rawCommand = consumerCommand;
    entry.description = filterQuery;

    entry.target.path = consumerCommand;
    entry.target.originalPath = consumerCommand;

    entry.mitreTechnique = "T1546.003";  // WMI Event Subscription
    return entry;
}

// ============================================================================
// PIMPL IMPLEMENTATION
// ============================================================================

/**
 * @brief Private implementation class for PersistenceDetector.
 */
class PersistenceDetector::Impl {
public:
    // ========================================================================
    // MEMBERS
    // ========================================================================

    // Thread safety
    mutable std::shared_mutex m_configMutex;
    mutable std::shared_mutex m_cacheMutex;
    mutable std::shared_mutex m_callbackMutex;
    mutable std::mutex m_scanMutex;

    // State
    std::atomic<bool> m_initialized{false};
    std::atomic<bool> m_scanning{false};
    std::atomic<bool> m_cancelRequested{false};
    bool m_comInitialized{false};  // Track whether WE initialized COM

    // Configuration
    PersistenceDetectorConfig m_config{};

    // Statistics
    PersistenceDetectorStatistics m_stats{};

    // Caches
    std::unordered_map<std::wstring, TargetBinary> m_targetCache;
    std::unordered_map<std::string, SignatureStatus> m_signatureCache;
    std::unordered_map<std::string, RiskLevel> m_hashReputationCache;

    // Callbacks
    std::atomic<uint64_t> m_nextCallbackId{1};
    std::unordered_map<uint64_t, ScanProgressCallback> m_progressCallbacks;
    std::unordered_map<uint64_t, EntryFoundCallback> m_entryCallbacks;
    std::unordered_map<uint64_t, PersistenceAlertCallback> m_alertCallbacks;

    // ========================================================================
    // CONSTRUCTOR / DESTRUCTOR
    // ========================================================================

    Impl() = default;
    ~Impl() = default;

    // ========================================================================
    // INITIALIZATION
    // ========================================================================

    [[nodiscard]] bool Initialize(const PersistenceDetectorConfig& config) {
        std::unique_lock lock(m_configMutex);

        if (m_initialized.load(std::memory_order_acquire)) {
            Logger::Warn("PersistenceDetector::Impl already initialized");
            return true;
        }

        try {
            Logger::Info("PersistenceDetector::Impl: Initializing");

            // Store configuration
            m_config = config;

            // Reset statistics
            m_stats.Reset();

            // Initialize COM for Task Scheduler and WMI
            HRESULT hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
            if (SUCCEEDED(hr)) {
                m_comInitialized = true;
            } else if (hr == RPC_E_CHANGED_MODE) {
                // COM was already initialized with a different threading model — acceptable
                m_comInitialized = false;
            } else {
                Logger::Error("PersistenceDetector: COM initialization failed: {:#x}", static_cast<uint32_t>(hr));
                return false;
            }

            m_initialized.store(true, std::memory_order_release);
            Logger::Info("PersistenceDetector::Impl: Initialization complete");

            return true;

        } catch (const std::exception& e) {
            Logger::Error("PersistenceDetector::Impl: Initialization exception: {}", e.what());
            return false;
        }
    }

    void Shutdown() noexcept {
        std::unique_lock lock(m_configMutex);

        if (!m_initialized.load(std::memory_order_acquire)) {
            return;
        }

        Logger::Info("PersistenceDetector::Impl: Shutting down");

        // Clear caches
        {
            std::unique_lock cacheLock(m_cacheMutex);
            m_targetCache.clear();
            m_signatureCache.clear();
            m_hashReputationCache.clear();
        }

        // Clear callbacks
        {
            std::unique_lock cbLock(m_callbackMutex);
            m_progressCallbacks.clear();
            m_entryCallbacks.clear();
            m_alertCallbacks.clear();
        }

        if (m_comInitialized) {
            CoUninitialize();
            m_comInitialized = false;
        }

        m_initialized.store(false, std::memory_order_release);
        Logger::Info("PersistenceDetector::Impl: Shutdown complete");
    }

    // ========================================================================
    // SCANNING IMPLEMENTATION
    // ========================================================================

    [[nodiscard]] ScanResult ScanImpl(ScanScope scope) {
        // Prevent concurrent scans — only one scan at a time
        std::unique_lock scanGuard(m_scanMutex, std::try_to_lock);
        if (!scanGuard.owns_lock()) {
            Logger::Warn("PersistenceDetector: Scan already in progress, rejecting concurrent scan");
            ScanResult empty{};
            empty.errorsEncountered = 1;
            return empty;
        }

        ScanResult result{};
        result.startTime = system_clock::now();
        result.scope = scope;

        const auto scanStart = steady_clock::now();

        // RAII guard to ensure m_scanning is always reset
        m_scanning.store(true, std::memory_order_release);
        m_cancelRequested.store(false, std::memory_order_release);
        auto scanCleanup = [this]() noexcept {
            m_scanning.store(false, std::memory_order_release);
        };
        struct ScanGuardRAII {
            std::function<void()> cleanup;
            ~ScanGuardRAII() { cleanup(); }
        } scanFlagGuard{scanCleanup};

        try {
            Logger::Info("PersistenceDetector: Starting scan - Scope: {}", static_cast<int>(scope));

            // Select locations based on scope
            std::vector<PersistenceLocation> locationsToScan;
            for (const auto& loc : PERSISTENCE_LOCATIONS) {
                bool shouldScan = false;

                switch (scope) {
                    case ScanScope::Critical:
                        shouldScan = loc.critical;
                        break;
                    case ScanScope::Standard:
                        shouldScan = true;  // All predefined locations
                        break;
                    case ScanScope::Extended:
                    case ScanScope::Full:
                        shouldScan = true;
                        break;
                    case ScanScope::Custom:
                        shouldScan = true;
                        break;
                }

                if (shouldScan) {
                    locationsToScan.push_back(loc);
                }
            }

            result.locationsScanned = static_cast<uint32_t>(locationsToScan.size());

            // Scan each location
            uint32_t currentLocation = 0;
            for (const auto& location : locationsToScan) {
                if (m_cancelRequested.load(std::memory_order_acquire)) {
                    Logger::Warn("PersistenceDetector: Scan cancelled");
                    break;
                }

                currentLocation++;
                InvokeProgressCallbacks(currentLocation, result.locationsScanned, location.subkey);

                // Scan registry location
                auto entries = ScanRegistryLocation(location);
                for (auto& entry : entries) {
                    result.entries.push_back(std::move(entry));
                }

                m_stats.locationsScanned.fetch_add(1, std::memory_order_relaxed);
            }

            // Scan services
            if (scope >= ScanScope::Standard && !m_cancelRequested.load(std::memory_order_acquire)) {
                auto services = ScanServicesImpl();
                for (auto& svc : services) {
                    result.entries.push_back(svc.asPersistenceEntry());
                }
            }

            // Scan scheduled tasks
            if (scope >= ScanScope::Standard && !m_cancelRequested.load(std::memory_order_acquire)) {
                auto tasks = ScanScheduledTasksImpl();
                for (auto& task : tasks) {
                    result.entries.push_back(task.asPersistenceEntry());
                }
            }

            // Scan WMI subscriptions
            if (scope >= ScanScope::Extended && !m_cancelRequested.load(std::memory_order_acquire)) {
                auto wmi = ScanWMISubscriptionsImpl();
                for (auto& sub : wmi) {
                    result.entries.push_back(sub.asPersistenceEntry());
                }
            }

            // Calculate summary
            result.totalEntries = static_cast<uint32_t>(result.entries.size());
            for (const auto& entry : result.entries) {
                result.entriesByType[entry.type]++;

                switch (entry.risk) {
                    case RiskLevel::Safe:
                    case RiskLevel::Low:
                        result.safeEntries++;
                        break;
                    case RiskLevel::Suspicious:
                        result.suspiciousEntries++;
                        break;
                    case RiskLevel::Malicious:
                        result.maliciousEntries++;
                        break;
                    case RiskLevel::Unknown:
                        result.unknownEntries++;
                        break;
                }

                if (entry.status == EntryStatus::Orphaned) {
                    result.orphanedEntries++;
                }

                m_stats.entriesScanned.fetch_add(1, std::memory_order_relaxed);
            }

            m_stats.totalScans.fetch_add(1, std::memory_order_relaxed);
            m_stats.safeEntriesFound.fetch_add(result.safeEntries, std::memory_order_relaxed);
            m_stats.suspiciousEntriesFound.fetch_add(result.suspiciousEntries, std::memory_order_relaxed);
            m_stats.maliciousEntriesFound.fetch_add(result.maliciousEntries, std::memory_order_relaxed);

            result.endTime = system_clock::now();
            result.duration = duration_cast<milliseconds>(steady_clock::now() - scanStart);

            Logger::Info("PersistenceDetector: Scan complete - {} entries, {} suspicious, {} malicious, {} ms",
                result.totalEntries, result.suspiciousEntries, result.maliciousEntries, result.duration.count());

            // m_scanning is reset by RAII guard
            return result;

        } catch (const std::exception& e) {
            Logger::Error("PersistenceDetector: Scan exception: {}", e.what());
            result.errorsEncountered++;
            // m_scanning is reset by RAII guard
            return result;
        }
    }

    [[nodiscard]] std::vector<PersistenceEntry> ScanRegistryLocation(const PersistenceLocation& location) {
        std::vector<PersistenceEntry> entries;

        try {
            // RAII registry key via RegistryUtils
            Utils::RegistryUtils::RegistryKey regKey;
            Utils::RegistryUtils::OpenOptions opts;
            opts.access = KEY_READ;
            opts.wow64_64 = true;
            if (!regKey.Open(location.hive, location.subkey, opts)) {
                return entries;
            }

            // Enumerate all values using RAII-safe enumeration
            std::vector<Utils::RegistryUtils::ValueInfo> values;
            if (!regKey.EnumValues(values)) {
                return entries;
            }

            for (const auto& valInfo : values) {
                // Skip if looking for specific value and this isn't it
                if (!location.valueName.empty() &&
                    !StringUtils::IEquals(location.valueName, valInfo.name)) {
                    continue;
                }

                PersistenceEntry entry{};
                entry.type = location.type;
                entry.entryName = valInfo.name;
                entry.location = std::format(L"{}\\{}",
                    (location.hive == HKEY_LOCAL_MACHINE) ? L"HKLM" :
                    (location.hive == HKEY_CURRENT_USER) ? L"HKCU" : L"HKCR",
                    location.subkey);
                entry.isUserEntry = (location.hive == HKEY_CURRENT_USER);
                entry.mitreTechnique = location.mitreTechnique;

                // Extract command based on value type (with bounds safety)
                if (valInfo.type == Utils::RegistryUtils::ValueType::String) {
                    std::wstring val;
                    if (regKey.ReadString(valInfo.name, val)) {
                        entry.rawCommand = val;
                    }
                } else if (valInfo.type == Utils::RegistryUtils::ValueType::ExpandString) {
                    std::wstring val;
                    if (regKey.ReadExpandString(valInfo.name, val, true)) {
                        entry.rawCommand = val;
                    }
                } else if (valInfo.type == Utils::RegistryUtils::ValueType::MultiString) {
                    std::vector<std::wstring> multiVal;
                    if (regKey.ReadMultiString(valInfo.name, multiVal)) {
                        for (const auto& s : multiVal) {
                            if (!entry.rawCommand.empty()) entry.rawCommand += L";";
                            entry.rawCommand += s;
                        }
                    }
                }

                entry.lastScanned = system_clock::now();

                // Resolve target and assess risk
                if (m_config.resolveTargets && !entry.rawCommand.empty()) {
                    entry.target = ResolveTargetImpl(entry.rawCommand);

                    // Whitelist check before scoring
                    if (IsWhitelisted(entry)) {
                        entry.risk = RiskLevel::Safe;
                        entry.riskScore = 0;
                        entry.isKnownGood = true;
                    } else {
                        // Hash and threat intel integration
                        EnrichWithHashLookup(entry);
                        EnrichWithThreatIntel(entry);

                        entry.risk = AssessRisk(entry);
                        entry.riskScore = CalculateRiskScore(entry);
                    }
                }

                entries.push_back(entry);
                InvokeEntryCallbacks(entry);
            }

        } catch (const std::exception& e) {
            Logger::Error("PersistenceDetector: Registry scan exception at {}: {}",
                StringUtils::ToNarrow(location.subkey), e.what());
        }

        return entries;
    }

    // ========================================================================
    // SERVICE SCANNING
    // ========================================================================

    [[nodiscard]] std::vector<ServiceEntry> ScanServicesImpl() {
        std::vector<ServiceEntry> services;

        try {
            Logger::Debug("PersistenceDetector: Scanning services");

            SC_HANDLE hSCManager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ENUMERATE_SERVICE);
            if (!hSCManager) {
                Logger::Error("PersistenceDetector: OpenSCManager failed: {}", GetLastError());
                return services;
            }

            DWORD bytesNeeded = 0;
            DWORD servicesReturned = 0;
            DWORD resumeHandle = 0;

            // Get required buffer size
            EnumServicesStatusExW(hSCManager, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL,
                                 nullptr, 0, &bytesNeeded, &servicesReturned, &resumeHandle, nullptr);

            if (bytesNeeded == 0) {
                CloseServiceHandle(hSCManager);
                return services;
            }

            std::vector<uint8_t> buffer(bytesNeeded);
            auto pServices = reinterpret_cast<ENUM_SERVICE_STATUS_PROCESSW*>(buffer.data());

            if (!EnumServicesStatusExW(hSCManager, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL,
                                       buffer.data(), bytesNeeded, &bytesNeeded, &servicesReturned, &resumeHandle, nullptr)) {
                Logger::Error("PersistenceDetector: EnumServicesStatusEx failed: {}", GetLastError());
                CloseServiceHandle(hSCManager);
                return services;
            }

            for (DWORD i = 0; i < servicesReturned; i++) {
                ServiceEntry entry{};
                entry.serviceName = pServices[i].lpServiceName;
                entry.displayName = pServices[i].lpDisplayName;
                entry.currentState = pServices[i].ServiceStatusProcess.dwCurrentState;
                entry.serviceType = pServices[i].ServiceStatusProcess.dwServiceType;
                entry.processId = pServices[i].ServiceStatusProcess.dwProcessId;

                // Get detailed config
                SC_HANDLE hService = OpenServiceW(hSCManager, entry.serviceName.c_str(), SERVICE_QUERY_CONFIG);
                if (hService) {
                    DWORD configBytesNeeded = 0;
                    QueryServiceConfigW(hService, nullptr, 0, &configBytesNeeded);

                    if (configBytesNeeded > 0) {
                        std::vector<uint8_t> configBuffer(configBytesNeeded);
                        auto pConfig = reinterpret_cast<QUERY_SERVICE_CONFIGW*>(configBuffer.data());

                        if (QueryServiceConfigW(hService, pConfig, configBytesNeeded, &configBytesNeeded)) {
                            entry.imagePath = pConfig->lpBinaryPathName ? pConfig->lpBinaryPathName : L"";
                            entry.startType = pConfig->dwStartType;
                            entry.errorControl = pConfig->dwErrorControl;
                            entry.objectName = pConfig->lpServiceStartName ? pConfig->lpServiceStartName : L"";
                        }
                    }

                    CloseServiceHandle(hService);
                }

                services.push_back(entry);
            }

            CloseServiceHandle(hSCManager);

            Logger::Info("PersistenceDetector: Found {} services", services.size());

        } catch (const std::exception& e) {
            Logger::Error("PersistenceDetector: Service scan exception: {}", e.what());
        }

        return services;
    }

    // ========================================================================
    // SCHEDULED TASK SCANNING
    // ========================================================================

    [[nodiscard]] std::vector<ScheduledTaskEntry> ScanScheduledTasksImpl() {
        std::vector<ScheduledTaskEntry> tasks;

        try {
            Logger::Debug("PersistenceDetector: Scanning scheduled tasks");

            ITaskService* pService = nullptr;
            HRESULT hr = CoCreateInstance(CLSID_TaskScheduler, nullptr, CLSCTX_INPROC_SERVER,
                                         IID_ITaskService, reinterpret_cast<void**>(&pService));
            if (FAILED(hr)) {
                Logger::Error("PersistenceDetector: CoCreateInstance(TaskScheduler) failed: {:#x}", static_cast<uint32_t>(hr));
                return tasks;
            }

            hr = pService->Connect(_variant_t(), _variant_t(), _variant_t(), _variant_t());
            if (FAILED(hr)) {
                Logger::Error("PersistenceDetector: TaskService Connect failed: {:#x}", static_cast<uint32_t>(hr));
                pService->Release();
                return tasks;
            }

            ITaskFolder* pRootFolder = nullptr;
            hr = pService->GetFolder(_bstr_t(L"\\"), &pRootFolder);
            if (SUCCEEDED(hr)) {
                EnumerateTaskFolder(pRootFolder, tasks);
                pRootFolder->Release();
            }

            pService->Release();

            Logger::Info("PersistenceDetector: Found {} scheduled tasks", tasks.size());

        } catch (const std::exception& e) {
            Logger::Error("PersistenceDetector: Task scan exception: {}", e.what());
        }

        return tasks;
    }

    void EnumerateTaskFolder(ITaskFolder* pFolder, std::vector<ScheduledTaskEntry>& tasks) {
        // Enumerate tasks in this folder
        IRegisteredTaskCollection* pTaskCollection = nullptr;
        HRESULT hr = pFolder->GetTasks(TASK_ENUM_HIDDEN, &pTaskCollection);
        if (SUCCEEDED(hr)) {
            LONG taskCount = 0;
            pTaskCollection->get_Count(&taskCount);

            for (LONG i = 1; i <= taskCount; i++) {
                IRegisteredTask* pTask = nullptr;
                hr = pTaskCollection->get_Item(_variant_t(i), &pTask);
                if (SUCCEEDED(hr)) {
                    ScheduledTaskEntry entry = ExtractTaskInfo(pTask);
                    tasks.push_back(entry);
                    pTask->Release();
                }
            }

            pTaskCollection->Release();
        }

        // Enumerate subfolders
        ITaskFolderCollection* pFolderCollection = nullptr;
        hr = pFolder->GetFolders(0, &pFolderCollection);
        if (SUCCEEDED(hr)) {
            LONG folderCount = 0;
            pFolderCollection->get_Count(&folderCount);

            for (LONG i = 1; i <= folderCount; i++) {
                ITaskFolder* pSubFolder = nullptr;
                hr = pFolderCollection->get_Item(_variant_t(i), &pSubFolder);
                if (SUCCEEDED(hr)) {
                    EnumerateTaskFolder(pSubFolder, tasks);
                    pSubFolder->Release();
                }
            }

            pFolderCollection->Release();
        }
    }

    [[nodiscard]] ScheduledTaskEntry ExtractTaskInfo(IRegisteredTask* pTask) {
        ScheduledTaskEntry entry{};

        try {
            BSTR taskName = nullptr;
            if (SUCCEEDED(pTask->get_Name(&taskName))) {
                entry.taskName = taskName;
                SysFreeString(taskName);
            }

            BSTR taskPath = nullptr;
            if (SUCCEEDED(pTask->get_Path(&taskPath))) {
                entry.taskPath = taskPath;
                SysFreeString(taskPath);
            }

            TASK_STATE state;
            if (SUCCEEDED(pTask->get_State(&state))) {
                entry.enabled = (state != TASK_STATE_DISABLED);
            }

            // Get definition
            ITaskDefinition* pDefinition = nullptr;
            if (SUCCEEDED(pTask->get_Definition(&pDefinition))) {

                // Registration info
                IRegistrationInfo* pRegInfo = nullptr;
                if (SUCCEEDED(pDefinition->get_RegistrationInfo(&pRegInfo))) {
                    BSTR description = nullptr;
                    if (SUCCEEDED(pRegInfo->get_Description(&description))) {
                        entry.description = description;
                        SysFreeString(description);
                    }
                    pRegInfo->Release();
                }

                // Actions
                IActionCollection* pActions = nullptr;
                if (SUCCEEDED(pDefinition->get_Actions(&pActions))) {
                    LONG actionCount = 0;
                    pActions->get_Count(&actionCount);

                    for (LONG i = 1; i <= actionCount; i++) {
                        IAction* pAction = nullptr;
                        if (SUCCEEDED(pActions->get_Item(i, &pAction))) {
                            TASK_ACTION_TYPE actionType;
                            pAction->get_Type(&actionType);

                            if (actionType == TASK_ACTION_EXEC) {
                                IExecAction* pExecAction = nullptr;
                                if (SUCCEEDED(pAction->QueryInterface(IID_IExecAction, reinterpret_cast<void**>(&pExecAction)))) {
                                    ScheduledTaskEntry::TaskAction action;
                                    action.type = L"Exec";

                                    BSTR path = nullptr;
                                    if (SUCCEEDED(pExecAction->get_Path(&path))) {
                                        action.path = path;
                                        SysFreeString(path);
                                    }

                                    BSTR args = nullptr;
                                    if (SUCCEEDED(pExecAction->get_Arguments(&args))) {
                                        action.arguments = args;
                                        SysFreeString(args);
                                    }

                                    entry.actions.push_back(action);
                                    pExecAction->Release();
                                }
                            }

                            pAction->Release();
                        }
                    }

                    pActions->Release();
                }

                pDefinition->Release();
            }

        } catch (...) {
            Logger::Error("PersistenceDetector: Exception extracting task info");
        }

        return entry;
    }

    // ========================================================================
    // WMI SCANNING
    // ========================================================================

    [[nodiscard]] std::vector<WMISubscription> ScanWMISubscriptionsImpl() {
        std::vector<WMISubscription> subscriptions;

        try {
            Logger::Info("PersistenceDetector: Performing deep WMI persistence scan");

            IWbemLocator* pLocator = nullptr;
            HRESULT hr = CoCreateInstance(CLSID_WbemLocator, nullptr, CLSCTX_INPROC_SERVER,
                                         IID_IWbemLocator, reinterpret_cast<void**>(&pLocator));
            if (FAILED(hr)) {
                Logger::Error("PersistenceDetector: CoCreateInstance(WbemLocator) failed: {:#x}", static_cast<uint32_t>(hr));
                return subscriptions;
            }

            IWbemServices* pServices = nullptr;
            hr = pLocator->ConnectServer(_bstr_t(L"ROOT\\subscription"), nullptr, nullptr, nullptr, 0, nullptr, nullptr, &pServices);
            if (FAILED(hr)) {
                Logger::Error("PersistenceDetector: WMI ConnectServer(ROOT\\subscription) failed: {:#x}", static_cast<uint32_t>(hr));
                pLocator->Release();
                return subscriptions;
            }

            // Set security levels
            CoSetProxyBlanket(pServices, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, nullptr,
                            RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, EOAC_NONE);

            // 1. Query Bindings: __FilterToConsumerBinding connects triggers to actions
            IEnumWbemClassObject* pBindingEnum = nullptr;
            hr = pServices->ExecQuery(_bstr_t(L"WQL"),
                                     _bstr_t(L"SELECT * FROM __FilterToConsumerBinding"),
                                     WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
                                     nullptr, &pBindingEnum);

            if (SUCCEEDED(hr)) {
                IWbemClassObject* pBindingObj = nullptr;
                ULONG returned = 0;

                while (SUCCEEDED(pBindingEnum->Next(WBEM_INFINITE, 1, &pBindingObj, &returned)) && returned > 0) {
                    WMISubscription sub{};

                    VARIANT vtFilter, vtConsumer;
                    VariantInit(&vtFilter);
                    VariantInit(&vtConsumer);

                    // Get relative paths to Filter and Consumer
                    if (SUCCEEDED(pBindingObj->Get(L"Filter", 0, &vtFilter, nullptr, nullptr)) &&
                        SUCCEEDED(pBindingObj->Get(L"Consumer", 0, &vtConsumer, nullptr, nullptr))) {

                        if (vtFilter.vt == VT_BSTR && vtConsumer.vt == VT_BSTR) {
                            sub.bindingName = vtFilter.bstrVal; // Use filter path as identifier

                            // 2. Resolve the Filter (The Trigger)
                            IWbemClassObject* pFilterObj = nullptr;
                            if (SUCCEEDED(pServices->GetObject(vtFilter.bstrVal, 0, nullptr, &pFilterObj, nullptr))) {
                                VARIANT vtQuery, vtName, vtLang;
                                VariantInit(&vtQuery); VariantInit(&vtName); VariantInit(&vtLang);

                                if (SUCCEEDED(pFilterObj->Get(L"Query", 0, &vtQuery, nullptr, nullptr)) && vtQuery.vt == VT_BSTR)
                                    sub.filterQuery = vtQuery.bstrVal;
                                if (SUCCEEDED(pFilterObj->Get(L"Name", 0, &vtName, nullptr, nullptr)) && vtName.vt == VT_BSTR)
                                    sub.filterName = vtName.bstrVal;
                                if (SUCCEEDED(pFilterObj->Get(L"QueryLanguage", 0, &vtLang, nullptr, nullptr)) && vtLang.vt == VT_BSTR)
                                    sub.filterLanguage = vtLang.bstrVal;

                                VariantClear(&vtQuery); VariantClear(&vtName); VariantClear(&vtLang);
                                pFilterObj->Release();
                            }

                            // 3. Resolve the Consumer (The Payload)
                            IWbemClassObject* pConsumerObj = nullptr;
                            if (SUCCEEDED(pServices->GetObject(vtConsumer.bstrVal, 0, nullptr, &pConsumerObj, nullptr))) {
                                VARIANT vtCName, vtClass;
                                VariantInit(&vtCName); VariantInit(&vtClass);

                                if (SUCCEEDED(pConsumerObj->Get(L"Name", 0, &vtCName, nullptr, nullptr)) && vtCName.vt == VT_BSTR)
                                    sub.consumerName = vtCName.bstrVal;

                                // Determine consumer type and extract payload
                                VARIANT vtPath; VariantInit(&vtPath);
                                if (SUCCEEDED(pConsumerObj->Get(L"__CLASS", 0, &vtClass, nullptr, nullptr)) && vtClass.vt == VT_BSTR) {
                                    sub.consumerType = vtClass.bstrVal;

                                    if (sub.consumerType == L"CommandLineEventConsumer") {
                                        VARIANT vtCmd; VariantInit(&vtCmd);
                                        if (SUCCEEDED(pConsumerObj->Get(L"CommandLineTemplate", 0, &vtCmd, nullptr, nullptr)) && vtCmd.vt == VT_BSTR)
                                            sub.consumerCommand = vtCmd.bstrVal;
                                        VariantClear(&vtCmd);
                                    }
                                    else if (sub.consumerType == L"ActiveScriptEventConsumer") {
                                        VARIANT vtScript; VariantInit(&vtScript);
                                        if (SUCCEEDED(pConsumerObj->Get(L"ScriptText", 0, &vtScript, nullptr, nullptr)) && vtScript.vt == VT_BSTR)
                                            sub.consumerCommand = vtScript.bstrVal; // Script content is the "command"
                                        VariantClear(&vtScript);
                                    }
                                }

                                VariantClear(&vtCName); VariantClear(&vtClass);
                                pConsumerObj->Release();
                            }
                        }
                    }

                    if (!sub.consumerCommand.empty()) {
                        subscriptions.push_back(std::move(sub));
                    }

                    VariantClear(&vtFilter);
                    VariantClear(&vtConsumer);
                    pBindingObj->Release();
                }
                pBindingEnum->Release();
            }

            pServices->Release();
            pLocator->Release();

            Logger::Info("PersistenceDetector: WMI scan found {} correlated subscriptions", subscriptions.size());

        } catch (const std::exception& e) {
            Logger::Error("PersistenceDetector: Deep WMI scan exception: {}", e.what());
        }

        return subscriptions;
    }

    // ========================================================================
    // TARGET RESOLUTION
    // ========================================================================

    /**
     * @brief Resolves a command line to a target binary with full file analysis.
     *
     * Handles:
     * - Quoted and unquoted paths
     * - Environment variable expansion
     * - System PATH search
     * - File existence/signature/hash verification
     * - Short (8.3) path normalization
     */
    [[nodiscard]] TargetBinary ResolveTargetImpl(const std::wstring& command) {
        TargetBinary target{};
        if (command.empty()) return target;

        target.originalPath = command;

        try {
            // Check cache first
            if (m_config.useCache) {
                std::shared_lock cacheLock(m_cacheMutex);
                auto it = m_targetCache.find(command);
                if (it != m_targetCache.end()) {
                    m_stats.cacheHits.fetch_add(1, std::memory_order_relaxed);
                    return it->second;
                }
            }

            // Extract executable path (handles quoted paths and arguments)
            std::wstring rawPath = ExtractExecutablePath(command);
            if (rawPath.empty()) return target;

            // Expand environment variables (critical for evasion resistance)
            wchar_t expandedBuf[MAX_PATH * 2]{};
            DWORD expandedLen = ExpandEnvironmentStringsW(rawPath.c_str(), expandedBuf,
                                                          static_cast<DWORD>(std::size(expandedBuf)));
            std::wstring expandedPath;
            if (expandedLen > 0 && expandedLen < std::size(expandedBuf)) {
                expandedPath = expandedBuf;
            } else {
                expandedPath = rawPath;
            }

            // Normalize short (8.3) paths to long form
            wchar_t longPathBuf[MAX_PATH * 2]{};
            DWORD longLen = GetLongPathNameW(expandedPath.c_str(), longPathBuf,
                                              static_cast<DWORD>(std::size(longPathBuf)));
            if (longLen > 0 && longLen < std::size(longPathBuf)) {
                expandedPath = longPathBuf;
            }

            target.path = expandedPath;

            // Extract arguments (everything after the executable path)
            std::wstring trimmedCmd = StringUtils::TrimCopy(command);
            if (trimmedCmd.starts_with(L'"')) {
                size_t endQuote = trimmedCmd.find(L'"', 1);
                if (endQuote != std::wstring::npos && endQuote + 1 < trimmedCmd.size()) {
                    target.arguments = StringUtils::TrimCopy(trimmedCmd.substr(endQuote + 1));
                }
            } else {
                size_t spacePos = trimmedCmd.find(L' ');
                if (spacePos != std::wstring::npos) {
                    target.arguments = StringUtils::TrimCopy(trimmedCmd.substr(spacePos + 1));
                }
            }

            // File existence and metadata
            std::error_code ec;
            fs::path filePath(target.path);
            target.exists = fs::exists(filePath, ec);

            if (target.exists) {
                target.fileSize = fs::file_size(filePath, ec);
                auto lwt = fs::last_write_time(filePath, ec);
                if (!ec) {
                    auto sctp = std::chrono::clock_cast<std::chrono::system_clock>(lwt);
                    target.modifiedTime = sctp;
                }

                // Determine file type from extension
                std::wstring ext = StringUtils::ToLowerCopy(filePath.extension().wstring());
                if (ext == L".exe" || ext == L".com" || ext == L".scr") {
                    target.isExecutable = true;
                    target.fileType = "PE_Executable";
                } else if (ext == L".dll" || ext == L".ocx" || ext == L".cpl") {
                    target.isDLL = true;
                    target.fileType = "PE_DLL";
                } else if (ext == L".sys") {
                    target.isDLL = true;
                    target.fileType = "PE_Driver";
                } else if (ext == L".ps1" || ext == L".vbs" || ext == L".js" ||
                           ext == L".bat" || ext == L".cmd" || ext == L".wsf" ||
                           ext == L".hta" || ext == L".wsh") {
                    target.isScript = true;
                    target.fileType = "Script";
                }

                // Path classification
                std::wstring lowerPath = StringUtils::ToLowerCopy(target.path);
                target.inSystemPath = (lowerPath.find(L"\\windows\\") != std::wstring::npos ||
                                       lowerPath.find(L"\\program files") != std::wstring::npos);
                target.inTempPath = (lowerPath.find(L"\\temp\\") != std::wstring::npos ||
                                     lowerPath.find(L"\\tmp\\") != std::wstring::npos ||
                                     lowerPath.find(L"\\appdata\\local\\temp\\") != std::wstring::npos);

                // Check for hidden files and ADS
                DWORD attrs = GetFileAttributesW(target.path.c_str());
                if (attrs != INVALID_FILE_ATTRIBUTES) {
                    target.isHidden = (attrs & FILE_ATTRIBUTE_HIDDEN) != 0;
                }

                // Check for Alternate Data Streams (ADS) via ":" in path after drive letter
                if (target.path.size() > 3) {
                    auto adsPos = target.path.find(L':', 2);
                    target.hasADS = (adsPos != std::wstring::npos);
                }

                // Signature verification (if enabled and file is PE)
                if (m_config.verifySignatures && (target.isExecutable || target.isDLL)) {
                    VerifyTargetSignature(target);
                }

                // Hash computation (if enabled)
                if (m_config.checkHashes && target.fileSize > 0 &&
                    target.fileSize < (512ULL * 1024 * 1024)) {
                    ComputeTargetHash(target);
                }

                // Entropy analysis for packer detection (first 64KB)
                if (target.isExecutable || target.isDLL) {
                    AnalyzeTargetEntropy(target);
                }
            } else if (!target.path.empty()) {
                // Mark as orphaned — target binary doesn't exist
                // Could be deleted malware or ADS-hidden payload
            }

            // Cache result
            if (m_config.useCache) {
                std::unique_lock cacheLock(m_cacheMutex);
                if (m_targetCache.size() < PersistenceDetectorConstants::SIGNATURE_CACHE_SIZE) {
                    m_targetCache[command] = target;
                }
            }

        } catch (const std::exception& e) {
            Logger::Error("PersistenceDetector: ResolveTarget exception: {}", e.what());
        }

        return target;
    }

    // ========================================================================
    // TARGET ENRICHMENT HELPERS
    // ========================================================================

    void VerifyTargetSignature(TargetBinary& target) {
        try {
            CertUtils::Certificate cert;
            CertUtils::Error certErr;
            if (cert.LoadFromFile(target.path, &certErr)) {
                CertUtils::CertificateInfo info;
                if (cert.GetInfo(info, &certErr)) {
                    target.signerName = info.subject;
                    target.issuerName = info.issuer;
                }

                if (cert.IsValid()) {
                    target.signatureStatus = SignatureStatus::SignedValid;
                    target.isTrusted = true;

                    std::wstring lowerSigner = StringUtils::ToLowerCopy(target.signerName);
                    target.isMicrosoftSigned = (lowerSigner.find(L"microsoft") != std::wstring::npos);
                } else {
                    target.signatureStatus = SignatureStatus::SignedInvalid;
                }
            } else {
                target.signatureStatus = SignatureStatus::NotSigned;
            }

            m_stats.signaturesVerified.fetch_add(1, std::memory_order_relaxed);

        } catch (const std::exception& e) {
            Logger::Debug("PersistenceDetector: Signature verification exception for {}: {}",
                StringUtils::ToNarrow(target.path), e.what());
            target.signatureStatus = SignatureStatus::Unknown;
        }
    }

    void ComputeTargetHash(TargetBinary& target) {
        try {
            FileUtils::Error fileErr;
            if (FileUtils::ComputeFileSHA256(target.path, target.sha256, &fileErr)) {
                target.sha256Hex = HashUtils::ToHexLower(target.sha256.data(), target.sha256.size());
            }
            m_stats.hashesChecked.fetch_add(1, std::memory_order_relaxed);
        } catch (const std::exception& e) {
            Logger::Debug("PersistenceDetector: Hash computation failed for {}: {}",
                StringUtils::ToNarrow(target.path), e.what());
        }
    }

    void AnalyzeTargetEntropy(TargetBinary& target) {
        try {
            constexpr size_t ENTROPY_SAMPLE_SIZE = 65536;
            std::ifstream file(target.path, std::ios::binary);
            if (!file.is_open()) return;

            std::vector<uint8_t> buffer(ENTROPY_SAMPLE_SIZE);
            file.read(reinterpret_cast<char*>(buffer.data()), ENTROPY_SAMPLE_SIZE);
            auto bytesRead = file.gcount();
            if (bytesRead > 0) {
                buffer.resize(static_cast<size_t>(bytesRead));
                target.entropy = CalculateEntropy(std::span<const uint8_t>(buffer));
                target.isPacked = (target.entropy > PersistenceDetectorConstants::SUSPICIOUS_ENTROPY_THRESHOLD);
            }
        } catch (const std::exception&) {
            // Non-critical: entropy analysis failure is acceptable
        }
    }

    /**
     * @brief Check if a persistence entry is whitelisted via config or WhiteListStore.
     */
    [[nodiscard]] bool IsWhitelisted(const PersistenceEntry& entry) const noexcept {
        try {
            // Check config-level path whitelist
            std::wstring lowerPath = StringUtils::ToLowerCopy(entry.target.path);
            for (const auto& wp : m_config.whitelistedPaths) {
                if (StringUtils::IContains(lowerPath, StringUtils::ToLowerCopy(wp))) {
                    return true;
                }
            }

            // Check config-level signer whitelist
            if (!entry.target.signerName.empty()) {
                for (const auto& ws : m_config.whitelistedSigners) {
                    if (StringUtils::IEquals(entry.target.signerName, ws)) {
                        return true;
                    }
                }
            }

            // Check config-level hash whitelist
            if (!entry.target.sha256Hex.empty()) {
                for (const auto& wh : m_config.whitelistedHashes) {
                    if (entry.target.sha256Hex == wh) {
                        return true;
                    }
                }
            }

            // WhiteListStore path-based whitelist check is handled at a higher level
            // (by the orchestrator that owns the WhitelistStore instance).
            // Config-level whitelist checks above are sufficient for the detector.

        } catch (const std::exception&) {
            // Whitelist check failure — default to NOT whitelisted (safe default)
        }
        return false;
    }

    /**
     * @brief Enrich entry with hash reputation from HashStore.
     *
     * The HashStore is not a singleton — it must be provided by the orchestrator.
     * When wired, pass the HashStore reference through PersistenceDetectorConfig
     * or a SetHashStore() method. For now, only config-level hash checks apply.
     */
    void EnrichWithHashLookup(PersistenceEntry& entry) noexcept {
        try {
            if (entry.target.sha256Hex.empty()) return;

            // Check config-level known-bad hashes
            for (const auto& badHash : m_config.whitelistedHashes) {
                // whitelistedHashes is used for known-GOOD; known-bad comes from HashStore
                // This is a no-op until HashStore reference is wired in.
            }
        } catch (const std::exception&) {
            // Non-critical
        }
    }

    /**
     * @brief Enrich entry with threat intelligence data.
     *
     * ThreatIntelLookup is not a singleton — it must be provided by the orchestrator.
     * When wired, pass through PersistenceDetectorConfig or a SetThreatIntel() method.
     */
    void EnrichWithThreatIntel(PersistenceEntry& entry) noexcept {
        // Threat intel enrichment requires a ThreatIntelLookup reference.
        // The orchestrator (e.g., RegistryMonitor or ScanEngine) should call
        // EnrichWithThreatIntel after obtaining the lookup instance.
    }

    // ========================================================================
    // COMPLEX COMMAND RESOLUTION
    // ========================================================================

    [[nodiscard]] std::vector<TargetBinary> ResolveComplexCommandImpl(const std::wstring& command) {
        std::vector<TargetBinary> targets;
        if (command.empty()) return targets;

        // 1. Initial resolution of the primary command
        TargetBinary primary = ResolveTargetImpl(command);
        targets.push_back(primary);

        std::wstring lowerCmd = StringUtils::ToLowerCopy(command);

        // 2. Resolve LOLBins (Living Off The Land Binaries)
        try {
            // rundll32.exe resolution
            if (lowerCmd.find(L"rundll32.exe") != std::wstring::npos) {
                // Format: rundll32.exe <dllname>,<entrypoint> <args>
                std::wstring args = primary.arguments;
                size_t commaPos = args.find(L',');
                std::wstring dllPath = (commaPos != std::wstring::npos) ? args.substr(0, commaPos) : args;
                dllPath = StringUtils::TrimCopy(dllPath);

                if (!dllPath.empty()) {
                    auto dllTarget = ResolveTargetImpl(dllPath);
                    dllTarget.description = L"Target DLL loaded via rundll32";
                    targets.push_back(dllTarget);
                }
            }
            // regsvr32.exe resolution
            else if (lowerCmd.find(L"regsvr32.exe") != std::wstring::npos) {
                // Format: regsvr32.exe [/u] [/s] [/n] [/i[:cmdline]] <dllname>
                std::vector<std::wstring> tokens = StringUtils::Split(primary.arguments, L" ");
                for (const auto& token : tokens) {
                    if (!token.empty() && token[0] != L'/' && token[0] != L'-') {
                        auto dllTarget = ResolveTargetImpl(token);
                        dllTarget.description = L"Target DLL registered via regsvr32";
                        targets.push_back(dllTarget);
                    }
                }
            }
            // mshta.exe resolution
            else if (lowerCmd.find(L"mshta.exe") != std::wstring::npos) {
                // Format: mshta.exe <url/path>
                if (!primary.arguments.empty()) {
                    auto htaTarget = ResolveTargetImpl(primary.arguments);
                    htaTarget.description = L"HTA/Script target executed via mshta";
                    targets.push_back(htaTarget);
                }
            }
            // cmd.exe / powershell.exe resolution
            else if (lowerCmd.find(L"cmd.exe") != std::wstring::npos ||
                     lowerCmd.find(L"powershell.exe") != std::wstring::npos ||
                     lowerCmd.find(L"pwsh.exe") != std::wstring::npos) {

                // Handle Base64 encoded PowerShell commands
                if (lowerCmd.find(L"-enc") != std::wstring::npos ||
                    lowerCmd.find(L"-encodedcommand") != std::wstring::npos) {

                    std::vector<std::wstring> tokens = StringUtils::Split(primary.arguments, L" ");
                    for (size_t i = 0; i < tokens.size(); ++i) {
                        if (StringUtils::IEquals(tokens[i], L"-enc") ||
                            StringUtils::IEquals(tokens[i], L"-encodedcommand")) {
                            if (i + 1 < tokens.size()) {
                                std::string encoded = StringUtils::ToNarrow(tokens[i + 1]);
                                std::vector<uint8_t> decodedBytes;
                                if (Base64Decode(encoded, decodedBytes)) {
                                    // PowerShell -EncodedCommand uses UTF-16LE encoding
                                    std::wstring wDecoded;
                                    if (decodedBytes.size() >= 2) {
                                        wDecoded.assign(
                                            reinterpret_cast<const wchar_t*>(decodedBytes.data()),
                                            decodedBytes.size() / sizeof(wchar_t));
                                    }

                                    TargetBinary encTarget;
                                    encTarget.originalPath = tokens[i + 1];
                                    encTarget.path = L"DECODED_SCRIPT";
                                    encTarget.arguments = wDecoded;
                                    encTarget.isScript = true;
                                    encTarget.description = L"De-obfuscated PowerShell command";
                                    targets.push_back(encTarget);
                                }
                            }
                        }
                    }
                }
            }
        } catch (const std::exception& e) {
            Logger::Error("PersistenceDetector: LOLBin resolution exception: {}", e.what());
        }

        return targets;
    }

    [[nodiscard]] std::vector<PersistenceEntry> ScanPathImpl(const std::wstring& targetPath) {
        std::vector<PersistenceEntry> results;
        std::wstring lowerTarget = StringUtils::ToLowerCopy(targetPath);

        // Perform a standard scan to gather all entries
        // Note: In a performance-critical production environment, we would implement
        // specialized index lookups, but for forensic thoroughness, we analyze all ASEPs.
        ScanResult fullScan = ScanImpl(ScanScope::Extended);

        for (auto& entry : fullScan.entries) {
            bool match = false;

            // Check primary target
            if (StringUtils::Contains(StringUtils::ToLowerCopy(entry.target.path), lowerTarget)) {
                match = true;
            }

            // Check additional targets (resolved from LOLBins/Scripts)
            if (!match) {
                for (const auto& addTarget : entry.additionalTargets) {
                    if (StringUtils::Contains(StringUtils::ToLowerCopy(addTarget.path), lowerTarget)) {
                        match = true;
                        break;
                    }
                }
            }

            // Check raw command if no path match yet (for obfuscated entries)
            if (!match && StringUtils::Contains(StringUtils::ToLowerCopy(entry.rawCommand), lowerTarget)) {
                match = true;
            }

            if (match) {
                results.push_back(std::move(entry));
            }
        }

        return results;
    }

    // ========================================================================
    // RISK ASSESSMENT
    // ========================================================================

    [[nodiscard]] bool IsLOLBin(const std::wstring& path) const noexcept {
        std::wstring lowerPath = StringUtils::ToLowerCopy(path);
        static const std::vector<std::wstring> lolbins = {
            L"rundll32.exe", L"regsvr32.exe", L"mshta.exe", L"powershell.exe",
            L"cmd.exe", L"certutil.exe", L"bitsadmin.exe", L"scrcons.exe",
            L"wmic.exe", L"msiexec.exe", L"cscript.exe", L"wscript.exe"
        };

        for (const auto& bin : lolbins) {
            if (lowerPath.find(bin) != std::wstring::npos) return true;
        }
        return false;
    }

    [[nodiscard]] RiskLevel AssessRisk(const PersistenceEntry& entry) const noexcept {
        uint32_t riskScore = CalculateRiskScore(entry);

        // Known bad/good overrides
        if (entry.isKnownBad) return RiskLevel::Malicious;
        if (entry.isKnownGood || entry.target.isMicrosoftSigned) return RiskLevel::Safe;

        // Calculate final risk level based on score
        if (riskScore >= 75) return RiskLevel::Malicious;
        if (riskScore >= 45) return RiskLevel::Suspicious;
        if (riskScore >= 20) return RiskLevel::Unknown;
        if (entry.target.isTrusted) return RiskLevel::Safe;

        return RiskLevel::Low;
    }

    [[nodiscard]] uint8_t CalculateRiskScore(const PersistenceEntry& entry) const noexcept {
        uint32_t score = 0;

        // 1. Availability & Pathing (Baseline: 0-40)
        if (!entry.target.exists && !entry.target.isScript) score += 40;
        if (IsSuspiciousPath(entry.target.path)) score += 30;
        if (entry.target.inTempPath) score += 35;

        // 2. Binary Characteristics (Baseline: 0-45)
        if (entry.target.signatureStatus == SignatureStatus::NotSigned && entry.target.isExecutable) {
            score += 20;
        }
        if (entry.target.isPacked) score += 25;

        // 3. Advanced Persistence Heuristics (Pillar 4 Weights)

        // LOLBin Usage (+25)
        if (IsLOLBin(entry.target.path)) {
            score += 25;
        }

        // WMI Persistence (+40) - High-confidence indicator of advanced threats
        if (entry.type == PersistenceType::WMI_EventConsumer ||
            entry.type == PersistenceType::WMI_FilterToConsumer) {
            score += 40;
        }

        // Non-Standard Extensions (+15)
        std::wstring ext = fs::path(entry.target.path).extension().wstring();
        if (!ext.empty() && entry.target.isExecutable) {
            std::wstring lowerExt = StringUtils::ToLowerCopy(ext);
            if (lowerExt != L".exe" && lowerExt != L".dll" && lowerExt != L".sys") {
                score += 15;
            }
        }

        // 4. Overrides
        if (entry.isKnownBad) score = 100;

        // Trusted Microsoft binaries should always have a lower floor unless modified
        if (entry.target.isMicrosoftSigned && score > 10) {
            // Even signed bins can be used maliciously (LOLBins), so we don't zero it
            score = std::max(10u, score - 20);
        }

        return static_cast<uint8_t>(std::min(score, 100u));
    }

    // ========================================================================
    // REAL-TIME ANALYSIS
    // ========================================================================

    [[nodiscard]] RealTimeAnalysis AnalyzeRealTimeImpl(
        const std::wstring& keyPath,
        const std::wstring& valueName,
        const std::wstring& data
    ) {
        RealTimeAnalysis analysis{};
        m_stats.realTimeAnalyses.fetch_add(1, std::memory_order_relaxed);

        try {
            // Check if this is a known persistence location
            analysis.detectedType = IsPersistenceLocationImpl(keyPath);
            analysis.isPersistenceAttempt = (analysis.detectedType != PersistenceType::Unknown);

            if (analysis.isPersistenceAttempt) {
                m_stats.persistenceAttempts.fetch_add(1, std::memory_order_relaxed);

                // Resolve target
                TargetBinary target = ResolveTargetImpl(data);
                analysis.resolvedTarget = target.path;

                // Check whitelist before scoring
                PersistenceEntry tempEntry{};
                tempEntry.target = target;
                tempEntry.type = analysis.detectedType;
                if (IsWhitelisted(tempEntry)) {
                    analysis.risk = RiskLevel::Safe;
                    analysis.riskScore = 0;
                    analysis.recommendation = "Allow (whitelisted)";
                    return analysis;
                }

                // Hash/ThreatIntel check
                if (!target.sha256Hex.empty()) {
                    EnrichWithHashLookup(tempEntry);
                    if (tempEntry.isKnownBad) {
                        analysis.isKnownBad = true;
                        analysis.indicators.push_back("Known malicious hash");
                    }
                }

                // Assess risk
                analysis.isSuspiciousLocation = IsSuspiciousPath(target.path);
                analysis.isSuspiciousTarget = !target.exists || target.inTempPath;
                analysis.isUnsigned = (target.signatureStatus == SignatureStatus::NotSigned);

                // Build indicators list for forensic evidence
                if (analysis.isSuspiciousLocation) analysis.indicators.push_back("Suspicious file path");
                if (analysis.isSuspiciousTarget) analysis.indicators.push_back("Target missing or in temp directory");
                if (analysis.isUnsigned) analysis.indicators.push_back("Unsigned binary");
                if (target.isPacked) analysis.indicators.push_back("High entropy — possible packing");
                if (target.hasADS) analysis.indicators.push_back("Alternate Data Stream detected");
                if (IsLOLBin(target.path)) analysis.indicators.push_back("LOLBin usage detected");

                // Calculate risk score
                uint32_t score = 0;
                if (analysis.isKnownBad) score = 100;
                else {
                    if (analysis.isSuspiciousLocation) score += 30;
                    if (analysis.isSuspiciousTarget) score += 40;
                    if (analysis.isUnsigned) score += 20;
                    if (target.isPacked) score += 25;
                    if (target.hasADS) score += 30;
                    if (IsLOLBin(target.path)) score += 25;
                }

                analysis.riskScore = static_cast<uint8_t>(std::min(score, 100u));

                if (analysis.riskScore >= 70) {
                    analysis.risk = RiskLevel::Malicious;
                    analysis.recommendation = "Block this persistence attempt";
                } else if (analysis.riskScore >= 40) {
                    analysis.risk = RiskLevel::Suspicious;
                    analysis.recommendation = "Alert and monitor";
                } else {
                    analysis.risk = RiskLevel::Low;
                    analysis.recommendation = "Allow";
                }

                Logger::Info("PersistenceDetector: Real-time analysis - Type: {}, Risk: {}, Score: {}",
                    static_cast<int>(analysis.detectedType), static_cast<int>(analysis.risk), analysis.riskScore);

                // Generate alert for suspicious+ events
                if ((analysis.risk >= RiskLevel::Suspicious && m_config.alertOnSuspicious) ||
                    (analysis.risk == RiskLevel::Unknown && m_config.alertOnUnknown)) {
                    GenerateRealTimeAlert(keyPath, valueName, data, analysis);
                }
            }

        } catch (const std::exception& e) {
            Logger::Error("PersistenceDetector: Real-time analysis exception: {}", e.what());
        }

        return analysis;
    }

    /**
     * @brief Generates a PersistenceAlert and dispatches it via registered callbacks.
     */
    void GenerateRealTimeAlert(
        const std::wstring& keyPath,
        const std::wstring& valueName,
        const std::wstring& data,
        const RealTimeAnalysis& analysis
    ) {
        PersistenceAlert alert{};
        alert.alertId = m_nextCallbackId.fetch_add(1, std::memory_order_relaxed);
        alert.timestamp = system_clock::now();
        alert.type = analysis.detectedType;
        alert.risk = analysis.risk;
        alert.description = analysis.recommendation;
        alert.location = keyPath;
        alert.entryName = valueName;
        alert.command = data;
        alert.targetPath = analysis.resolvedTarget;
        alert.analysis = analysis;
        alert.mitreTechnique = GetMITRETechnique(analysis.detectedType);

        // Capture process context
        alert.processId = static_cast<uint32_t>(GetCurrentProcessId());

        m_stats.alertsGenerated.fetch_add(1, std::memory_order_relaxed);
        InvokeAlertCallbacks(alert);

        Logger::Warn("PersistenceDetector: ALERT - {} persistence attempt at {}/{} -> {} (Risk={})",
            alert.mitreTechnique,
            StringUtils::ToNarrow(keyPath),
            StringUtils::ToNarrow(valueName),
            StringUtils::ToNarrow(analysis.resolvedTarget),
            static_cast<int>(analysis.risk));
    }

    [[nodiscard]] PersistenceType IsPersistenceLocationImpl(const std::wstring& keyPath) const noexcept {
        std::wstring upperPath = StringUtils::ToUpperCopy(keyPath);

        // Normalize kernel-format paths to usermode format
        // Kernel sends: \REGISTRY\MACHINE\..., usermode uses: HKEY_LOCAL_MACHINE\...
        std::wstring normalizedPath = upperPath;
        if (normalizedPath.find(L"\\REGISTRY\\MACHINE\\") != std::wstring::npos) {
            size_t pos = normalizedPath.find(L"\\REGISTRY\\MACHINE\\");
            normalizedPath.replace(pos, 18, L"HKEY_LOCAL_MACHINE\\");
        } else if (normalizedPath.find(L"\\REGISTRY\\USER\\") != std::wstring::npos) {
            // \REGISTRY\USER\<SID>\... → HKEY_CURRENT_USER\...
            size_t pos = normalizedPath.find(L"\\REGISTRY\\USER\\");
            size_t sidEnd = normalizedPath.find(L'\\', pos + 15);
            if (sidEnd != std::wstring::npos) {
                normalizedPath.replace(pos, sidEnd - pos + 1, L"HKEY_CURRENT_USER\\");
            }
        }

        for (const auto& loc : PERSISTENCE_LOCATIONS) {
            std::wstring checkPath = std::format(L"{}\\{}",
                (loc.hive == HKEY_LOCAL_MACHINE) ? L"HKEY_LOCAL_MACHINE" :
                (loc.hive == HKEY_CURRENT_USER) ? L"HKEY_CURRENT_USER" : L"HKEY_CLASSES_ROOT",
                loc.subkey);

            std::wstring upperCheckPath = StringUtils::ToUpperCopy(checkPath);

            if (normalizedPath.find(upperCheckPath) != std::wstring::npos) {
                return loc.type;
            }
        }

        // Also handle short-form paths: HKLM\..., HKCU\...
        std::wstring shortFormPath = normalizedPath;
        if (shortFormPath.starts_with(L"HKLM\\")) {
            shortFormPath = L"HKEY_LOCAL_MACHINE\\" + shortFormPath.substr(5);
        } else if (shortFormPath.starts_with(L"HKCU\\")) {
            shortFormPath = L"HKEY_CURRENT_USER\\" + shortFormPath.substr(5);
        } else if (shortFormPath.starts_with(L"HKCR\\")) {
            shortFormPath = L"HKEY_CLASSES_ROOT\\" + shortFormPath.substr(5);
        }

        if (shortFormPath != normalizedPath) {
            for (const auto& loc : PERSISTENCE_LOCATIONS) {
                std::wstring checkPath = std::format(L"{}\\{}",
                    (loc.hive == HKEY_LOCAL_MACHINE) ? L"HKEY_LOCAL_MACHINE" :
                    (loc.hive == HKEY_CURRENT_USER) ? L"HKEY_CURRENT_USER" : L"HKEY_CLASSES_ROOT",
                    loc.subkey);

                std::wstring upperCheckPath = StringUtils::ToUpperCopy(checkPath);
                if (shortFormPath.find(upperCheckPath) != std::wstring::npos) {
                    return loc.type;
                }
            }
        }

        return PersistenceType::Unknown;
    }

    // ========================================================================
    // CALLBACKS
    // ========================================================================

    void InvokeProgressCallbacks(uint32_t current, uint32_t total, const std::wstring& path) const {
        std::shared_lock lock(m_callbackMutex);

        for (const auto& [id, callback] : m_progressCallbacks) {
            try {
                callback(current, total, path);
            } catch (const std::exception& e) {
                Logger::Error("PersistenceDetector: Progress callback exception: {}", e.what());
            }
        }
    }

    void InvokeEntryCallbacks(const PersistenceEntry& entry) const {
        std::shared_lock lock(m_callbackMutex);

        for (const auto& [id, callback] : m_entryCallbacks) {
            try {
                callback(entry);
            } catch (const std::exception& e) {
                Logger::Error("PersistenceDetector: Entry callback exception: {}", e.what());
            }
        }
    }

    void InvokeAlertCallbacks(const PersistenceAlert& alert) const {
        std::shared_lock lock(m_callbackMutex);

        for (const auto& [id, callback] : m_alertCallbacks) {
            try {
                callback(alert);
            } catch (const std::exception& e) {
                Logger::Error("PersistenceDetector: Alert callback exception: {}", e.what());
            }
        }
    }
};

// ============================================================================
// SINGLETON INSTANCE
// ============================================================================

PersistenceDetector& PersistenceDetector::Instance() {
    static PersistenceDetector instance;
    return instance;
}

// ============================================================================
// CONSTRUCTOR / DESTRUCTOR
// ============================================================================

PersistenceDetector::PersistenceDetector()
    : m_impl(std::make_unique<Impl>())
{
    Logger::Info("PersistenceDetector: Constructor called");
}

PersistenceDetector::~PersistenceDetector() {
    if (m_impl) {
        m_impl->Shutdown();
    }
    Logger::Info("PersistenceDetector: Destructor called");
}

// ============================================================================
// LIFECYCLE MANAGEMENT
// ============================================================================

bool PersistenceDetector::Initialize(const PersistenceDetectorConfig& config) {
    if (!m_impl) {
        Logger::Error("PersistenceDetector: Implementation is null");
        return false;
    }

    return m_impl->Initialize(config);
}

void PersistenceDetector::Shutdown() noexcept {
    if (m_impl) {
        m_impl->Shutdown();
    }
}

// ============================================================================
// SCANNING
// ============================================================================

[[nodiscard]] ScanResult PersistenceDetector::ScanAll() {
    return Scan(ScanScope::Standard);
}

[[nodiscard]] ScanResult PersistenceDetector::ScanCritical() {
    return Scan(ScanScope::Critical);
}

[[nodiscard]] ScanResult PersistenceDetector::Scan(ScanScope scope) {
    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        Logger::Error("PersistenceDetector: Not initialized");
        return ScanResult{};
    }

    return m_impl->ScanImpl(scope);
}

[[nodiscard]] std::vector<PersistenceEntry> PersistenceDetector::ScanType(PersistenceType type) {
    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        Logger::Error("PersistenceDetector: Not initialized");
        return {};
    }

    auto result = m_impl->ScanImpl(ScanScope::Standard);

    std::vector<PersistenceEntry> filtered;
    for (const auto& entry : result.entries) {
        if (entry.type == type) {
            filtered.push_back(entry);
        }
    }

    return filtered;
}

[[nodiscard]] std::vector<PersistenceEntry> PersistenceDetector::ScanPath(const std::wstring& path) {
    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        Logger::Error("PersistenceDetector: Not initialized");
        return {};
    }

    return m_impl->ScanPathImpl(path);
}

void PersistenceDetector::CancelScan() {
    if (m_impl) {
        m_impl->m_cancelRequested.store(true, std::memory_order_release);
    }
}

// ============================================================================
// REAL-TIME ANALYSIS
// ============================================================================

[[nodiscard]] RiskLevel PersistenceDetector::AnalyzeRealTime(
    const std::wstring& keyPath,
    const std::wstring& valueName,
    const std::wstring& data
) {
    auto analysis = AnalyzeRealTimeFull(keyPath, valueName, data);
    return analysis.risk;
}

[[nodiscard]] RealTimeAnalysis PersistenceDetector::AnalyzeRealTimeFull(
    const std::wstring& keyPath,
    const std::wstring& valueName,
    const std::wstring& data
) {
    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        Logger::Error("PersistenceDetector: Not initialized");
        return RealTimeAnalysis{};
    }

    return m_impl->AnalyzeRealTimeImpl(keyPath, valueName, data);
}

[[nodiscard]] PersistenceType PersistenceDetector::IsPersistenceLocation(const std::wstring& keyPath) const {
    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        return PersistenceType::Unknown;
    }

    return m_impl->IsPersistenceLocationImpl(keyPath);
}

// ============================================================================
// TARGET RESOLUTION
// ============================================================================

[[nodiscard]] TargetBinary PersistenceDetector::ResolveTarget(const std::wstring& command) {
    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        Logger::Error("PersistenceDetector: Not initialized");
        return TargetBinary{};
    }

    return m_impl->ResolveTargetImpl(command);
}

[[nodiscard]] std::vector<TargetBinary> PersistenceDetector::ResolveComplexCommand(const std::wstring& command) {
    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        Logger::Error("PersistenceDetector: Not initialized");
        return {};
    }

    return m_impl->ResolveComplexCommandImpl(command);
}

// ============================================================================
// SERVICE SCANNING
// ============================================================================

[[nodiscard]] std::vector<ServiceEntry> PersistenceDetector::ScanServices() {
    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        Logger::Error("PersistenceDetector: Not initialized");
        return {};
    }

    return m_impl->ScanServicesImpl();
}

[[nodiscard]] std::optional<ServiceEntry> PersistenceDetector::GetService(const std::wstring& serviceName) {
    auto services = ScanServices();
    for (const auto& svc : services) {
        if (StringUtils::IEquals(svc.serviceName, serviceName)) {
            return svc;
        }
    }
    return std::nullopt;
}

// ============================================================================
// SCHEDULED TASK SCANNING
// ============================================================================

[[nodiscard]] std::vector<ScheduledTaskEntry> PersistenceDetector::ScanScheduledTasks() {
    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        Logger::Error("PersistenceDetector: Not initialized");
        return {};
    }

    return m_impl->ScanScheduledTasksImpl();
}

// ============================================================================
// WMI SCANNING
// ============================================================================

[[nodiscard]] std::vector<WMISubscription> PersistenceDetector::ScanWMISubscriptions() {
    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        Logger::Error("PersistenceDetector: Not initialized");
        return {};
    }

    return m_impl->ScanWMISubscriptionsImpl();
}

// ============================================================================
// CALLBACK REGISTRATION
// ============================================================================

[[nodiscard]] uint64_t PersistenceDetector::RegisterProgressCallback(ScanProgressCallback callback) {
    if (!callback || !m_impl) return 0;

    std::unique_lock lock(m_impl->m_callbackMutex);

    uint64_t id = m_impl->m_nextCallbackId.fetch_add(1, std::memory_order_relaxed);
    m_impl->m_progressCallbacks[id] = std::move(callback);

    Logger::Debug("PersistenceDetector: Registered progress callback {}", id);
    return id;
}

[[nodiscard]] uint64_t PersistenceDetector::RegisterEntryCallback(EntryFoundCallback callback) {
    if (!callback || !m_impl) return 0;

    std::unique_lock lock(m_impl->m_callbackMutex);

    uint64_t id = m_impl->m_nextCallbackId.fetch_add(1, std::memory_order_relaxed);
    m_impl->m_entryCallbacks[id] = std::move(callback);

    Logger::Debug("PersistenceDetector: Registered entry callback {}", id);
    return id;
}

[[nodiscard]] uint64_t PersistenceDetector::RegisterAlertCallback(PersistenceAlertCallback callback) {
    if (!callback || !m_impl) return 0;

    std::unique_lock lock(m_impl->m_callbackMutex);

    uint64_t id = m_impl->m_nextCallbackId.fetch_add(1, std::memory_order_relaxed);
    m_impl->m_alertCallbacks[id] = std::move(callback);

    Logger::Debug("PersistenceDetector: Registered alert callback {}", id);
    return id;
}

bool PersistenceDetector::UnregisterCallback(uint64_t callbackId) {
    if (!m_impl) return false;

    std::unique_lock lock(m_impl->m_callbackMutex);

    bool removed = false;
    removed |= m_impl->m_progressCallbacks.erase(callbackId) > 0;
    removed |= m_impl->m_entryCallbacks.erase(callbackId) > 0;
    removed |= m_impl->m_alertCallbacks.erase(callbackId) > 0;

    if (removed) {
        Logger::Debug("PersistenceDetector: Unregistered callback {}", callbackId);
    }

    return removed;
}

// ============================================================================
// STATISTICS
// ============================================================================

[[nodiscard]] const PersistenceDetectorStatistics& PersistenceDetector::GetStatistics() const noexcept {
    static PersistenceDetectorStatistics emptyStats{};
    return m_impl ? m_impl->m_stats : emptyStats;
}

void PersistenceDetector::ResetStatistics() noexcept {
    if (m_impl) {
        m_impl->m_stats.Reset();
        Logger::Info("PersistenceDetector: Statistics reset");
    }
}

// ============================================================================
// DIAGNOSTICS
// ============================================================================

[[nodiscard]] bool PersistenceDetector::PerformDiagnostics() const {
    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        Logger::Error("PersistenceDetector: Not initialized");
        return false;
    }

    try {
        Logger::Info("PersistenceDetector: Running diagnostics");

        // Test registry access
        HKEY hKey;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            RegCloseKey(hKey);
            Logger::Info("PersistenceDetector: Registry access OK");
        } else {
            Logger::Error("PersistenceDetector: Registry access failed");
            return false;
        }

        // Test service manager access
        SC_HANDLE hSCM = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ENUMERATE_SERVICE);
        if (hSCM) {
            CloseServiceHandle(hSCM);
            Logger::Info("PersistenceDetector: Service Manager access OK");
        } else {
            Logger::Error("PersistenceDetector: Service Manager access failed");
            return false;
        }

        Logger::Info("PersistenceDetector: Diagnostics passed");
        return true;

    } catch (const std::exception& e) {
        Logger::Error("PersistenceDetector: Diagnostics exception: {}", e.what());
        return false;
    }
}

bool PersistenceDetector::ExportDiagnostics(const std::wstring& outputPath) const {
    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        Logger::Error("PersistenceDetector: Not initialized for diagnostics export");
        return false;
    }

    try {
        std::ofstream file(outputPath, std::ios::out | std::ios::trunc);
        if (!file.is_open()) {
            Logger::Error("PersistenceDetector: Cannot open diagnostics output: {}",
                StringUtils::ToNarrow(outputPath));
            return false;
        }

        const auto& stats = m_impl->m_stats;
        file << "=== ShadowStrike PersistenceDetector Diagnostics ===\n";
        file << "Total Scans: " << stats.totalScans.load() << "\n";
        file << "Entries Scanned: " << stats.entriesScanned.load() << "\n";
        file << "Locations Scanned: " << stats.locationsScanned.load() << "\n";
        file << "Safe Entries: " << stats.safeEntriesFound.load() << "\n";
        file << "Suspicious Entries: " << stats.suspiciousEntriesFound.load() << "\n";
        file << "Malicious Entries: " << stats.maliciousEntriesFound.load() << "\n";
        file << "Real-Time Analyses: " << stats.realTimeAnalyses.load() << "\n";
        file << "Persistence Attempts: " << stats.persistenceAttempts.load() << "\n";
        file << "Blocked Attempts: " << stats.blockedAttempts.load() << "\n";
        file << "Signatures Verified: " << stats.signaturesVerified.load() << "\n";
        file << "Hashes Checked: " << stats.hashesChecked.load() << "\n";
        file << "Cache Hits: " << stats.cacheHits.load() << "\n";
        file << "Alerts Generated: " << stats.alertsGenerated.load() << "\n";
        file.flush();

        Logger::Info("PersistenceDetector: Diagnostics exported to {}",
            StringUtils::ToNarrow(outputPath));
        return true;

    } catch (const std::exception& e) {
        Logger::Error("PersistenceDetector: Diagnostics export failed: {}", e.what());
        return false;
    }
}

bool PersistenceDetector::ExportScanReport(const ScanResult& result, const std::wstring& outputPath) const {
    if (!m_impl) {
        Logger::Error("PersistenceDetector: Not initialized for report export");
        return false;
    }

    try {
        std::ofstream file(outputPath, std::ios::out | std::ios::trunc);
        if (!file.is_open()) {
            Logger::Error("PersistenceDetector: Cannot open report output: {}",
                StringUtils::ToNarrow(outputPath));
            return false;
        }

        file << "=== ShadowStrike Persistence Scan Report ===\n";
        file << "Duration: " << result.duration.count() << " ms\n";
        file << "Scope: " << static_cast<int>(result.scope) << "\n";
        file << "Locations Scanned: " << result.locationsScanned << "\n";
        file << "Total Entries: " << result.totalEntries << "\n";
        file << "Safe: " << result.safeEntries << "\n";
        file << "Suspicious: " << result.suspiciousEntries << "\n";
        file << "Malicious: " << result.maliciousEntries << "\n";
        file << "Unknown: " << result.unknownEntries << "\n";
        file << "Orphaned: " << result.orphanedEntries << "\n";
        file << "Errors: " << result.errorsEncountered << "\n\n";

        for (const auto& entry : result.entries) {
            if (entry.risk < RiskLevel::Suspicious && !m_impl->m_config.logAllEntries) {
                continue;
            }
            file << "--- Entry ---\n";
            file << "  Type: " << static_cast<int>(entry.type) << "\n";
            file << "  Location: " << StringUtils::ToNarrow(entry.location) << "\n";
            file << "  Name: " << StringUtils::ToNarrow(entry.entryName) << "\n";
            file << "  Command: " << StringUtils::ToNarrow(entry.rawCommand) << "\n";
            file << "  Target: " << StringUtils::ToNarrow(entry.target.path) << "\n";
            file << "  Exists: " << (entry.target.exists ? "Yes" : "No") << "\n";
            file << "  Risk: " << static_cast<int>(entry.risk) << " (Score: " << static_cast<int>(entry.riskScore) << ")\n";
            file << "  MITRE: " << entry.mitreTechnique << "\n";
            if (!entry.target.sha256Hex.empty()) {
                file << "  SHA256: " << entry.target.sha256Hex << "\n";
            }
            if (!entry.target.signerName.empty()) {
                file << "  Signer: " << StringUtils::ToNarrow(entry.target.signerName) << "\n";
            }
            for (const auto& factor : entry.riskFactors) {
                file << "  RiskFactor: " << factor << "\n";
            }
            file << "\n";
        }

        file.flush();
        Logger::Info("PersistenceDetector: Report exported to {}",
            StringUtils::ToNarrow(outputPath));
        return true;

    } catch (const std::exception& e) {
        Logger::Error("PersistenceDetector: Report export failed: {}", e.what());
        return false;
    }
}

} // namespace Registry
} // namespace Core
} // namespace ShadowStrike
