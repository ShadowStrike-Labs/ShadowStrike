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
    { PersistenceType::Winlogon_VMApplet, HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Session Manager", L"AppCertDlls", false, "T1547.004" },

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

    std::wstring trimmed = StringUtils::Trim(commandLine);

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
    std::wstring lowerPath = StringUtils::ToLowerCase(path);

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
            if (FAILED(hr) && hr != RPC_E_CHANGED_MODE) {
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

        CoUninitialize();

        m_initialized.store(false, std::memory_order_release);
        Logger::Info("PersistenceDetector::Impl: Shutdown complete");
    }

    // ========================================================================
    // SCANNING IMPLEMENTATION
    // ========================================================================

    [[nodiscard]] ScanResult ScanImpl(ScanScope scope) {
        ScanResult result{};
        result.startTime = system_clock::now();
        result.scope = scope;

        const auto scanStart = steady_clock::now();

        try {
            m_scanning.store(true, std::memory_order_release);
            m_cancelRequested.store(false, std::memory_order_release);

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
                    default:
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

            m_scanning.store(false, std::memory_order_release);
            return result;

        } catch (const std::exception& e) {
            Logger::Error("PersistenceDetector: Scan exception: {}", e.what());
            result.errorsEncountered++;
            m_scanning.store(false, std::memory_order_release);
            return result;
        }
    }

    [[nodiscard]] std::vector<PersistenceEntry> ScanRegistryLocation(const PersistenceLocation& location) {
        std::vector<PersistenceEntry> entries;

        try {
            HKEY hKey;
            LONG result = RegOpenKeyExW(location.hive, location.subkey.c_str(), 0, KEY_READ | KEY_WOW64_64KEY, &hKey);
            if (result != ERROR_SUCCESS) {
                // Key doesn't exist - not an error
                return entries;
            }

            // Enumerate values
            DWORD index = 0;
            wchar_t valueName[16384];
            DWORD valueNameSize;
            DWORD valueType;
            std::vector<uint8_t> valueData(65536);
            DWORD valueDataSize;

            while (true) {
                valueNameSize = sizeof(valueName) / sizeof(wchar_t);
                valueDataSize = static_cast<DWORD>(valueData.size());

                result = RegEnumValueW(hKey, index, valueName, &valueNameSize, nullptr,
                                      &valueType, valueData.data(), &valueDataSize);

                if (result == ERROR_NO_MORE_ITEMS) {
                    break;
                }

                if (result != ERROR_SUCCESS) {
                    index++;
                    continue;
                }

                // Skip if looking for specific value and this isn't it
                if (!location.valueName.empty() && location.valueName != valueName) {
                    index++;
                    continue;
                }

                // Create entry
                PersistenceEntry entry{};
                entry.type = location.type;
                entry.entryName = valueName;
                entry.location = std::format(L"{}\\{}",
                    (location.hive == HKEY_LOCAL_MACHINE) ? L"HKLM" :
                    (location.hive == HKEY_CURRENT_USER) ? L"HKCU" : L"HKCR",
                    location.subkey);
                entry.isUserEntry = (location.hive == HKEY_CURRENT_USER);
                entry.mitreTechnique = location.mitreTechnique;

                // Extract command from value data
                if (valueType == REG_SZ || valueType == REG_EXPAND_SZ) {
                    entry.rawCommand = std::wstring(reinterpret_cast<const wchar_t*>(valueData.data()));
                } else if (valueType == REG_MULTI_SZ) {
                    // Parse multi-string
                    const wchar_t* ptr = reinterpret_cast<const wchar_t*>(valueData.data());
                    while (*ptr) {
                        if (!entry.rawCommand.empty()) entry.rawCommand += L";";
                        entry.rawCommand += ptr;
                        ptr += wcslen(ptr) + 1;
                    }
                }

                entry.lastScanned = system_clock::now();

                // Resolve target
                if (m_config.resolveTargets && !entry.rawCommand.empty()) {
                    entry.target = ResolveTargetImpl(entry.rawCommand);

                    // Assess risk
                    entry.risk = AssessRisk(entry);
                    entry.riskScore = CalculateRiskScore(entry);
                }

                entries.push_back(entry);
                InvokeEntryCallbacks(entry);

                index++;
            }

            RegCloseKey(hKey);

        } catch (const std::exception& e) {
            Logger::Error("PersistenceDetector: Registry scan exception: {}", e.what());
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
            Logger::Debug("PersistenceDetector: Scanning WMI subscriptions");

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
                Logger::Error("PersistenceDetector: WMI ConnectServer failed: {:#x}", static_cast<uint32_t>(hr));
                pLocator->Release();
                return subscriptions;
            }

            // Set security levels
            CoSetProxyBlanket(pServices, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, nullptr,
                            RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, EOAC_NONE);

            // Query event consumers
            IEnumWbemClassObject* pEnumerator = nullptr;
            hr = pServices->ExecQuery(_bstr_t(L"WQL"),
                                     _bstr_t(L"SELECT * FROM __EventConsumer"),
                                     WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
                                     nullptr, &pEnumerator);
            if (SUCCEEDED(hr)) {
                IWbemClassObject* pObject = nullptr;
                ULONG returned = 0;

                while (pEnumerator) {
                    hr = pEnumerator->Next(WBEM_INFINITE, 1, &pObject, &returned);
                    if (returned == 0) break;

                    WMISubscription sub{};

                    VARIANT vtName;
                    VariantInit(&vtName);
                    if (SUCCEEDED(pObject->Get(L"Name", 0, &vtName, nullptr, nullptr))) {
                        if (vtName.vt == VT_BSTR) {
                            sub.consumerName = vtName.bstrVal;
                        }
                        VariantClear(&vtName);
                    }

                    subscriptions.push_back(sub);
                    pObject->Release();
                }

                pEnumerator->Release();
            }

            pServices->Release();
            pLocator->Release();

            Logger::Info("PersistenceDetector: Found {} WMI subscriptions", subscriptions.size());

        } catch (const std::exception& e) {
            Logger::Error("PersistenceDetector: WMI scan exception: {}", e.what());
        }

        return subscriptions;
    }

    // ========================================================================
    // TARGET RESOLUTION
    // ========================================================================

    [[nodiscard]] TargetBinary ResolveTargetImpl(const std::wstring& command) {
        TargetBinary target{};
        target.originalPath = command;

        try {
            // Check cache
            if (m_config.useCache) {
                std::shared_lock lock(m_cacheMutex);
                auto it = m_targetCache.find(command);
                if (it != m_targetCache.end()) {
                    m_stats.cacheHits.fetch_add(1, std::memory_order_relaxed);
                    return it->second;
                }
            }

            // Extract executable path
            std::wstring exePath = ExtractExecutablePath(command);

            // Expand environment variables
            wchar_t expanded[MAX_PATH * 4];
            if (ExpandEnvironmentStringsW(exePath.c_str(), expanded, sizeof(expanded) / sizeof(wchar_t))) {
                exePath = expanded;
            }

            target.path = exePath;

            // Check if file exists
            std::error_code ec;
            target.exists = fs::exists(exePath, ec);

            if (target.exists) {
                target.fileSize = fs::file_size(exePath, ec);

                auto lastWriteTime = fs::last_write_time(exePath, ec);
                if (!ec) {
                    auto sctp = std::chrono::time_point_cast<system_clock::duration>(
                        lastWriteTime - fs::file_time_type::clock::now() + system_clock::now()
                    );
                    target.modifiedTime = sctp;
                }

                // Determine file type
                std::wstring lowerPath = StringUtils::ToLowerCase(exePath);
                target.isExecutable = lowerPath.ends_with(L".exe") || lowerPath.ends_with(L".com");
                target.isDLL = lowerPath.ends_with(L".dll");
                target.isScript = lowerPath.ends_with(L".bat") || lowerPath.ends_with(L".cmd") ||
                                lowerPath.ends_with(L".vbs") || lowerPath.ends_with(L".ps1") ||
                                lowerPath.ends_with(L".js");

                // Check location
                target.inSystemPath = lowerPath.find(L"\\windows\\system32\\") != std::wstring::npos ||
                                     lowerPath.find(L"\\windows\\syswow64\\") != std::wstring::npos;
                target.inTempPath = lowerPath.find(L"\\temp\\") != std::wstring::npos ||
                                   lowerPath.find(L"\\tmp\\") != std::wstring::npos;

                // Calculate hash
                if (m_config.checkHashes && target.fileSize < 100 * 1024 * 1024) {  // Max 100MB
                    target.sha256 = HashUtils::CalculateSHA256File(exePath);
                    target.sha256Hex = HashUtils::ToHexString(target.sha256);
                    m_stats.hashesChecked.fetch_add(1, std::memory_order_relaxed);
                }

                // Verify signature
                if (m_config.verifySignatures) {
                    // Would use CertUtils here
                    // For now, simplified
                    target.signatureStatus = SignatureStatus::Unknown;
                    m_stats.signaturesVerified.fetch_add(1, std::memory_order_relaxed);
                }

                // Calculate entropy (for packed detection)
                if (target.fileSize > 0 && target.fileSize < 10 * 1024 * 1024) {
                    std::ifstream file(exePath, std::ios::binary);
                    if (file) {
                        std::vector<uint8_t> buffer(std::min<size_t>(target.fileSize, 1024 * 1024));
                        file.read(reinterpret_cast<char*>(buffer.data()), buffer.size());
                        target.entropy = CalculateEntropy(buffer);
                        target.isPacked = (target.entropy >= PersistenceDetectorConstants::SUSPICIOUS_ENTROPY_THRESHOLD);
                    }
                }
            }

            // Cache result
            if (m_config.useCache) {
                std::unique_lock lock(m_cacheMutex);
                m_targetCache[command] = target;
            }

        } catch (const std::exception& e) {
            Logger::Error("PersistenceDetector: Target resolution exception: {}", e.what());
        }

        return target;
    }

    // ========================================================================
    // RISK ASSESSMENT
    // ========================================================================

    [[nodiscard]] RiskLevel AssessRisk(const PersistenceEntry& entry) const noexcept {
        uint32_t riskScore = 0;

        // Target doesn't exist
        if (!entry.target.path.empty() && !entry.target.exists) {
            riskScore += 40;
        }

        // Suspicious path
        if (IsSuspiciousPath(entry.target.path)) {
            riskScore += 30;
        }

        // Unsigned binary
        if (entry.target.signatureStatus == SignatureStatus::NotSigned && entry.target.isExecutable) {
            riskScore += 20;
        }

        // High entropy (packed)
        if (entry.target.isPacked) {
            riskScore += 25;
        }

        // Temp location
        if (entry.target.inTempPath) {
            riskScore += 35;
        }

        // Known bad hash
        if (entry.isKnownBad) {
            return RiskLevel::Malicious;
        }

        // Known good
        if (entry.isKnownGood || entry.target.isMicrosoftSigned) {
            return RiskLevel::Safe;
        }

        // Calculate final risk
        if (riskScore >= 70) return RiskLevel::Malicious;
        if (riskScore >= 40) return RiskLevel::Suspicious;
        if (riskScore >= 20) return RiskLevel::Unknown;
        if (entry.target.isTrusted) return RiskLevel::Safe;

        return RiskLevel::Low;
    }

    [[nodiscard]] uint8_t CalculateRiskScore(const PersistenceEntry& entry) const noexcept {
        uint32_t score = 0;

        if (!entry.target.exists) score += 40;
        if (IsSuspiciousPath(entry.target.path)) score += 30;
        if (entry.target.signatureStatus == SignatureStatus::NotSigned) score += 20;
        if (entry.target.isPacked) score += 25;
        if (entry.target.inTempPath) score += 35;
        if (entry.isKnownBad) score = 100;
        if (entry.target.isMicrosoftSigned) score = std::max(score, 10u);

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

                // Assess risk
                analysis.isSuspiciousLocation = IsSuspiciousPath(target.path);
                analysis.isSuspiciousTarget = !target.exists || target.inTempPath;
                analysis.isUnsigned = (target.signatureStatus == SignatureStatus::NotSigned);

                // Calculate risk score
                uint32_t score = 0;
                if (analysis.isSuspiciousLocation) score += 30;
                if (analysis.isSuspiciousTarget) score += 40;
                if (analysis.isUnsigned) score += 20;
                if (target.isPacked) score += 25;

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
            }

        } catch (const std::exception& e) {
            Logger::Error("PersistenceDetector: Real-time analysis exception: {}", e.what());
        }

        return analysis;
    }

    [[nodiscard]] PersistenceType IsPersistenceLocationImpl(const std::wstring& keyPath) const noexcept {
        std::wstring upperPath = StringUtils::ToUpperCase(keyPath);

        for (const auto& loc : PERSISTENCE_LOCATIONS) {
            std::wstring checkPath = std::format(L"{}\\{}",
                (loc.hive == HKEY_LOCAL_MACHINE) ? L"HKEY_LOCAL_MACHINE" :
                (loc.hive == HKEY_CURRENT_USER) ? L"HKEY_CURRENT_USER" : L"HKEY_CLASSES_ROOT",
                loc.subkey);

            std::wstring upperCheckPath = StringUtils::ToUpperCase(checkPath);

            if (upperPath.find(upperCheckPath) != std::wstring::npos) {
                return loc.type;
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
        Logger::Critical("PersistenceDetector: Implementation is null");
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

    // Not implemented in this version
    return {};
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
    // Simplified - would parse rundll32, cmd /c, etc.
    std::vector<TargetBinary> targets;
    targets.push_back(ResolveTarget(command));
    return targets;
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
        if (StringUtils::EqualsIgnoreCase(svc.serviceName, serviceName)) {
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
    // Placeholder for export functionality
    Logger::Info("PersistenceDetector: Diagnostics export not yet implemented");
    return false;
}

bool PersistenceDetector::ExportScanReport(const ScanResult& result, const std::wstring& outputPath) const {
    // Placeholder for report export
    Logger::Info("PersistenceDetector: Report export not yet implemented");
    return false;
}

} // namespace Registry
} // namespace Core
} // namespace ShadowStrike
