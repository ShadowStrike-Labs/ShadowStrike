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
 * ShadowStrike NGAV - PRIVACY CLEANER IMPLEMENTATION
 * ============================================================================
 *
 * @file PrivacyCleaner.cpp
 * @brief Enterprise-grade privacy cleaner with secure erasure
 *
 * Implements comprehensive digital footprint removal including browser data,
 * system traces, application logs, and secure file deletion using DoD and
 * Gutmann standards for enterprise privacy compliance.
 *
 * ARCHITECTURE:
 * =============
 * - PIMPL pattern for ABI stability
 * - Meyers' Singleton for thread-safe instance management
 * - std::shared_mutex for concurrent read access
 * - RAII throughout for exception safety
 *
 * PERFORMANCE:
 * ============
 * - Lock-free statistics updates
 * - Efficient file scanning with filesystem iterators
 * - Parallel cleaning operations (where safe)
 * - Optimized secure erase algorithms
 *
 * BROWSER SUPPORT:
 * ================
 * - Chrome/Chromium (SQLite databases)
 * - Firefox (SQLite databases)
 * - Edge (Chromium-based)
 * - Opera/Opera GX
 * - Brave Browser
 * - Vivaldi
 * - Internet Explorer (legacy registry)
 *
 * SECURE ERASE METHODS:
 * =====================
 * - Single Pass: One zero pass (fast)
 * - Three Pass: Three random passes
 * - DoD 5220.22-M: 3-pass standard (0xFF, 0x00, random)
 * - Gutmann: 35-pass algorithm
 * - NIST 800-88: Clear method
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
#include "PrivacyCleaner.hpp"

#include <algorithm>
#include <sstream>
#include <iomanip>
#include <fstream>
#include <random>
#include <thread>
#include <condition_variable>
#include <array>
#include <deque>

// Third-party libraries
#include <nlohmann/json.hpp>

// ShadowStrike infrastructure
#include "../Utils/Logger.hpp"
#include "../Utils/FileUtils.hpp"
#include "../Utils/StringUtils.hpp"
#include "../Utils/SystemUtils.hpp"
#include "../Utils/ProcessUtils.hpp"

// Windows-specific headers
#ifdef _WIN32
#include <shlobj.h>
#include <comdef.h>
#include <wbemidl.h>
#include <iphlpapi.h>
#include <tlhelp32.h>
#include <windns.h>
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "dnsapi.lib")
#endif

namespace ShadowStrike {
namespace Privacy {

// ============================================================================
// INTERNAL STRUCTURES
// ============================================================================

namespace {

/// @brief ASCII-only lowercase for domain names (avoids wide-string round-trip)
[[nodiscard]] std::string ToLowerAscii(std::string_view src) {
    std::string result(src);
    for (auto& ch : result) {
        if (ch >= 'A' && ch <= 'Z') ch += ('a' - 'A');
    }
    return result;
}

/// @brief Shared directory iterator options: skip inaccessible directories
constexpr auto kDirIterOpts = fs::directory_options::skip_permission_denied;

/**
 * @brief Browser profile locations
 */
struct BrowserPaths {
    std::vector<fs::path> profilePaths;
    fs::path executablePath;
    std::string processName;
};

/**
 * @brief Gutmann pass patterns for passes 5-31 (27 deterministic passes).
 *        Passes 1-4 and 32-35 are random.
 *        Single-byte approximation of original multi-byte Gutmann sequences.
 */
constexpr std::array<uint8_t, 27> GUTMANN_DETERMINISTIC_PATTERNS = {
    0x55, 0xAA, 0x92, 0x49, 0x24, 0x00, 0x11, 0x22,
    0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA,
    0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x92, 0x49, 0x24,
    0x6D, 0xB6, 0xDB
};

/**
 * @brief Get browser profile paths helper
 */
BrowserPaths GetBrowserPathsInternal(BrowserType browser) {
    BrowserPaths paths;

#ifdef _WIN32
    wchar_t appDataPath[MAX_PATH] = {};
    wchar_t localAppDataPath[MAX_PATH] = {};

    SHGetFolderPathW(nullptr, CSIDL_APPDATA, nullptr, SHGFP_TYPE_CURRENT, appDataPath);
    SHGetFolderPathW(nullptr, CSIDL_LOCAL_APPDATA, nullptr, SHGFP_TYPE_CURRENT, localAppDataPath);

    fs::path appData = appDataPath;
    fs::path localAppData = localAppDataPath;

    switch (browser) {
        case BrowserType::Chrome:
            paths.profilePaths.push_back(localAppData / "Google" / "Chrome" / "User Data");
            paths.executablePath = fs::path("C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe");
            paths.processName = "chrome.exe";
            break;

        case BrowserType::Firefox:
            paths.profilePaths.push_back(appData / "Mozilla" / "Firefox" / "Profiles");
            paths.executablePath = fs::path("C:\\Program Files\\Mozilla Firefox\\firefox.exe");
            paths.processName = "firefox.exe";
            break;

        case BrowserType::Edge:
            paths.profilePaths.push_back(localAppData / "Microsoft" / "Edge" / "User Data");
            paths.executablePath = fs::path("C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe");
            paths.processName = "msedge.exe";
            break;

        case BrowserType::Opera:
            paths.profilePaths.push_back(appData / "Opera Software" / "Opera Stable");
            paths.executablePath = fs::path("C:\\Program Files\\Opera\\launcher.exe");
            paths.processName = "opera.exe";
            break;

        case BrowserType::Brave:
            paths.profilePaths.push_back(localAppData / "BraveSoftware" / "Brave-Browser" / "User Data");
            paths.executablePath = fs::path("C:\\Program Files\\BraveSoftware\\Brave-Browser\\Application\\brave.exe");
            paths.processName = "brave.exe";
            break;

        case BrowserType::Vivaldi:
            paths.profilePaths.push_back(localAppData / "Vivaldi" / "User Data");
            paths.executablePath = fs::path("C:\\Program Files\\Vivaldi\\Application\\vivaldi.exe");
            paths.processName = "vivaldi.exe";
            break;

        case BrowserType::Chromium:
            paths.profilePaths.push_back(localAppData / "Chromium" / "User Data");
            paths.processName = "chromium.exe";
            break;

        default:
            break;
    }
#endif

    return paths;
}

} // anonymous namespace

// ============================================================================
// PRIVACY CLEANER IMPLEMENTATION (PIMPL)
// ============================================================================

class PrivacyCleanerImpl {
public:
    PrivacyCleanerImpl();
    ~PrivacyCleanerImpl();

    // Lifecycle
    bool Initialize(const CleanerConfiguration& config);
    void Shutdown();
    bool IsInitialized() const noexcept { return m_initialized.load(std::memory_order_acquire); }
    ModuleStatus GetStatus() const noexcept { return m_status.load(std::memory_order_acquire); }

    bool UpdateConfiguration(const CleanerConfiguration& config);
    CleanerConfiguration GetConfiguration() const;

    // Scanning
    CleanScanResult ScanForCleanableItems();
    std::vector<CleanTarget> ScanBrowserData(BrowserType browser, BrowserDataType dataTypes);
    std::vector<CleanTarget> ScanSystemData(SystemDataType dataTypes);
    std::vector<BrowserProfile> GetBrowserProfiles(BrowserType browser);

    // Cleaning
    CleanResultDetails CleanAll();
    CleanResultDetails CleanBrowser(const std::wstring& browserName);
    CleanResultDetails CleanBrowser(BrowserType browser, BrowserDataType dataTypes);
    CleanResultDetails CleanSystem(SystemDataType dataTypes);
    CleanResultDetails CleanTargets(const std::vector<CleanTarget>& targets);
    CleanResultDetails CleanTempFiles(std::chrono::hours olderThan);
    CleanResultDetails EmptyRecycleBin();
    bool ClearDNSCache();
    bool ClearClipboard();

    // Secure erasure
    bool SecureEraseFile(const fs::path& filePath, SecureEraseMethod method);
    CleanResultDetails SecureEraseDirectory(const fs::path& dirPath, SecureEraseMethod method);
    bool SecureEraseFreeSpace(const std::wstring& driveLetter, SecureEraseMethod method);

    // Scheduling
    bool AddSchedule(const CleanSchedule& schedule);
    bool RemoveSchedule(const std::string& scheduleId);
    bool SetScheduleEnabled(const std::string& scheduleId, bool enabled);
    std::vector<CleanSchedule> GetSchedules() const;
    CleanResultDetails RunScheduledClean(const std::string& scheduleId);

    // Cookie management
    bool AddPreservedDomain(const std::string& domain);
    bool RemovePreservedDomain(const std::string& domain);
    std::vector<std::string> GetPreservedDomains() const;

    // Callbacks
    void RegisterProgressCallback(ProgressCallback callback);
    void RegisterCompletionCallback(CompletionCallback callback);
    void RegisterScanCallback(ScanCallback callback);
    void RegisterConfirmCallback(ConfirmCallback callback);
    void RegisterErrorCallback(ErrorCallback callback);
    void UnregisterCallbacks();

    // Statistics
    CleanerStatistics GetStatistics() const;
    void ResetStatistics();

    bool SelfTest();

private:
    // Helper functions
    CleanTarget CreateCleanTarget(const fs::path& path, const std::string& description, const std::string& category);
    bool DeleteFileSecurely(const fs::path& filePath, SecureEraseMethod method);
    bool OverwriteFile(const fs::path& filePath, uint8_t pattern);
    bool OverwriteFileRandom(const fs::path& filePath);
    void DoD_5220_22_M_Erase(const fs::path& filePath);
    void GutmannErase(const fs::path& filePath);
    void NIST_800_88_Erase(const fs::path& filePath);

    std::vector<CleanTarget> ScanChromiumBrowser(BrowserType browser, BrowserDataType dataTypes);
    std::vector<CleanTarget> ScanFirefox(BrowserDataType dataTypes);
    bool CleanChromiumCache(const fs::path& profilePath);
    bool CleanChromiumCookies(const fs::path& profilePath);
    bool CleanChromiumHistory(const fs::path& profilePath);

    std::vector<CleanTarget> ScanRecentDocuments();
    std::vector<CleanTarget> ScanJumpLists();
    std::vector<CleanTarget> ScanThumbnailCache();
    std::vector<CleanTarget> ScanTempFiles();
    std::vector<CleanTarget> ScanPrefetch();

    bool DeleteTarget(const CleanTarget& target, SecureEraseMethod method);
    uint64_t CalculateDirectorySize(const fs::path& dirPath);
    uint32_t CountFilesInDirectory(const fs::path& dirPath);
    bool IsFileInUse(const fs::path& filePath);
    bool IsPathExcluded(const fs::path& path);
    bool IsDomainPreserved(const std::string& domain);

    void NotifyProgress(const std::string& item, int percent);
    void NotifyCompletion(const CleanResultDetails& result);
    void NotifyScan(const CleanScanResult& result);
    bool NotifyConfirm(const std::string& message);
    void NotifyError(const std::string& message, int code);

    // Member variables
    mutable std::shared_mutex m_mutex;
    std::atomic<bool> m_initialized{false};
    std::atomic<ModuleStatus> m_status{ModuleStatus::Uninitialized};
    CleanerConfiguration m_config;

    // Schedules
    std::vector<CleanSchedule> m_schedules;

    // Preserved domains
    std::unordered_set<std::string> m_preservedDomains;

    // Callbacks
    mutable std::mutex m_callbackMutex;
    ProgressCallback m_progressCallback;
    CompletionCallback m_completionCallback;
    ScanCallback m_scanCallback;
    ConfirmCallback m_confirmCallback;
    ErrorCallback m_errorCallback;

    // Statistics
    mutable CleanerStatistics m_stats;

    // Random generator for secure erase
    mutable std::mutex m_rngMutex;
    std::mt19937_64 m_rng{std::random_device{}()};
};

// ============================================================================
// IMPLEMENTATION
// ============================================================================

PrivacyCleanerImpl::PrivacyCleanerImpl() {
    SS_LOG_INFO(L"PrivacyCleaner", L"Instance created");
}

PrivacyCleanerImpl::~PrivacyCleanerImpl() {
    Shutdown();
    SS_LOG_INFO(L"PrivacyCleaner", L"Instance destroyed");
}

bool PrivacyCleanerImpl::Initialize(const CleanerConfiguration& config) {
    std::unique_lock lock(m_mutex);

    if (m_initialized.load(std::memory_order_acquire)) {
        SS_LOG_WARN(L"PrivacyCleaner", L"Already initialized");
        return true;
    }

    try {
        m_status.store(ModuleStatus::Initializing, std::memory_order_release);

        // Validate configuration
        if (!config.IsValid()) {
            SS_LOG_ERROR(L"PrivacyCleaner", L"Invalid configuration");
            m_status.store(ModuleStatus::Error, std::memory_order_release);
            return false;
        }

        m_config = config;

        // Initialize preserved domains (case-insensitive via ASCII lowercase)
        m_preservedDomains.clear();
        for (const auto& domain : m_config.preservedCookieDomains) {
            m_preservedDomains.insert(ToLowerAscii(domain));
        }

        // Load schedules
        m_schedules = m_config.schedules;

        // Reset statistics
        m_stats.Reset();
        m_stats.startTime = Clock::now();

        m_initialized.store(true, std::memory_order_release);
        m_status.store(ModuleStatus::Ready, std::memory_order_release);

        SS_LOG_INFO(L"PrivacyCleaner", L"Initialized successfully (Version %hs)",
            PrivacyCleaner::GetVersionString().c_str());

        return true;

    } catch (const std::exception& e) {
        SS_LOG_FATAL(L"PrivacyCleaner", L"Initialization failed: %hs", e.what());
        m_status.store(ModuleStatus::Error, std::memory_order_release);
        return false;
    } catch (...) {
        SS_LOG_FATAL(L"PrivacyCleaner", L"Initialization failed: Unknown error");
        m_status.store(ModuleStatus::Error, std::memory_order_release);
        return false;
    }
}

void PrivacyCleanerImpl::Shutdown() {
    std::unique_lock lock(m_mutex);

    if (!m_initialized.load(std::memory_order_acquire)) {
        return;
    }

    try {
        m_status.store(ModuleStatus::Stopping, std::memory_order_release);

        // Clear state
        m_schedules.clear();
        m_preservedDomains.clear();

        m_initialized.store(false, std::memory_order_release);
        m_status.store(ModuleStatus::Stopped, std::memory_order_release);

        // Clear callbacks AFTER releasing m_initialized to prevent
        // new operations from starting. Use separate lock scope.
        {
            std::lock_guard cbLock(m_callbackMutex);
            m_progressCallback = nullptr;
            m_completionCallback = nullptr;
            m_scanCallback = nullptr;
            m_confirmCallback = nullptr;
            m_errorCallback = nullptr;
        }

        SS_LOG_INFO(L"PrivacyCleaner", L"Shutdown complete");

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"PrivacyCleaner", L"Shutdown error: %hs", e.what());
    } catch (...) {
        SS_LOG_ERROR(L"PrivacyCleaner", L"Shutdown error: Unknown exception");
    }
}

bool PrivacyCleanerImpl::UpdateConfiguration(const CleanerConfiguration& config) {
    std::unique_lock lock(m_mutex);

    if (!config.IsValid()) {
        SS_LOG_ERROR(L"PrivacyCleaner", L"Invalid configuration");
        return false;
    }

    m_config = config;

    // Synchronize derived state from new configuration
    m_preservedDomains.clear();
    for (const auto& domain : m_config.preservedCookieDomains) {
        m_preservedDomains.insert(ToLowerAscii(domain));
    }
    m_schedules = m_config.schedules;

    SS_LOG_INFO(L"PrivacyCleaner", L"Configuration updated");
    return true;
}

CleanerConfiguration PrivacyCleanerImpl::GetConfiguration() const {
    std::shared_lock lock(m_mutex);
    return m_config;
}

// ============================================================================
// SCANNING
// ============================================================================

CleanScanResult PrivacyCleanerImpl::ScanForCleanableItems() {
    if (!m_initialized.load(std::memory_order_acquire)) {
        SS_LOG_ERROR(L"PrivacyCleaner", L"ScanForCleanableItems: not initialized");
        return {};
    }

    auto startTime = Clock::now();
    CleanScanResult result;

    try {
        m_status.store(ModuleStatus::Cleaning, std::memory_order_release);

        // Scan browsers
        result.browserTargets = ScanBrowserData(BrowserType::All, BrowserDataType::All);

        // Scan system
        result.systemTargets = ScanSystemData(SystemDataType::All);

        // Get browser profiles
        result.browserProfiles = GetBrowserProfiles(BrowserType::All);

        // Calculate totals
        for (const auto& target : result.browserTargets) {
            result.totalSizeBytes += target.sizeBytes;
            result.totalFileCount += target.isDirectory ? target.fileCount : 1;
        }
        for (const auto& target : result.systemTargets) {
            result.totalSizeBytes += target.sizeBytes;
            result.totalFileCount += target.isDirectory ? target.fileCount : 1;
        }

        auto endTime = Clock::now();
        result.scanDuration = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime);

        m_status.store(ModuleStatus::Ready, std::memory_order_release);

        SS_LOG_INFO(L"PrivacyCleaner", L"Scan complete: %u items (%llu bytes)",
            result.totalFileCount, static_cast<unsigned long long>(result.totalSizeBytes));

        NotifyScan(result);
        return result;

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"PrivacyCleaner", L"Scan failed: %hs", e.what());
        m_status.store(ModuleStatus::Ready, std::memory_order_release);
        NotifyError(e.what(), -1);
        return result;
    }
}

std::vector<CleanTarget> PrivacyCleanerImpl::ScanBrowserData(BrowserType browser, BrowserDataType dataTypes) {
    std::vector<CleanTarget> targets;

    if (browser == BrowserType::All) {
        // Scan all browsers
        for (int i = 1; i <= 8; ++i) {
            auto browserType = static_cast<BrowserType>(i);
            auto browserTargets = ScanBrowserData(browserType, dataTypes);
            targets.insert(targets.end(), browserTargets.begin(), browserTargets.end());
        }
        return targets;
    }

    // Scan specific browser
    if (browser == BrowserType::Firefox) {
        return ScanFirefox(dataTypes);
    } else {
        // Chromium-based browsers
        return ScanChromiumBrowser(browser, dataTypes);
    }
}

std::vector<CleanTarget> PrivacyCleanerImpl::ScanSystemData(SystemDataType dataTypes) {
    std::vector<CleanTarget> targets;

    uint32_t types = static_cast<uint32_t>(dataTypes);

    if (types & static_cast<uint32_t>(SystemDataType::RecentDocuments)) {
        auto recent = ScanRecentDocuments();
        targets.insert(targets.end(), recent.begin(), recent.end());
    }

    if (types & static_cast<uint32_t>(SystemDataType::JumpLists)) {
        auto jumplists = ScanJumpLists();
        targets.insert(targets.end(), jumplists.begin(), jumplists.end());
    }

    if (types & static_cast<uint32_t>(SystemDataType::ThumbnailCache)) {
        auto thumbs = ScanThumbnailCache();
        targets.insert(targets.end(), thumbs.begin(), thumbs.end());
    }

    if (types & static_cast<uint32_t>(SystemDataType::TempFiles)) {
        auto temp = ScanTempFiles();
        targets.insert(targets.end(), temp.begin(), temp.end());
    }

    if (types & static_cast<uint32_t>(SystemDataType::Prefetch)) {
        auto prefetch = ScanPrefetch();
        targets.insert(targets.end(), prefetch.begin(), prefetch.end());
    }

    if (types & static_cast<uint32_t>(SystemDataType::RecycleBin)) {
        // Recycle bin handled separately
    }

    return targets;
}

std::vector<BrowserProfile> PrivacyCleanerImpl::GetBrowserProfiles(BrowserType browser) {
    std::vector<BrowserProfile> profiles;

    try {
        if (browser == BrowserType::All) {
            for (int i = 1; i <= 8; ++i) {
                auto browserType = static_cast<BrowserType>(i);
                auto browserProfiles = GetBrowserProfiles(browserType);
                profiles.insert(profiles.end(), browserProfiles.begin(), browserProfiles.end());
            }
            return profiles;
        }

        auto browserPaths = GetBrowserPathsInternal(browser);

        for (const auto& basePath : browserPaths.profilePaths) {
            std::error_code ec;
            if (!fs::exists(basePath, ec) || ec) continue;

            // Chromium-based: multiple profiles (Default, Profile 1, etc.)
            if (browser != BrowserType::Firefox) {
                for (const auto& entry : fs::directory_iterator(basePath, kDirIterOpts, ec)) {
                    if (ec) break;
                    if (!entry.is_directory(ec) || ec) continue;

                    auto dirName = entry.path().filename().string();
                    if (dirName.find("Profile") != 0 && dirName != "Default") continue;

                    BrowserProfile profile;
                    profile.browser = browser;
                    profile.name = dirName;
                    profile.path = entry.path();
                    profile.sizeBytes = CalculateDirectorySize(entry.path());
                    profile.isDefault = (dirName == "Default");
                    profiles.push_back(std::move(profile));
                }
            } else {
                // Firefox: iterate profile directories (named <random>.profilename)
                for (const auto& entry : fs::directory_iterator(basePath, kDirIterOpts, ec)) {
                    if (ec) break;
                    if (!entry.is_directory(ec) || ec) continue;

                    BrowserProfile profile;
                    profile.browser = browser;
                    profile.name = entry.path().filename().string();
                    profile.path = entry.path();
                    profile.sizeBytes = CalculateDirectorySize(entry.path());
                    profiles.push_back(std::move(profile));
                }
            }
        }

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"PrivacyCleaner", L"GetBrowserProfiles error: %hs", e.what());
    }

    return profiles;
}

// ============================================================================
// CLEANING
// ============================================================================

CleanResultDetails PrivacyCleanerImpl::CleanAll() {
    if (!m_initialized.load(std::memory_order_acquire)) {
        SS_LOG_ERROR(L"PrivacyCleaner", L"CleanAll: not initialized");
        return {};
    }

    auto startTime = Clock::now();
    CleanResultDetails result;

    try {
        m_status.store(ModuleStatus::Cleaning, std::memory_order_release);

        // Clean all browsers
        auto browserResult = CleanBrowser(BrowserType::All, BrowserDataType::All);
        result.itemsCleaned += browserResult.itemsCleaned;
        result.itemsFailed += browserResult.itemsFailed;
        result.bytesCleaned += browserResult.bytesCleaned;
        result.errors.insert(result.errors.end(), browserResult.errors.begin(), browserResult.errors.end());

        // Clean system
        auto systemResult = CleanSystem(SystemDataType::All);
        result.itemsCleaned += systemResult.itemsCleaned;
        result.itemsFailed += systemResult.itemsFailed;
        result.bytesCleaned += systemResult.bytesCleaned;
        result.errors.insert(result.errors.end(), systemResult.errors.begin(), systemResult.errors.end());

        // Empty recycle bin
        auto recycleBinResult = EmptyRecycleBin();
        result.itemsCleaned += recycleBinResult.itemsCleaned;
        result.bytesCleaned += recycleBinResult.bytesCleaned;

        auto endTime = Clock::now();
        result.duration = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime);

        result.result = (result.itemsFailed == 0) ? CleanResult::Success : CleanResult::PartialSuccess;

        m_status.store(ModuleStatus::Ready, std::memory_order_release);
        m_stats.totalCleanOperations.fetch_add(1, std::memory_order_relaxed);

        SS_LOG_INFO(L"PrivacyCleaner", L"CleanAll complete: %u items (%llu bytes)",
            result.itemsCleaned, static_cast<unsigned long long>(result.bytesCleaned));

        NotifyCompletion(result);
        return result;

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"PrivacyCleaner", L"CleanAll failed: %hs", e.what());
        m_status.store(ModuleStatus::Ready, std::memory_order_release);
        result.result = CleanResult::Error;
        NotifyError(e.what(), -1);
        return result;
    }
}

CleanResultDetails PrivacyCleanerImpl::CleanBrowser(const std::wstring& browserName) {
    std::wstring lowerName = Utils::StringUtils::ToLowerCopy(browserName);

    BrowserType browser = BrowserType::Unknown;
    if (Utils::StringUtils::IContains(lowerName, L"chrome"))       browser = BrowserType::Chrome;
    else if (Utils::StringUtils::IContains(lowerName, L"firefox")) browser = BrowserType::Firefox;
    else if (Utils::StringUtils::IContains(lowerName, L"edge"))    browser = BrowserType::Edge;
    else if (Utils::StringUtils::IContains(lowerName, L"opera"))   browser = BrowserType::Opera;
    else if (Utils::StringUtils::IContains(lowerName, L"brave"))   browser = BrowserType::Brave;
    else if (Utils::StringUtils::IContains(lowerName, L"vivaldi")) browser = BrowserType::Vivaldi;

    if (browser == BrowserType::Unknown) {
        SS_LOG_WARN(L"PrivacyCleaner", L"CleanBrowser: unrecognized browser name '%ls'", browserName.c_str());
    }

    return CleanBrowser(browser, BrowserDataType::All);
}

CleanResultDetails PrivacyCleanerImpl::CleanBrowser(BrowserType browser, BrowserDataType dataTypes) {
    auto startTime = Clock::now();
    CleanResultDetails result;

    try {
        // Scan targets
        auto targets = ScanBrowserData(browser, dataTypes);

        // Clean targets
        result = CleanTargets(targets);

        auto endTime = Clock::now();
        result.duration = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime);

        m_stats.browserCleans.fetch_add(1, std::memory_order_relaxed);
        if (static_cast<size_t>(browser) < m_stats.byBrowser.size()) {
            m_stats.byBrowser[static_cast<size_t>(browser)].fetch_add(1, std::memory_order_relaxed);
        }

        SS_LOG_INFO(L"PrivacyCleaner", L"Browser clean complete: %hs (%u items, %llu bytes)",
            GetBrowserTypeName(browser).data(), result.itemsCleaned,
            static_cast<unsigned long long>(result.bytesCleaned));

        return result;

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"PrivacyCleaner", L"CleanBrowser failed: %hs", e.what());
        result.result = CleanResult::Error;
        result.errors.push_back(e.what());
        return result;
    }
}

CleanResultDetails PrivacyCleanerImpl::CleanSystem(SystemDataType dataTypes) {
    auto startTime = Clock::now();
    CleanResultDetails result;

    try {
        // Scan targets
        auto targets = ScanSystemData(dataTypes);

        // Clean targets
        result = CleanTargets(targets);

        // DNS cache
        if (static_cast<uint32_t>(dataTypes) & static_cast<uint32_t>(SystemDataType::DNSCache)) {
            if (ClearDNSCache()) {
                result.itemsCleaned++;
            }
        }

        auto endTime = Clock::now();
        result.duration = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime);

        m_stats.systemCleans.fetch_add(1, std::memory_order_relaxed);

        SS_LOG_INFO(L"PrivacyCleaner", L"System clean complete: %u items (%llu bytes)",
            result.itemsCleaned, static_cast<unsigned long long>(result.bytesCleaned));

        return result;

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"PrivacyCleaner", L"CleanSystem failed: %hs", e.what());
        result.result = CleanResult::Error;
        result.errors.push_back(e.what());
        return result;
    }
}

CleanResultDetails PrivacyCleanerImpl::CleanTargets(const std::vector<CleanTarget>& targets) {
    CleanResultDetails result;

    if (targets.empty()) {
        result.result = CleanResult::Success;
        return result;
    }

    for (size_t i = 0; i < targets.size(); ++i) {
        const auto& target = targets[i];

        try {
            NotifyProgress(target.path.string(), static_cast<int>((i * 100) / targets.size()));

            if (DeleteTarget(target, m_config.defaultEraseMethod)) {
                result.itemsCleaned++;
                result.bytesCleaned += target.sizeBytes;
                result.cleanedFiles.push_back(target.path);
                m_stats.totalFilesDeleted.fetch_add(1, std::memory_order_relaxed);
            } else {
                result.itemsFailed++;
                result.bytesFailed += target.sizeBytes;
                result.failedFiles.push_back(target.path);
            }

        } catch (const std::exception& e) {
            result.itemsFailed++;
            result.errors.push_back(target.path.string() + ": " + e.what());
            SS_LOG_ERROR(L"PrivacyCleaner", L"Failed to clean target %hs: %hs",
                target.path.string().c_str(), e.what());
        }
    }

    result.result = (result.itemsFailed == 0) ? CleanResult::Success : CleanResult::PartialSuccess;
    m_stats.totalBytesReclaimed.fetch_add(result.bytesCleaned, std::memory_order_relaxed);

    return result;
}

CleanResultDetails PrivacyCleanerImpl::CleanTempFiles(std::chrono::hours olderThan) {
    CleanResultDetails result;
    auto cutoffTime = std::chrono::system_clock::now() - olderThan;

    try {
#ifdef _WIN32
        wchar_t tempPath[MAX_PATH] = {};
        GetTempPathW(MAX_PATH, tempPath);

        fs::path tempDir = tempPath;
        std::error_code ec;

        for (const auto& entry : fs::recursive_directory_iterator(tempDir, kDirIterOpts, ec)) {
            if (ec) { ec.clear(); continue; }

            try {
                if (entry.is_regular_file(ec) && !ec) {
                    auto lastWrite = fs::last_write_time(entry.path(), ec);
                    if (ec) { ec.clear(); continue; }

                    auto sctp = std::chrono::time_point_cast<std::chrono::system_clock::duration>(
                        lastWrite - fs::file_time_type::clock::now() + std::chrono::system_clock::now()
                    );

                    if (sctp < cutoffTime) {
                        auto size = entry.file_size(ec);
                        if (ec) { ec.clear(); size = 0; }

                        if (DeleteFileSecurely(entry.path(), m_config.defaultEraseMethod)) {
                            result.itemsCleaned++;
                            result.bytesCleaned += size;
                        } else {
                            result.itemsFailed++;
                        }
                    }
                }
            } catch (...) {
                result.itemsFailed++;
            }
        }
#endif

        result.result = (result.itemsFailed == 0) ? CleanResult::Success : CleanResult::PartialSuccess;
        m_stats.totalBytesReclaimed.fetch_add(result.bytesCleaned, std::memory_order_relaxed);

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"PrivacyCleaner", L"CleanTempFiles failed: %hs", e.what());
        result.result = CleanResult::Error;
    }

    return result;
}

CleanResultDetails PrivacyCleanerImpl::EmptyRecycleBin() {
    CleanResultDetails result;

    try {
#ifdef _WIN32
        HRESULT hr = SHEmptyRecycleBinW(nullptr, nullptr,
            SHERB_NOCONFIRMATION | SHERB_NOPROGRESSUI | SHERB_NOSOUND);

        if (SUCCEEDED(hr)) {
            result.result = CleanResult::Success;
            result.itemsCleaned = 1;
            SS_LOG_INFO(L"PrivacyCleaner", L"Recycle bin emptied");
        } else if (hr == S_FALSE || hr == E_UNEXPECTED) {
            // S_FALSE or E_UNEXPECTED: bin was already empty
            result.result = CleanResult::Success;
            SS_LOG_DEBUG(L"PrivacyCleaner", L"Recycle bin was already empty");
        } else {
            result.result = CleanResult::Error;
            SS_LOG_ERROR(L"PrivacyCleaner", L"Failed to empty recycle bin: HRESULT 0x%08lX",
                static_cast<unsigned long>(hr));
        }
#endif

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"PrivacyCleaner", L"EmptyRecycleBin failed: %hs", e.what());
        result.result = CleanResult::Error;
    }

    return result;
}

bool PrivacyCleanerImpl::ClearDNSCache() {
    try {
#ifdef _WIN32
        // DnsFlushResolverCache returns BOOL: nonzero on success, zero on failure
        BOOL flushed = DnsFlushResolverCache();
        if (flushed) {
            SS_LOG_INFO(L"PrivacyCleaner", L"DNS cache cleared");
            return true;
        } else {
            SS_LOG_WARN(L"PrivacyCleaner", L"DNS cache flush returned failure");
        }
#endif
    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"PrivacyCleaner", L"ClearDNSCache failed: %hs", e.what());
    }

    return false;
}

bool PrivacyCleanerImpl::ClearClipboard() {
    try {
#ifdef _WIN32
        if (OpenClipboard(nullptr)) {
            BOOL emptied = EmptyClipboard();
            CloseClipboard();
            if (emptied) {
                SS_LOG_INFO(L"PrivacyCleaner", L"Clipboard cleared");
                return true;
            }
            SS_LOG_WARN(L"PrivacyCleaner", L"EmptyClipboard returned failure");
            return false;
        }
        SS_LOG_LAST_ERROR(L"PrivacyCleaner", L"OpenClipboard failed");
#endif
    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"PrivacyCleaner", L"ClearClipboard failed: %hs", e.what());
    }

    return false;
}

// ============================================================================
// SECURE ERASURE
// ============================================================================

bool PrivacyCleanerImpl::SecureEraseFile(const fs::path& filePath, SecureEraseMethod method) {
    if (!m_initialized.load(std::memory_order_acquire)) {
        return false;
    }

    try {
        std::error_code ec;
        if (!fs::exists(filePath, ec) || ec) {
            SS_LOG_WARN(L"PrivacyCleaner", L"SecureEraseFile: file not found or inaccessible: %hs",
                filePath.string().c_str());
            return false;
        }

        if (!fs::is_regular_file(filePath, ec) || ec) {
            SS_LOG_ERROR(L"PrivacyCleaner", L"SecureEraseFile: not a regular file: %hs",
                filePath.string().c_str());
            return false;
        }

        auto size = fs::file_size(filePath, ec);
        if (ec) {
            SS_LOG_ERROR(L"PrivacyCleaner", L"SecureEraseFile: cannot get file size: %hs",
                filePath.string().c_str());
            return false;
        }

        if (size > CleanerConstants::MAX_SECURE_ERASE_SIZE) {
            SS_LOG_ERROR(L"PrivacyCleaner", L"SecureEraseFile: file too large (%llu bytes) for secure erase",
                static_cast<unsigned long long>(size));
            return false;
        }

        bool success = DeleteFileSecurely(filePath, method);

        if (success) {
            m_stats.totalSecureErases.fetch_add(1, std::memory_order_relaxed);
            m_stats.totalBytesReclaimed.fetch_add(size, std::memory_order_relaxed);
            SS_LOG_DEBUG(L"PrivacyCleaner", L"Securely erased: %hs (%llu bytes)",
                filePath.string().c_str(), static_cast<unsigned long long>(size));
        }

        return success;

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"PrivacyCleaner", L"SecureEraseFile failed: %hs", e.what());
        return false;
    }
}

CleanResultDetails PrivacyCleanerImpl::SecureEraseDirectory(const fs::path& dirPath, SecureEraseMethod method) {
    CleanResultDetails result;

    try {
        std::error_code ec;
        if (!fs::exists(dirPath, ec) || ec || !fs::is_directory(dirPath, ec) || ec) {
            result.result = CleanResult::NotFound;
            return result;
        }

        for (const auto& entry : fs::recursive_directory_iterator(dirPath, kDirIterOpts, ec)) {
            if (ec) { ec.clear(); continue; }
            if (entry.is_regular_file(ec) && !ec) {
                auto size = entry.file_size(ec);
                if (ec) { ec.clear(); size = 0; }

                if (SecureEraseFile(entry.path(), method)) {
                    result.itemsCleaned++;
                    result.bytesCleaned += size;
                } else {
                    result.itemsFailed++;
                }
            }
        }

        // Remove empty directory tree after erasing contents
        fs::remove_all(dirPath, ec);
        if (ec) {
            SS_LOG_WARN(L"PrivacyCleaner", L"SecureEraseDirectory: could not remove directory tree: %hs",
                dirPath.string().c_str());
        }

        result.result = (result.itemsFailed == 0) ? CleanResult::Success : CleanResult::PartialSuccess;

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"PrivacyCleaner", L"SecureEraseDirectory failed: %hs", e.what());
        result.result = CleanResult::Error;
        result.errors.push_back(e.what());
    }

    return result;
}

bool PrivacyCleanerImpl::SecureEraseFreeSpace(const std::wstring& driveLetter, SecureEraseMethod method) {
    if (!m_initialized.load(std::memory_order_acquire)) {
        SS_LOG_ERROR(L"PrivacyCleaner", L"SecureEraseFreeSpace: not initialized");
        return false;
    }

#ifdef _WIN32
    // Validate drive letter
    if (driveLetter.empty()) {
        SS_LOG_ERROR(L"PrivacyCleaner", L"SecureEraseFreeSpace: empty drive letter");
        return false;
    }

    wchar_t driveChar = std::towupper(driveLetter[0]);
    if (driveChar < L'A' || driveChar > L'Z') {
        SS_LOG_ERROR(L"PrivacyCleaner", L"SecureEraseFreeSpace: invalid drive letter '%lc'", driveChar);
        return false;
    }

    std::wstring driveRoot = { driveChar, L':', L'\\' };

    DWORD driveType = GetDriveTypeW(driveRoot.c_str());
    if (driveType == DRIVE_UNKNOWN || driveType == DRIVE_NO_ROOT_DIR) {
        SS_LOG_ERROR(L"PrivacyCleaner", L"SecureEraseFreeSpace: drive %ls not found", driveRoot.c_str());
        return false;
    }

    // Determine pass count based on erase method (cap for free-space wipe to stay practical)
    int passCount = 1;
    switch (method) {
        case SecureEraseMethod::SinglePass:
        case SecureEraseMethod::NIST_800_88:
        case SecureEraseMethod::Random:
            passCount = 1;
            break;
        case SecureEraseMethod::ThreePass:
        case SecureEraseMethod::DoD_5220_22_M:
            passCount = 3;
            break;
        case SecureEraseMethod::Gutmann:
            // 35-pass on free space is impractical; cap at 3 passes for sanity
            passCount = 3;
            SS_LOG_WARN(L"PrivacyCleaner", L"Gutmann 35-pass capped to 3 for free-space wipe");
            break;
    }

    // Create wipe file — attempt drive root, fall back to user temp on same drive
    wchar_t tempFileName[MAX_PATH]{};
    bool gotTempFile = (GetTempFileNameW(driveRoot.c_str(), L"SSW", 0, tempFileName) != 0);
    if (!gotTempFile) {
        wchar_t userTemp[MAX_PATH]{};
        GetTempPathW(MAX_PATH, userTemp);
        if (userTemp[0] != L'\0' && std::towupper(userTemp[0]) == driveChar) {
            gotTempFile = (GetTempFileNameW(userTemp, L"SSW", 0, tempFileName) != 0);
        }
    }
    if (!gotTempFile) {
        SS_LOG_ERROR(L"PrivacyCleaner", L"SecureEraseFreeSpace: cannot create wipe file on %ls", driveRoot.c_str());
        return false;
    }

    // RAII guard to ensure wipe file is always deleted
    struct WipeFileGuard {
        const wchar_t* path;
        ~WipeFileGuard() { if (path) DeleteFileW(path); }
    } wipeGuard{ tempFileName };

    try {
        constexpr DWORD CHUNK_SIZE = 1024 * 1024; // 1 MB
        std::vector<uint8_t> buffer(CHUNK_SIZE);

        for (int pass = 0; pass < passCount; ++pass) {
            // Determine fill pattern for this pass
            bool useRandom = false;
            uint8_t fillByte = 0x00;

            switch (method) {
                case SecureEraseMethod::SinglePass:
                case SecureEraseMethod::NIST_800_88:
                    fillByte = 0x00;
                    break;
                case SecureEraseMethod::Random:
                case SecureEraseMethod::ThreePass:
                    useRandom = true;
                    break;
                case SecureEraseMethod::DoD_5220_22_M:
                    if (pass == 0) fillByte = 0xFF;
                    else if (pass == 1) fillByte = 0x00;
                    else useRandom = true;
                    break;
                case SecureEraseMethod::Gutmann:
                    useRandom = true; // Simplified for free-space
                    break;
            }

            if (!useRandom) {
                std::memset(buffer.data(), fillByte, CHUNK_SIZE);
            }

            // Open wipe file for this pass
            HANDLE hFile = CreateFileW(tempFileName, GENERIC_WRITE, 0, nullptr,
                CREATE_ALWAYS, FILE_FLAG_WRITE_THROUGH | FILE_ATTRIBUTE_HIDDEN, nullptr);
            if (hFile == INVALID_HANDLE_VALUE) {
                SS_LOG_LAST_ERROR(L"PrivacyCleaner", L"SecureEraseFreeSpace: failed to open wipe file");
                return false;
            }

            uint64_t totalWritten = 0;
            bool diskFull = false;

            while (!diskFull) {
                // Fill with random data if needed
                if (useRandom) {
                    std::lock_guard rngLock(m_rngMutex);
                    std::uniform_int_distribution<uint16_t> dist(0, 255);
                    for (DWORD i = 0; i < CHUNK_SIZE; ++i) {
                        buffer[i] = static_cast<uint8_t>(dist(m_rng));
                    }
                }

                DWORD written = 0;
                if (!WriteFile(hFile, buffer.data(), CHUNK_SIZE, &written, nullptr)) {
                    DWORD err = GetLastError();
                    if (err == ERROR_DISK_FULL || err == ERROR_HANDLE_DISK_FULL) {
                        diskFull = true;
                    } else {
                        SS_LOG_ERROR(L"PrivacyCleaner", L"SecureEraseFreeSpace: write error %lu on pass %d",
                            err, pass + 1);
                        CloseHandle(hFile);
                        return false;
                    }
                }
                totalWritten += written;
            }

            CloseHandle(hFile);
            // Delete wipe file between passes to reclaim space for next pass
            DeleteFileW(tempFileName);

            SS_LOG_INFO(L"PrivacyCleaner", L"Free-space wipe pass %d/%d complete: %llu bytes written",
                pass + 1, passCount, static_cast<unsigned long long>(totalWritten));
        }

        wipeGuard.path = nullptr; // Already deleted in loop
        m_stats.totalSecureErases.fetch_add(1, std::memory_order_relaxed);
        SS_LOG_INFO(L"PrivacyCleaner", L"Free-space wipe complete on drive %ls", driveRoot.c_str());
        return true;

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"PrivacyCleaner", L"SecureEraseFreeSpace exception: %hs", e.what());
        return false;
    }
#else
    (void)driveLetter; (void)method;
    SS_LOG_WARN(L"PrivacyCleaner", L"SecureEraseFreeSpace: not supported on this platform");
    return false;
#endif
}

// ============================================================================
// SCHEDULING
// ============================================================================

bool PrivacyCleanerImpl::AddSchedule(const CleanSchedule& schedule) {
    std::unique_lock lock(m_mutex);

    try {
        // Reject duplicate schedule IDs
        for (const auto& existing : m_schedules) {
            if (existing.scheduleId == schedule.scheduleId) {
                SS_LOG_WARN(L"PrivacyCleaner", L"AddSchedule: duplicate schedule ID '%hs'",
                    schedule.scheduleId.c_str());
                return false;
            }
        }

        // Validate schedule ID is non-empty
        if (schedule.scheduleId.empty()) {
            SS_LOG_ERROR(L"PrivacyCleaner", L"AddSchedule: empty schedule ID");
            return false;
        }

        m_schedules.push_back(schedule);
        SS_LOG_INFO(L"PrivacyCleaner", L"Added schedule: %hs", schedule.scheduleId.c_str());
        return true;
    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"PrivacyCleaner", L"AddSchedule failed: %hs", e.what());
        return false;
    }
}

bool PrivacyCleanerImpl::RemoveSchedule(const std::string& scheduleId) {
    std::unique_lock lock(m_mutex);

    auto it = std::remove_if(m_schedules.begin(), m_schedules.end(),
        [&scheduleId](const CleanSchedule& s) { return s.scheduleId == scheduleId; });

    if (it != m_schedules.end()) {
        m_schedules.erase(it, m_schedules.end());
        SS_LOG_INFO(L"PrivacyCleaner", L"Removed schedule: %hs", scheduleId.c_str());
        return true;
    }

    SS_LOG_WARN(L"PrivacyCleaner", L"RemoveSchedule: schedule '%hs' not found", scheduleId.c_str());
    return false;
}

bool PrivacyCleanerImpl::SetScheduleEnabled(const std::string& scheduleId, bool enabled) {
    std::unique_lock lock(m_mutex);

    for (auto& schedule : m_schedules) {
        if (schedule.scheduleId == scheduleId) {
            schedule.enabled = enabled;
            SS_LOG_INFO(L"PrivacyCleaner", L"Schedule '%hs' %ls",
                scheduleId.c_str(), enabled ? L"enabled" : L"disabled");
            return true;
        }
    }

    SS_LOG_WARN(L"PrivacyCleaner", L"SetScheduleEnabled: schedule '%hs' not found", scheduleId.c_str());
    return false;
}

std::vector<CleanSchedule> PrivacyCleanerImpl::GetSchedules() const {
    std::shared_lock lock(m_mutex);
    return m_schedules;
}

CleanResultDetails PrivacyCleanerImpl::RunScheduledClean(const std::string& scheduleId) {
    CleanSchedule schedule;

    {
        std::shared_lock lock(m_mutex);
        auto it = std::find_if(m_schedules.begin(), m_schedules.end(),
            [&scheduleId](const CleanSchedule& s) { return s.scheduleId == scheduleId; });

        if (it == m_schedules.end()) {
            SS_LOG_ERROR(L"PrivacyCleaner", L"Schedule not found: %hs", scheduleId.c_str());
            return {};
        }

        schedule = *it;
    }

    if (!schedule.enabled) {
        SS_LOG_WARN(L"PrivacyCleaner", L"Schedule disabled: %hs", scheduleId.c_str());
        return {};
    }

    CleanResultDetails result;

    // Clean browser data
    if (schedule.browserData != BrowserDataType::None) {
        for (auto browser : schedule.browsers) {
            auto browserResult = CleanBrowser(browser, schedule.browserData);
            result.itemsCleaned += browserResult.itemsCleaned;
            result.bytesCleaned += browserResult.bytesCleaned;
            result.itemsFailed += browserResult.itemsFailed;
        }
    }

    // Clean system data
    if (schedule.systemData != SystemDataType::None) {
        auto systemResult = CleanSystem(schedule.systemData);
        result.itemsCleaned += systemResult.itemsCleaned;
        result.bytesCleaned += systemResult.bytesCleaned;
        result.itemsFailed += systemResult.itemsFailed;
    }

    result.result = (result.itemsFailed == 0) ? CleanResult::Success : CleanResult::PartialSuccess;
    m_stats.scheduledCleans.fetch_add(1, std::memory_order_relaxed);

    SS_LOG_INFO(L"PrivacyCleaner", L"Scheduled clean complete: %hs (%u items)",
        scheduleId.c_str(), result.itemsCleaned);

    return result;
}

// ============================================================================
// COOKIE MANAGEMENT
// ============================================================================

bool PrivacyCleanerImpl::AddPreservedDomain(const std::string& domain) {
    if (domain.empty()) {
        SS_LOG_WARN(L"PrivacyCleaner", L"AddPreservedDomain: empty domain");
        return false;
    }

    std::unique_lock lock(m_mutex);
    auto lowered = ToLowerAscii(domain);
    auto [_, inserted] = m_preservedDomains.insert(std::move(lowered));
    if (inserted) {
        SS_LOG_INFO(L"PrivacyCleaner", L"Added preserved domain: %hs", domain.c_str());
    }
    return true;
}

bool PrivacyCleanerImpl::RemovePreservedDomain(const std::string& domain) {
    std::unique_lock lock(m_mutex);
    auto it = m_preservedDomains.find(ToLowerAscii(domain));
    if (it != m_preservedDomains.end()) {
        m_preservedDomains.erase(it);
        SS_LOG_INFO(L"PrivacyCleaner", L"Removed preserved domain: %hs", domain.c_str());
        return true;
    }
    return false;
}

std::vector<std::string> PrivacyCleanerImpl::GetPreservedDomains() const {
    std::shared_lock lock(m_mutex);
    return std::vector<std::string>(m_preservedDomains.begin(), m_preservedDomains.end());
}

// ============================================================================
// CALLBACKS
// ============================================================================

void PrivacyCleanerImpl::RegisterProgressCallback(ProgressCallback callback) {
    std::lock_guard lock(m_callbackMutex);
    m_progressCallback = std::move(callback);
}

void PrivacyCleanerImpl::RegisterCompletionCallback(CompletionCallback callback) {
    std::lock_guard lock(m_callbackMutex);
    m_completionCallback = std::move(callback);
}

void PrivacyCleanerImpl::RegisterScanCallback(ScanCallback callback) {
    std::lock_guard lock(m_callbackMutex);
    m_scanCallback = std::move(callback);
}

void PrivacyCleanerImpl::RegisterConfirmCallback(ConfirmCallback callback) {
    std::lock_guard lock(m_callbackMutex);
    m_confirmCallback = std::move(callback);
}

void PrivacyCleanerImpl::RegisterErrorCallback(ErrorCallback callback) {
    std::lock_guard lock(m_callbackMutex);
    m_errorCallback = std::move(callback);
}

void PrivacyCleanerImpl::UnregisterCallbacks() {
    std::lock_guard lock(m_callbackMutex);
    m_progressCallback = nullptr;
    m_completionCallback = nullptr;
    m_scanCallback = nullptr;
    m_confirmCallback = nullptr;
    m_errorCallback = nullptr;
}

// ============================================================================
// STATISTICS
// ============================================================================

CleanerStatistics PrivacyCleanerImpl::GetStatistics() const {
    // Manually load each atomic into a new default-constructed object.
    // This is NOT an atomic snapshot across all fields, which is acceptable
    // for telemetry counters — each individual read is atomic.
    CleanerStatistics snapshot;
    snapshot.totalCleanOperations.store(m_stats.totalCleanOperations.load(std::memory_order_acquire), std::memory_order_relaxed);
    snapshot.totalBytesReclaimed.store(m_stats.totalBytesReclaimed.load(std::memory_order_acquire), std::memory_order_relaxed);
    snapshot.totalFilesDeleted.store(m_stats.totalFilesDeleted.load(std::memory_order_acquire), std::memory_order_relaxed);
    snapshot.totalSecureErases.store(m_stats.totalSecureErases.load(std::memory_order_acquire), std::memory_order_relaxed);
    snapshot.browserCleans.store(m_stats.browserCleans.load(std::memory_order_acquire), std::memory_order_relaxed);
    snapshot.systemCleans.store(m_stats.systemCleans.load(std::memory_order_acquire), std::memory_order_relaxed);
    snapshot.scheduledCleans.store(m_stats.scheduledCleans.load(std::memory_order_acquire), std::memory_order_relaxed);
    snapshot.failedOperations.store(m_stats.failedOperations.load(std::memory_order_acquire), std::memory_order_relaxed);
    snapshot.cookiesDeleted.store(m_stats.cookiesDeleted.load(std::memory_order_acquire), std::memory_order_relaxed);
    snapshot.cacheCleared.store(m_stats.cacheCleared.load(std::memory_order_acquire), std::memory_order_relaxed);
    snapshot.historyCleared.store(m_stats.historyCleared.load(std::memory_order_acquire), std::memory_order_relaxed);
    for (size_t i = 0; i < m_stats.byBrowser.size(); ++i) {
        snapshot.byBrowser[i].store(m_stats.byBrowser[i].load(std::memory_order_acquire), std::memory_order_relaxed);
    }
    snapshot.startTime = m_stats.startTime;
    return snapshot;
}

void PrivacyCleanerImpl::ResetStatistics() {
    m_stats.Reset();
    m_stats.startTime = Clock::now();
    SS_LOG_INFO(L"PrivacyCleaner", L"Statistics reset");
}

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

CleanTarget PrivacyCleanerImpl::CreateCleanTarget(
    const fs::path& path,
    const std::string& description,
    const std::string& category) {

    CleanTarget target;
    target.path = path;
    target.description = description;
    target.category = category;

    std::error_code ec;
    target.isDirectory = fs::is_directory(path, ec);

    if (target.isDirectory) {
        target.sizeBytes = CalculateDirectorySize(path);
        target.fileCount = CountFilesInDirectory(path);
    } else {
        target.sizeBytes = fs::file_size(path, ec);
        if (ec) target.sizeBytes = 0;
        target.fileCount = 1;
    }

    target.lastModified = std::chrono::system_clock::now();
    target.isInUse = !target.isDirectory && IsFileInUse(path);

    return target;
}

bool PrivacyCleanerImpl::DeleteFileSecurely(const fs::path& filePath, SecureEraseMethod method) {
    try {
        switch (method) {
            case SecureEraseMethod::SinglePass:
                if (!OverwriteFile(filePath, 0x00)) return false;
                break;

            case SecureEraseMethod::ThreePass:
                if (!OverwriteFileRandom(filePath)) return false;
                if (!OverwriteFileRandom(filePath)) return false;
                if (!OverwriteFileRandom(filePath)) return false;
                break;

            case SecureEraseMethod::DoD_5220_22_M:
                DoD_5220_22_M_Erase(filePath);
                break;

            case SecureEraseMethod::Gutmann:
                GutmannErase(filePath);
                break;

            case SecureEraseMethod::NIST_800_88:
                NIST_800_88_Erase(filePath);
                break;

            case SecureEraseMethod::Random:
                if (!OverwriteFileRandom(filePath)) return false;
                break;
        }

        // Delete file after overwriting
        std::error_code ec;
        fs::remove(filePath, ec);
        if (ec) {
            SS_LOG_WARN(L"PrivacyCleaner", L"DeleteFileSecurely: overwrite succeeded but remove failed: %hs",
                filePath.string().c_str());
            return false;
        }
        return true;

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"PrivacyCleaner", L"DeleteFileSecurely failed for %hs: %hs",
            filePath.string().c_str(), e.what());
        return false;
    }
}

bool PrivacyCleanerImpl::OverwriteFile(const fs::path& filePath, uint8_t pattern) {
    try {
        std::fstream file(filePath, std::ios::in | std::ios::out | std::ios::binary);
        if (!file) return false;

        file.seekg(0, std::ios::end);
        auto size = file.tellg();
        if (size <= 0) { file.close(); return true; }
        file.seekg(0, std::ios::beg);

        constexpr size_t BUFFER_SIZE = 64 * 1024;  // 64KB buffer
        std::vector<uint8_t> buffer(BUFFER_SIZE, pattern);

        for (std::streampos pos = 0; pos < size; pos += BUFFER_SIZE) {
            auto remaining = static_cast<size_t>(size - pos);
            auto writeSize = std::min(BUFFER_SIZE, remaining);
            file.write(reinterpret_cast<const char*>(buffer.data()), static_cast<std::streamsize>(writeSize));
            if (!file) {
                SS_LOG_ERROR(L"PrivacyCleaner", L"OverwriteFile: write failed at offset %lld",
                    static_cast<long long>(pos));
                return false;
            }
        }

        file.flush();
        file.close();
        return true;

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"PrivacyCleaner", L"OverwriteFile failed: %hs", e.what());
        return false;
    }
}

bool PrivacyCleanerImpl::OverwriteFileRandom(const fs::path& filePath) {
    try {
        std::fstream file(filePath, std::ios::in | std::ios::out | std::ios::binary);
        if (!file) return false;

        file.seekg(0, std::ios::end);
        auto size = file.tellg();
        if (size <= 0) { file.close(); return true; }
        file.seekg(0, std::ios::beg);

        constexpr size_t BUFFER_SIZE = 64 * 1024;
        std::vector<uint8_t> buffer(BUFFER_SIZE);

        for (std::streampos pos = 0; pos < size; pos += BUFFER_SIZE) {
            auto remaining = static_cast<size_t>(size - pos);
            auto writeSize = std::min(BUFFER_SIZE, remaining);

            // Only hold the RNG mutex while filling the buffer, NOT during I/O
            {
                std::lock_guard lock(m_rngMutex);
                std::uniform_int_distribution<uint16_t> dist(0, 255);
                for (size_t i = 0; i < writeSize; ++i) {
                    buffer[i] = static_cast<uint8_t>(dist(m_rng));
                }
            }

            file.write(reinterpret_cast<const char*>(buffer.data()), static_cast<std::streamsize>(writeSize));
            if (!file) {
                SS_LOG_ERROR(L"PrivacyCleaner", L"OverwriteFileRandom: write failed at offset %lld",
                    static_cast<long long>(pos));
                return false;
            }
        }

        file.flush();
        file.close();
        return true;

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"PrivacyCleaner", L"OverwriteFileRandom failed: %hs", e.what());
        return false;
    }
}

void PrivacyCleanerImpl::DoD_5220_22_M_Erase(const fs::path& filePath) {
    // DoD 5220.22-M: Pass 1 (0xFF), Pass 2 (0x00), Pass 3 (random)
    OverwriteFile(filePath, 0xFF);
    OverwriteFile(filePath, 0x00);
    OverwriteFileRandom(filePath);
}

void PrivacyCleanerImpl::GutmannErase(const fs::path& filePath) {
    // Gutmann 35-pass: 4 random + 27 deterministic + 4 random
    for (int i = 0; i < 4; ++i) {
        OverwriteFileRandom(filePath);
    }

    for (const auto pattern : GUTMANN_DETERMINISTIC_PATTERNS) {
        OverwriteFile(filePath, pattern);
    }

    for (int i = 0; i < 4; ++i) {
        OverwriteFileRandom(filePath);
    }
}

void PrivacyCleanerImpl::NIST_800_88_Erase(const fs::path& filePath) {
    // NIST 800-88 Clear: Single pass with zeros
    OverwriteFile(filePath, 0x00);
}

bool PrivacyCleanerImpl::CleanChromiumCache(const fs::path& profilePath) {
    bool success = true;
    std::error_code ec;

    // Chromium cache directories
    const std::array<const char*, 3> cacheDirs = { "Cache", "Code Cache", "GPUCache" };
    for (const auto* dirName : cacheDirs) {
        fs::path cachePath = profilePath / dirName;
        if (fs::exists(cachePath, ec) && !ec && fs::is_directory(cachePath, ec) && !ec) {
            for (const auto& entry : fs::recursive_directory_iterator(cachePath, kDirIterOpts, ec)) {
                if (ec) { ec.clear(); continue; }
                if (entry.is_regular_file(ec) && !ec) {
                    if (!DeleteFileSecurely(entry.path(), m_config.defaultEraseMethod)) {
                        success = false;
                    }
                }
            }
        }
    }

    if (success) {
        m_stats.cacheCleared.fetch_add(1, std::memory_order_relaxed);
    }
    return success;
}

bool PrivacyCleanerImpl::CleanChromiumCookies(const fs::path& profilePath) {
    std::error_code ec;
    fs::path cookiesPath = profilePath / "Cookies";
    if (!fs::exists(cookiesPath, ec) || ec) {
        return true; // Nothing to clean
    }

    bool deleted = DeleteFileSecurely(cookiesPath, m_config.defaultEraseMethod);

    // Also clean Cookies-journal if present
    fs::path journalPath = profilePath / "Cookies-journal";
    if (fs::exists(journalPath, ec) && !ec) {
        DeleteFileSecurely(journalPath, m_config.defaultEraseMethod);
    }

    if (deleted) {
        m_stats.cookiesDeleted.fetch_add(1, std::memory_order_relaxed);
    }
    return deleted;
}

bool PrivacyCleanerImpl::CleanChromiumHistory(const fs::path& profilePath) {
    bool success = true;
    std::error_code ec;

    // Main history database
    const std::array<const char*, 4> historyFiles = {
        "History", "History-journal", "Visited Links", "Top Sites"
    };

    for (const auto* fileName : historyFiles) {
        fs::path filePath = profilePath / fileName;
        if (fs::exists(filePath, ec) && !ec) {
            if (!DeleteFileSecurely(filePath, m_config.defaultEraseMethod)) {
                success = false;
            }
        }
    }

    if (success) {
        m_stats.historyCleared.fetch_add(1, std::memory_order_relaxed);
    }
    return success;
}

std::vector<CleanTarget> PrivacyCleanerImpl::ScanChromiumBrowser(BrowserType browser, BrowserDataType dataTypes) {
    std::vector<CleanTarget> targets;

    try {
        auto browserPaths = GetBrowserPathsInternal(browser);
        uint32_t dtypes = static_cast<uint32_t>(dataTypes);

        for (const auto& basePath : browserPaths.profilePaths) {
            std::error_code ec;
            if (!fs::exists(basePath, ec) || ec) continue;

            for (const auto& entry : fs::directory_iterator(basePath, kDirIterOpts, ec)) {
                if (ec) { ec.clear(); break; }
                if (!entry.is_directory(ec) || ec) continue;

                auto dirName = entry.path().filename().string();
                if (dirName.find("Profile") != 0 && dirName != "Default") continue;

                auto profilePath = entry.path();

                if (dtypes & static_cast<uint32_t>(BrowserDataType::Cache)) {
                    auto cachePath = profilePath / "Cache";
                    if (fs::exists(cachePath, ec) && !ec) {
                        targets.push_back(CreateCleanTarget(cachePath, "Browser Cache", "Cache"));
                    }
                    // Also check Cache2/Code Cache for newer Chromium
                    auto codeCachePath = profilePath / "Code Cache";
                    if (fs::exists(codeCachePath, ec) && !ec) {
                        targets.push_back(CreateCleanTarget(codeCachePath, "Code Cache", "Cache"));
                    }
                }

                if (dtypes & static_cast<uint32_t>(BrowserDataType::Cookies)) {
                    auto cookiesPath = profilePath / "Cookies";
                    if (fs::exists(cookiesPath, ec) && !ec) {
                        targets.push_back(CreateCleanTarget(cookiesPath, "Browser Cookies", "Cookies"));
                    }
                }

                if (dtypes & static_cast<uint32_t>(BrowserDataType::History)) {
                    auto historyPath = profilePath / "History";
                    if (fs::exists(historyPath, ec) && !ec) {
                        targets.push_back(CreateCleanTarget(historyPath, "Browsing History", "History"));
                    }
                }

                if (dtypes & static_cast<uint32_t>(BrowserDataType::LocalStorage)) {
                    auto localStoragePath = profilePath / "Local Storage";
                    if (fs::exists(localStoragePath, ec) && !ec) {
                        targets.push_back(CreateCleanTarget(localStoragePath, "Local Storage", "Storage"));
                    }
                }

                if (dtypes & static_cast<uint32_t>(BrowserDataType::SessionStorage)) {
                    auto sessionPath = profilePath / "Session Storage";
                    if (fs::exists(sessionPath, ec) && !ec) {
                        targets.push_back(CreateCleanTarget(sessionPath, "Session Storage", "Storage"));
                    }
                }

                if (dtypes & static_cast<uint32_t>(BrowserDataType::IndexedDB)) {
                    auto indexedDBPath = profilePath / "IndexedDB";
                    if (fs::exists(indexedDBPath, ec) && !ec) {
                        targets.push_back(CreateCleanTarget(indexedDBPath, "IndexedDB", "Storage"));
                    }
                }

                if (dtypes & static_cast<uint32_t>(BrowserDataType::ServiceWorkers)) {
                    auto swPath = profilePath / "Service Worker";
                    if (fs::exists(swPath, ec) && !ec) {
                        targets.push_back(CreateCleanTarget(swPath, "Service Workers", "Storage"));
                    }
                }
            }
        }

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"PrivacyCleaner", L"ScanChromiumBrowser error: %hs", e.what());
    }

    return targets;
}

std::vector<CleanTarget> PrivacyCleanerImpl::ScanFirefox(BrowserDataType dataTypes) {
    std::vector<CleanTarget> targets;

    try {
        auto browserPaths = GetBrowserPathsInternal(BrowserType::Firefox);
        uint32_t dtypes = static_cast<uint32_t>(dataTypes);

        for (const auto& basePath : browserPaths.profilePaths) {
            std::error_code ec;
            if (!fs::exists(basePath, ec) || ec) continue;

            for (const auto& entry : fs::directory_iterator(basePath, kDirIterOpts, ec)) {
                if (ec) { ec.clear(); break; }
                if (!entry.is_directory(ec) || ec) continue;

                auto profilePath = entry.path();

                if (dtypes & static_cast<uint32_t>(BrowserDataType::Cache)) {
                    auto cachePath = profilePath / "cache2";
                    if (fs::exists(cachePath, ec) && !ec) {
                        targets.push_back(CreateCleanTarget(cachePath, "Firefox Cache", "Cache"));
                    }
                }

                if (dtypes & static_cast<uint32_t>(BrowserDataType::Cookies)) {
                    auto cookiesPath = profilePath / "cookies.sqlite";
                    if (fs::exists(cookiesPath, ec) && !ec) {
                        targets.push_back(CreateCleanTarget(cookiesPath, "Firefox Cookies", "Cookies"));
                    }
                }

                if (dtypes & static_cast<uint32_t>(BrowserDataType::History)) {
                    auto historyPath = profilePath / "places.sqlite";
                    if (fs::exists(historyPath, ec) && !ec) {
                        targets.push_back(CreateCleanTarget(historyPath, "Firefox History", "History"));
                    }
                }

                if (dtypes & static_cast<uint32_t>(BrowserDataType::FormData)) {
                    auto formPath = profilePath / "formhistory.sqlite";
                    if (fs::exists(formPath, ec) && !ec) {
                        targets.push_back(CreateCleanTarget(formPath, "Firefox Form Data", "FormData"));
                    }
                }

                if (dtypes & static_cast<uint32_t>(BrowserDataType::SessionStorage)) {
                    auto sessionPath = profilePath / "sessionstore.jsonlz4";
                    if (fs::exists(sessionPath, ec) && !ec) {
                        targets.push_back(CreateCleanTarget(sessionPath, "Firefox Session", "Storage"));
                    }
                }
            }
        }

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"PrivacyCleaner", L"ScanFirefox error: %hs", e.what());
    }

    return targets;
}

std::vector<CleanTarget> PrivacyCleanerImpl::ScanRecentDocuments() {
    std::vector<CleanTarget> targets;

#ifdef _WIN32
    try {
        wchar_t recentPath[MAX_PATH] = {};
        if (SUCCEEDED(SHGetFolderPathW(nullptr, CSIDL_RECENT, nullptr, SHGFP_TYPE_CURRENT, recentPath))) {
            std::error_code ec;
            fs::path recent = recentPath;
            if (fs::exists(recent, ec) && !ec) {
                targets.push_back(CreateCleanTarget(recent, "Recent Documents", "System"));
            }
        }
    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"PrivacyCleaner", L"ScanRecentDocuments error: %hs", e.what());
    }
#endif

    return targets;
}

std::vector<CleanTarget> PrivacyCleanerImpl::ScanJumpLists() {
    std::vector<CleanTarget> targets;

#ifdef _WIN32
    try {
        wchar_t appDataPath[MAX_PATH] = {};
        if (SUCCEEDED(SHGetFolderPathW(nullptr, CSIDL_APPDATA, nullptr, SHGFP_TYPE_CURRENT, appDataPath))) {
            std::error_code ec;
            fs::path jumpListPath = fs::path(appDataPath) / "Microsoft" / "Windows" / "Recent" / "AutomaticDestinations";
            if (fs::exists(jumpListPath, ec) && !ec) {
                targets.push_back(CreateCleanTarget(jumpListPath, "Jump Lists (Auto)", "System"));
            }
            fs::path customJumpPath = fs::path(appDataPath) / "Microsoft" / "Windows" / "Recent" / "CustomDestinations";
            if (fs::exists(customJumpPath, ec) && !ec) {
                targets.push_back(CreateCleanTarget(customJumpPath, "Jump Lists (Custom)", "System"));
            }
        }
    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"PrivacyCleaner", L"ScanJumpLists error: %hs", e.what());
    }
#endif

    return targets;
}

std::vector<CleanTarget> PrivacyCleanerImpl::ScanThumbnailCache() {
    std::vector<CleanTarget> targets;

#ifdef _WIN32
    try {
        wchar_t localAppDataPath[MAX_PATH] = {};
        if (SUCCEEDED(SHGetFolderPathW(nullptr, CSIDL_LOCAL_APPDATA, nullptr, SHGFP_TYPE_CURRENT, localAppDataPath))) {
            std::error_code ec;
            fs::path thumbCachePath = fs::path(localAppDataPath) / "Microsoft" / "Windows" / "Explorer";
            if (fs::exists(thumbCachePath, ec) && !ec) {
                for (const auto& entry : fs::directory_iterator(thumbCachePath, kDirIterOpts, ec)) {
                    if (ec) { ec.clear(); break; }
                    if (entry.path().extension() == ".db") {
                        targets.push_back(CreateCleanTarget(entry.path(), "Thumbnail Cache", "System"));
                    }
                }
            }
        }
    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"PrivacyCleaner", L"ScanThumbnailCache error: %hs", e.what());
    }
#endif

    return targets;
}

std::vector<CleanTarget> PrivacyCleanerImpl::ScanTempFiles() {
    std::vector<CleanTarget> targets;

#ifdef _WIN32
    try {
        wchar_t tempPath[MAX_PATH] = {};
        GetTempPathW(MAX_PATH, tempPath);

        std::error_code ec;
        fs::path temp = tempPath;
        if (fs::exists(temp, ec) && !ec) {
            targets.push_back(CreateCleanTarget(temp, "Temporary Files", "System"));
        }
    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"PrivacyCleaner", L"ScanTempFiles error: %hs", e.what());
    }
#endif

    return targets;
}

std::vector<CleanTarget> PrivacyCleanerImpl::ScanPrefetch() {
    std::vector<CleanTarget> targets;

#ifdef _WIN32
    try {
        // Resolve Windows directory dynamically instead of hardcoding C:\Windows
        wchar_t winDir[MAX_PATH] = {};
        GetWindowsDirectoryW(winDir, MAX_PATH);
        fs::path prefetchPath = fs::path(winDir) / L"Prefetch";

        std::error_code ec;
        if (fs::exists(prefetchPath, ec) && !ec) {
            CleanTarget target;
            target.path = prefetchPath;
            target.description = "Prefetch Files";
            target.category = "System";
            target.isDirectory = true;
            target.requiresElevation = true; // Prefetch typically requires admin
            target.sizeBytes = CalculateDirectorySize(prefetchPath);
            target.fileCount = CountFilesInDirectory(prefetchPath);
            targets.push_back(std::move(target));
        }
    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"PrivacyCleaner", L"ScanPrefetch error: %hs", e.what());
    }
#endif

    return targets;
}

bool PrivacyCleanerImpl::DeleteTarget(const CleanTarget& target, SecureEraseMethod method) {
    try {
        std::error_code ec;
        if (!fs::exists(target.path, ec) || ec) {
            return false;
        }

        if (IsPathExcluded(target.path)) {
            SS_LOG_DEBUG(L"PrivacyCleaner", L"Skipping excluded path: %hs", target.path.string().c_str());
            return false;
        }

        if (target.isDirectory) {
            for (const auto& entry : fs::recursive_directory_iterator(target.path, kDirIterOpts, ec)) {
                if (ec) { ec.clear(); continue; }
                if (entry.is_regular_file(ec) && !ec) {
                    DeleteFileSecurely(entry.path(), method);
                }
            }
            fs::remove_all(target.path, ec);
            if (ec) {
                SS_LOG_WARN(L"PrivacyCleaner", L"DeleteTarget: could not fully remove directory: %hs",
                    target.path.string().c_str());
            }
        } else {
            DeleteFileSecurely(target.path, method);
        }

        return true;

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"PrivacyCleaner", L"DeleteTarget failed for %hs: %hs",
            target.path.string().c_str(), e.what());
        return false;
    }
}

uint64_t PrivacyCleanerImpl::CalculateDirectorySize(const fs::path& dirPath) {
    uint64_t totalSize = 0;
    std::error_code ec;

    for (const auto& entry : fs::recursive_directory_iterator(dirPath, kDirIterOpts, ec)) {
        if (ec) { ec.clear(); continue; }
        if (entry.is_regular_file(ec) && !ec) {
            auto sz = entry.file_size(ec);
            if (!ec) totalSize += sz;
            else ec.clear();
        }
    }

    return totalSize;
}

uint32_t PrivacyCleanerImpl::CountFilesInDirectory(const fs::path& dirPath) {
    uint32_t count = 0;
    std::error_code ec;

    for (const auto& entry : fs::recursive_directory_iterator(dirPath, kDirIterOpts, ec)) {
        if (ec) { ec.clear(); continue; }
        if (entry.is_regular_file(ec) && !ec) {
            ++count;
        }
    }

    return count;
}

bool PrivacyCleanerImpl::IsFileInUse(const fs::path& filePath) {
#ifdef _WIN32
    HANDLE hFile = CreateFileW(
        filePath.c_str(),
        GENERIC_READ,
        0,  // No sharing — probes for exclusive access
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr
    );

    if (hFile == INVALID_HANDLE_VALUE) {
        // Do NOT call CloseHandle on INVALID_HANDLE_VALUE
        return (GetLastError() == ERROR_SHARING_VIOLATION);
    }

    CloseHandle(hFile);
#endif

    return false;
}

bool PrivacyCleanerImpl::IsPathExcluded(const fs::path& path) {
    std::shared_lock lock(m_mutex);

    // Normalize to canonical form for reliable comparison
    std::error_code ec;
    fs::path normalizedPath = fs::weakly_canonical(path, ec);
    if (ec) normalizedPath = path; // Fallback to raw path

    for (const auto& excluded : m_config.excludedPaths) {
        fs::path normalizedExcluded = fs::weakly_canonical(excluded, ec);
        if (ec) { ec.clear(); normalizedExcluded = excluded; }

        // Check if path starts with the excluded path (proper prefix)
        auto [pathIt, exclIt] = std::mismatch(
            normalizedPath.begin(), normalizedPath.end(),
            normalizedExcluded.begin(), normalizedExcluded.end());

        if (exclIt == normalizedExcluded.end()) {
            return true; // Excluded path is a prefix of this path
        }
    }

    return false;
}

bool PrivacyCleanerImpl::IsDomainPreserved(const std::string& domain) {
    std::shared_lock lock(m_mutex);
    return m_preservedDomains.find(ToLowerAscii(domain)) != m_preservedDomains.end();
}

void PrivacyCleanerImpl::NotifyProgress(const std::string& item, int percent) {
    ProgressCallback cb;
    {
        std::lock_guard lock(m_callbackMutex);
        cb = m_progressCallback;
    }
    if (cb) {
        try {
            cb(item, percent);
        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"PrivacyCleaner", L"Progress callback exception: %hs", e.what());
        } catch (...) {
            SS_LOG_ERROR(L"PrivacyCleaner", L"Progress callback threw unknown exception");
        }
    }
}

void PrivacyCleanerImpl::NotifyCompletion(const CleanResultDetails& result) {
    CompletionCallback cb;
    {
        std::lock_guard lock(m_callbackMutex);
        cb = m_completionCallback;
    }
    if (cb) {
        try {
            cb(result);
        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"PrivacyCleaner", L"Completion callback exception: %hs", e.what());
        } catch (...) {
            SS_LOG_ERROR(L"PrivacyCleaner", L"Completion callback threw unknown exception");
        }
    }
}

void PrivacyCleanerImpl::NotifyScan(const CleanScanResult& result) {
    ScanCallback cb;
    {
        std::lock_guard lock(m_callbackMutex);
        cb = m_scanCallback;
    }
    if (cb) {
        try {
            cb(result);
        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"PrivacyCleaner", L"Scan callback exception: %hs", e.what());
        } catch (...) {
            SS_LOG_ERROR(L"PrivacyCleaner", L"Scan callback threw unknown exception");
        }
    }
}

bool PrivacyCleanerImpl::NotifyConfirm(const std::string& message) {
    ConfirmCallback cb;
    {
        std::lock_guard lock(m_callbackMutex);
        cb = m_confirmCallback;
    }
    if (cb) {
        try {
            return cb(message);
        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"PrivacyCleaner", L"Confirm callback exception: %hs", e.what());
        } catch (...) {
            SS_LOG_ERROR(L"PrivacyCleaner", L"Confirm callback threw unknown exception");
        }
    }
    return true;  // Default: proceed
}

void PrivacyCleanerImpl::NotifyError(const std::string& message, int code) {
    ErrorCallback cb;
    {
        std::lock_guard lock(m_callbackMutex);
        cb = m_errorCallback;
    }
    if (cb) {
        try {
            cb(message, code);
        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"PrivacyCleaner", L"Error callback exception: %hs", e.what());
        } catch (...) {
            SS_LOG_ERROR(L"PrivacyCleaner", L"Error callback threw unknown exception");
        }
    }
}

bool PrivacyCleanerImpl::SelfTest() {
    SS_LOG_INFO(L"PrivacyCleaner", L"Running self-test...");

    try {
        // Test 1: Secure erase single pass
        {
            std::error_code ec;
            fs::path testFile = fs::temp_directory_path(ec) / "shadowstrike_test_erase.tmp";
            if (ec) {
                SS_LOG_ERROR(L"PrivacyCleaner", L"Self-test: cannot get temp directory");
                return false;
            }

            {
                std::ofstream file(testFile, std::ios::binary);
                if (!file) {
                    SS_LOG_ERROR(L"PrivacyCleaner", L"Self-test: cannot create test file");
                    return false;
                }
                file << "Test data for secure erase";
                file.close();
            }

            if (!SecureEraseFile(testFile, SecureEraseMethod::SinglePass)) {
                SS_LOG_ERROR(L"PrivacyCleaner", L"Self-test failed: Secure erase returned false");
                fs::remove(testFile, ec); // Cleanup on failure
                return false;
            }

            if (fs::exists(testFile, ec)) {
                SS_LOG_ERROR(L"PrivacyCleaner", L"Self-test failed: File still exists after erase");
                fs::remove(testFile, ec);
                return false;
            }
        }

        // Test 2: Browser profile detection
        {
            auto profiles = GetBrowserProfiles(BrowserType::Chrome);
            SS_LOG_INFO(L"PrivacyCleaner", L"Self-test: Found %zu Chrome profiles", profiles.size());
        }

        // Test 3: Preserved domain management
        {
            const std::string testDomain = "selftest.shadowstrike.internal";
            AddPreservedDomain(testDomain);
            if (!IsDomainPreserved(testDomain)) {
                SS_LOG_ERROR(L"PrivacyCleaner", L"Self-test failed: Domain preservation add/check");
                RemovePreservedDomain(testDomain);
                return false;
            }
            RemovePreservedDomain(testDomain);
            if (IsDomainPreserved(testDomain)) {
                SS_LOG_ERROR(L"PrivacyCleaner", L"Self-test failed: Domain still preserved after removal");
                return false;
            }
        }

        SS_LOG_INFO(L"PrivacyCleaner", L"Self-test PASSED");
        return true;

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"PrivacyCleaner", L"Self-test exception: %hs", e.what());
        return false;
    }
}

// ============================================================================
// SINGLETON IMPLEMENTATION
// ============================================================================

std::atomic<bool> PrivacyCleaner::s_instanceCreated{false};

PrivacyCleaner::PrivacyCleaner()
    : m_impl(std::make_unique<PrivacyCleanerImpl>()) {
    s_instanceCreated.store(true, std::memory_order_release);
}

PrivacyCleaner::~PrivacyCleaner() = default;

PrivacyCleaner& PrivacyCleaner::Instance() noexcept {
    static PrivacyCleaner instance;
    return instance;
}

bool PrivacyCleaner::HasInstance() noexcept {
    return s_instanceCreated.load(std::memory_order_acquire);
}

// ============================================================================
// PUBLIC API FORWARDING
// ============================================================================

bool PrivacyCleaner::Initialize(const CleanerConfiguration& config) {
    return m_impl->Initialize(config);
}

void PrivacyCleaner::Shutdown() {
    m_impl->Shutdown();
}

bool PrivacyCleaner::IsInitialized() const noexcept {
    return m_impl->IsInitialized();
}

ModuleStatus PrivacyCleaner::GetStatus() const noexcept {
    return m_impl->GetStatus();
}

bool PrivacyCleaner::UpdateConfiguration(const CleanerConfiguration& config) {
    return m_impl->UpdateConfiguration(config);
}

CleanerConfiguration PrivacyCleaner::GetConfiguration() const {
    return m_impl->GetConfiguration();
}

CleanScanResult PrivacyCleaner::ScanForCleanableItems() {
    return m_impl->ScanForCleanableItems();
}

std::vector<CleanTarget> PrivacyCleaner::ScanBrowserData(BrowserType browser, BrowserDataType dataTypes) {
    return m_impl->ScanBrowserData(browser, dataTypes);
}

std::vector<CleanTarget> PrivacyCleaner::ScanSystemData(SystemDataType dataTypes) {
    return m_impl->ScanSystemData(dataTypes);
}

std::vector<BrowserProfile> PrivacyCleaner::GetBrowserProfiles(BrowserType browser) {
    return m_impl->GetBrowserProfiles(browser);
}

CleanResultDetails PrivacyCleaner::CleanAll() {
    return m_impl->CleanAll();
}

CleanResultDetails PrivacyCleaner::CleanBrowser(const std::wstring& browserName) {
    return m_impl->CleanBrowser(browserName);
}

CleanResultDetails PrivacyCleaner::CleanBrowser(BrowserType browser, BrowserDataType dataTypes) {
    return m_impl->CleanBrowser(browser, dataTypes);
}

CleanResultDetails PrivacyCleaner::CleanSystem(SystemDataType dataTypes) {
    return m_impl->CleanSystem(dataTypes);
}

CleanResultDetails PrivacyCleaner::CleanTargets(const std::vector<CleanTarget>& targets) {
    return m_impl->CleanTargets(targets);
}

CleanResultDetails PrivacyCleaner::CleanTempFiles(std::chrono::hours olderThan) {
    return m_impl->CleanTempFiles(olderThan);
}

CleanResultDetails PrivacyCleaner::EmptyRecycleBin() {
    return m_impl->EmptyRecycleBin();
}

bool PrivacyCleaner::ClearDNSCache() {
    return m_impl->ClearDNSCache();
}

bool PrivacyCleaner::ClearClipboard() {
    return m_impl->ClearClipboard();
}

bool PrivacyCleaner::SecureEraseFile(const fs::path& filePath, SecureEraseMethod method) {
    return m_impl->SecureEraseFile(filePath, method);
}

CleanResultDetails PrivacyCleaner::SecureEraseDirectory(const fs::path& dirPath, SecureEraseMethod method) {
    return m_impl->SecureEraseDirectory(dirPath, method);
}

bool PrivacyCleaner::SecureEraseFreeSpace(const std::wstring& driveLetter, SecureEraseMethod method) {
    return m_impl->SecureEraseFreeSpace(driveLetter, method);
}

bool PrivacyCleaner::AddSchedule(const CleanSchedule& schedule) {
    return m_impl->AddSchedule(schedule);
}

bool PrivacyCleaner::RemoveSchedule(const std::string& scheduleId) {
    return m_impl->RemoveSchedule(scheduleId);
}

bool PrivacyCleaner::SetScheduleEnabled(const std::string& scheduleId, bool enabled) {
    return m_impl->SetScheduleEnabled(scheduleId, enabled);
}

std::vector<CleanSchedule> PrivacyCleaner::GetSchedules() const {
    return m_impl->GetSchedules();
}

CleanResultDetails PrivacyCleaner::RunScheduledClean(const std::string& scheduleId) {
    return m_impl->RunScheduledClean(scheduleId);
}

bool PrivacyCleaner::AddPreservedDomain(const std::string& domain) {
    return m_impl->AddPreservedDomain(domain);
}

bool PrivacyCleaner::RemovePreservedDomain(const std::string& domain) {
    return m_impl->RemovePreservedDomain(domain);
}

std::vector<std::string> PrivacyCleaner::GetPreservedDomains() const {
    return m_impl->GetPreservedDomains();
}

void PrivacyCleaner::RegisterProgressCallback(ProgressCallback callback) {
    m_impl->RegisterProgressCallback(std::move(callback));
}

void PrivacyCleaner::RegisterCompletionCallback(CompletionCallback callback) {
    m_impl->RegisterCompletionCallback(std::move(callback));
}

void PrivacyCleaner::RegisterScanCallback(ScanCallback callback) {
    m_impl->RegisterScanCallback(std::move(callback));
}

void PrivacyCleaner::RegisterConfirmCallback(ConfirmCallback callback) {
    m_impl->RegisterConfirmCallback(std::move(callback));
}

void PrivacyCleaner::RegisterErrorCallback(ErrorCallback callback) {
    m_impl->RegisterErrorCallback(std::move(callback));
}

void PrivacyCleaner::UnregisterCallbacks() {
    m_impl->UnregisterCallbacks();
}

CleanerStatistics PrivacyCleaner::GetStatistics() const {
    return m_impl->GetStatistics();
}

void PrivacyCleaner::ResetStatistics() {
    m_impl->ResetStatistics();
}

bool PrivacyCleaner::SelfTest() {
    return m_impl->SelfTest();
}

std::string PrivacyCleaner::GetVersionString() noexcept {
    return std::to_string(CleanerConstants::VERSION_MAJOR) + "." +
           std::to_string(CleanerConstants::VERSION_MINOR) + "." +
           std::to_string(CleanerConstants::VERSION_PATCH);
}

// ============================================================================
// STRUCTURE SERIALIZATION
// ============================================================================

CleanerStatistics::CleanerStatistics(const CleanerStatistics& other) noexcept
    : startTime(other.startTime) {
    totalCleanOperations.store(other.totalCleanOperations.load(std::memory_order_acquire), std::memory_order_relaxed);
    totalBytesReclaimed.store(other.totalBytesReclaimed.load(std::memory_order_acquire), std::memory_order_relaxed);
    totalFilesDeleted.store(other.totalFilesDeleted.load(std::memory_order_acquire), std::memory_order_relaxed);
    totalSecureErases.store(other.totalSecureErases.load(std::memory_order_acquire), std::memory_order_relaxed);
    browserCleans.store(other.browserCleans.load(std::memory_order_acquire), std::memory_order_relaxed);
    systemCleans.store(other.systemCleans.load(std::memory_order_acquire), std::memory_order_relaxed);
    scheduledCleans.store(other.scheduledCleans.load(std::memory_order_acquire), std::memory_order_relaxed);
    failedOperations.store(other.failedOperations.load(std::memory_order_acquire), std::memory_order_relaxed);
    cookiesDeleted.store(other.cookiesDeleted.load(std::memory_order_acquire), std::memory_order_relaxed);
    cacheCleared.store(other.cacheCleared.load(std::memory_order_acquire), std::memory_order_relaxed);
    historyCleared.store(other.historyCleared.load(std::memory_order_acquire), std::memory_order_relaxed);
    for (size_t i = 0; i < byBrowser.size(); ++i) {
        byBrowser[i].store(other.byBrowser[i].load(std::memory_order_acquire), std::memory_order_relaxed);
    }
}

CleanerStatistics& CleanerStatistics::operator=(const CleanerStatistics& other) noexcept {
    if (this != &other) {
        totalCleanOperations.store(other.totalCleanOperations.load(std::memory_order_acquire), std::memory_order_relaxed);
        totalBytesReclaimed.store(other.totalBytesReclaimed.load(std::memory_order_acquire), std::memory_order_relaxed);
        totalFilesDeleted.store(other.totalFilesDeleted.load(std::memory_order_acquire), std::memory_order_relaxed);
        totalSecureErases.store(other.totalSecureErases.load(std::memory_order_acquire), std::memory_order_relaxed);
        browserCleans.store(other.browserCleans.load(std::memory_order_acquire), std::memory_order_relaxed);
        systemCleans.store(other.systemCleans.load(std::memory_order_acquire), std::memory_order_relaxed);
        scheduledCleans.store(other.scheduledCleans.load(std::memory_order_acquire), std::memory_order_relaxed);
        failedOperations.store(other.failedOperations.load(std::memory_order_acquire), std::memory_order_relaxed);
        cookiesDeleted.store(other.cookiesDeleted.load(std::memory_order_acquire), std::memory_order_relaxed);
        cacheCleared.store(other.cacheCleared.load(std::memory_order_acquire), std::memory_order_relaxed);
        historyCleared.store(other.historyCleared.load(std::memory_order_acquire), std::memory_order_relaxed);
        for (size_t i = 0; i < byBrowser.size(); ++i) {
            byBrowser[i].store(other.byBrowser[i].load(std::memory_order_acquire), std::memory_order_relaxed);
        }
        startTime = other.startTime;
    }
    return *this;
}

void CleanerStatistics::Reset() noexcept {
    totalCleanOperations.store(0, std::memory_order_release);
    totalBytesReclaimed.store(0, std::memory_order_release);
    totalFilesDeleted.store(0, std::memory_order_release);
    totalSecureErases.store(0, std::memory_order_release);
    browserCleans.store(0, std::memory_order_release);
    systemCleans.store(0, std::memory_order_release);
    scheduledCleans.store(0, std::memory_order_release);
    failedOperations.store(0, std::memory_order_release);
    cookiesDeleted.store(0, std::memory_order_release);
    cacheCleared.store(0, std::memory_order_release);
    historyCleared.store(0, std::memory_order_release);

    for (auto& counter : byBrowser) {
        counter.store(0, std::memory_order_release);
    }

    startTime = Clock::now();
}

std::string CleanerStatistics::ToJson() const {
    nlohmann::json j;
    j["totalCleanOperations"] = totalCleanOperations.load(std::memory_order_acquire);
    j["totalBytesReclaimed"] = totalBytesReclaimed.load(std::memory_order_acquire);
    j["totalFilesDeleted"] = totalFilesDeleted.load(std::memory_order_acquire);
    j["totalSecureErases"] = totalSecureErases.load(std::memory_order_acquire);
    j["browserCleans"] = browserCleans.load(std::memory_order_acquire);
    j["systemCleans"] = systemCleans.load(std::memory_order_acquire);
    j["scheduledCleans"] = scheduledCleans.load(std::memory_order_acquire);
    j["failedOperations"] = failedOperations.load(std::memory_order_acquire);
    j["cookiesDeleted"] = cookiesDeleted.load(std::memory_order_acquire);
    j["cacheCleared"] = cacheCleared.load(std::memory_order_acquire);
    j["historyCleared"] = historyCleared.load(std::memory_order_acquire);

    auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
        Clock::now() - startTime).count();
    j["uptimeSeconds"] = elapsed;

    return j.dump();
}

std::string CleanTarget::ToJson() const {
    nlohmann::json j;
    j["path"] = path.string();
    j["isDirectory"] = isDirectory;
    j["sizeBytes"] = sizeBytes;
    j["fileCount"] = fileCount;
    j["description"] = description;
    j["category"] = category;
    j["requiresElevation"] = requiresElevation;
    j["isInUse"] = isInUse;
    return j.dump();
}

std::string CleanResultDetails::ToJson() const {
    nlohmann::json j;
    j["result"] = static_cast<int>(result);
    j["itemsCleaned"] = itemsCleaned;
    j["itemsFailed"] = itemsFailed;
    j["itemsSkipped"] = itemsSkipped;
    j["bytesCleaned"] = bytesCleaned;
    j["bytesFailed"] = bytesFailed;
    j["durationMs"] = duration.count();
    j["errorCount"] = errors.size();
    return j.dump();
}

std::string BrowserProfile::ToJson() const {
    nlohmann::json j;
    j["name"] = name;
    j["path"] = path.string();
    j["browser"] = static_cast<int>(browser);
    j["user"] = user;
    j["sizeBytes"] = sizeBytes;
    j["cookieCount"] = cookieCount;
    j["cacheSize"] = cacheSize;
    j["historyCount"] = historyCount;
    j["isDefault"] = isDefault;
    return j.dump();
}

std::string CleanScanResult::ToJson() const {
    nlohmann::json j;
    j["browserTargetCount"] = browserTargets.size();
    j["systemTargetCount"] = systemTargets.size();
    j["applicationTargetCount"] = applicationTargets.size();
    j["totalSizeBytes"] = totalSizeBytes;
    j["totalFileCount"] = totalFileCount;
    j["scanDurationMs"] = scanDuration.count();
    j["browserProfileCount"] = browserProfiles.size();
    return j.dump();
}

std::string CleanSchedule::ToJson() const {
    nlohmann::json j;
    j["scheduleId"] = scheduleId;
    j["type"] = static_cast<int>(type);
    j["enabled"] = enabled;
    j["browserData"] = static_cast<uint32_t>(browserData);
    j["systemData"] = static_cast<uint32_t>(systemData);
    j["eraseMethod"] = static_cast<int>(eraseMethod);
    j["hourOfDay"] = hourOfDay;
    j["dayOfWeek"] = dayOfWeek;
    return j.dump();
}

bool CleanerConfiguration::IsValid() const noexcept {
    if (tempFileAge.count() < 0 || tempFileAge.count() > 720) {  // Max 30 days
        return false;
    }
    return true;
}

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

std::string_view GetBrowserTypeName(BrowserType browser) noexcept {
    switch (browser) {
        case BrowserType::Chrome:    return "Chrome";
        case BrowserType::Firefox:   return "Firefox";
        case BrowserType::Edge:      return "Edge";
        case BrowserType::Opera:     return "Opera";
        case BrowserType::Brave:     return "Brave";
        case BrowserType::Vivaldi:   return "Vivaldi";
        case BrowserType::IE:        return "Internet Explorer";
        case BrowserType::Chromium:  return "Chromium";
        case BrowserType::All:       return "All";
        default:                     return "Unknown";
    }
}

std::string_view GetEraseMethodName(SecureEraseMethod method) noexcept {
    switch (method) {
        case SecureEraseMethod::SinglePass:     return "Single Pass";
        case SecureEraseMethod::ThreePass:      return "Three Pass";
        case SecureEraseMethod::DoD_5220_22_M:  return "DoD 5220.22-M";
        case SecureEraseMethod::Gutmann:        return "Gutmann 35-Pass";
        case SecureEraseMethod::Random:         return "Random";
        case SecureEraseMethod::NIST_800_88:    return "NIST 800-88";
        default:                                return "Unknown";
    }
}

std::string_view GetCleanResultName(CleanResult result) noexcept {
    switch (result) {
        case CleanResult::Success:        return "Success";
        case CleanResult::PartialSuccess: return "Partial Success";
        case CleanResult::AccessDenied:   return "Access Denied";
        case CleanResult::FileInUse:      return "File In Use";
        case CleanResult::NotFound:       return "Not Found";
        case CleanResult::Error:          return "Error";
        default:                          return "Unknown";
    }
}

std::string_view GetScheduleTypeName(ScheduleType type) noexcept {
    switch (type) {
        case ScheduleType::OnShutdown:     return "On Shutdown";
        case ScheduleType::OnBrowserClose: return "On Browser Close";
        case ScheduleType::Daily:          return "Daily";
        case ScheduleType::Weekly:         return "Weekly";
        case ScheduleType::OnDemand:       return "On Demand";
        default:                           return "None";
    }
}

std::vector<fs::path> GetBrowserProfilePaths(BrowserType browser) {
    auto paths = GetBrowserPathsInternal(browser);
    return paths.profilePaths;
}

fs::path GetBrowserPath(BrowserType browser) {
    auto paths = GetBrowserPathsInternal(browser);
    return paths.executablePath;
}

bool IsBrowserRunning(BrowserType browser) {
    auto paths = GetBrowserPathsInternal(browser);
    if (paths.processName.empty()) {
        return false;
    }

    try {
        std::wstring processNameW = Utils::StringUtils::ToWide(paths.processName);
        return Utils::ProcessUtils::IsProcessRunning(processNameW);
    } catch (...) {
        return false;
    }
}

bool CloseBrowser(BrowserType browser) {
    auto paths = GetBrowserPathsInternal(browser);
    if (paths.processName.empty()) {
        return false;
    }

#ifdef _WIN32
    try {
        std::wstring processNameW = Utils::StringUtils::ToWide(paths.processName);

        // Enumerate processes to find PIDs matching the browser process name
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot == INVALID_HANDLE_VALUE) {
            SS_LOG_LAST_ERROR(L"PrivacyCleaner", L"CloseBrowser: CreateToolhelp32Snapshot failed");
            return false;
        }

        PROCESSENTRY32W pe32{};
        pe32.dwSize = sizeof(pe32);

        std::vector<DWORD> pids;
        if (Process32FirstW(hSnapshot, &pe32)) {
            do {
                if (Utils::StringUtils::IEquals(pe32.szExeFile, processNameW)) {
                    pids.push_back(pe32.th32ProcessID);
                }
            } while (Process32NextW(hSnapshot, &pe32));
        }

        CloseHandle(hSnapshot);

        if (pids.empty()) {
            return true; // Not running, nothing to close
        }

        bool anyTerminated = false;
        for (DWORD pid : pids) {
            if (Utils::ProcessUtils::TerminateProcess(pid, 0)) {
                anyTerminated = true;
            }
        }

        return anyTerminated;
    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"PrivacyCleaner", L"CloseBrowser exception: %hs", e.what());
        return false;
    }
#else
    return false;
#endif
}

}  // namespace Privacy
}  // namespace ShadowStrike
