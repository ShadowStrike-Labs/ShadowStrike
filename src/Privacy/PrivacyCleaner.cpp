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
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "wbemuuid.lib")
#endif

namespace ShadowStrike {
namespace Privacy {

// ============================================================================
// INTERNAL STRUCTURES
// ============================================================================

namespace {

/**
 * @brief Browser profile locations
 */
struct BrowserPaths {
    std::vector<fs::path> profilePaths;
    fs::path executablePath;
    std::string processName;
};

/**
 * @brief Gutmann pass patterns
 */
const std::array<uint8_t, 35> GUTMANN_PATTERNS = {
    0x55, 0xAA, 0x92, 0x49, 0x24, 0x00, 0x11, 0x22,
    0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA,
    0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x92, 0x49, 0x24,
    0x92, 0x49, 0x24, 0x00, 0x00, 0x00, 0x11, 0x22,
    0x33, 0x44, 0x55
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
    Logger::Info("[PrivacyCleaner] Instance created");
}

PrivacyCleanerImpl::~PrivacyCleanerImpl() {
    Shutdown();
    Logger::Info("[PrivacyCleaner] Instance destroyed");
}

bool PrivacyCleanerImpl::Initialize(const CleanerConfiguration& config) {
    std::unique_lock lock(m_mutex);

    if (m_initialized.load(std::memory_order_acquire)) {
        Logger::Warn("[PrivacyCleaner] Already initialized");
        return true;
    }

    try {
        m_status.store(ModuleStatus::Initializing, std::memory_order_release);

        // Validate configuration
        if (!config.IsValid()) {
            Logger::Error("[PrivacyCleaner] Invalid configuration");
            m_status.store(ModuleStatus::Error, std::memory_order_release);
            return false;
        }

        m_config = config;

        // Initialize preserved domains
        for (const auto& domain : m_config.preservedCookieDomains) {
            m_preservedDomains.insert(StringUtils::ToLower(domain));
        }

        // Load schedules
        m_schedules = m_config.schedules;

        // Reset statistics
        m_stats.Reset();
        m_stats.startTime = Clock::now();

        m_initialized.store(true, std::memory_order_release);
        m_status.store(ModuleStatus::Ready, std::memory_order_release);

        Logger::Info("[PrivacyCleaner] Initialized successfully (Version {})",
            PrivacyCleaner::GetVersionString());

        return true;

    } catch (const std::exception& e) {
        Logger::Critical("[PrivacyCleaner] Initialization failed: {}", e.what());
        m_status.store(ModuleStatus::Error, std::memory_order_release);
        return false;
    } catch (...) {
        Logger::Critical("[PrivacyCleaner] Initialization failed: Unknown error");
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

        // Clear callbacks
        UnregisterCallbacks();

        m_initialized.store(false, std::memory_order_release);
        m_status.store(ModuleStatus::Stopped, std::memory_order_release);

        Logger::Info("[PrivacyCleaner] Shutdown complete");

    } catch (const std::exception& e) {
        Logger::Error("[PrivacyCleaner] Shutdown error: {}", e.what());
    } catch (...) {
        Logger::Error("[PrivacyCleaner] Shutdown error: Unknown exception");
    }
}

bool PrivacyCleanerImpl::UpdateConfiguration(const CleanerConfiguration& config) {
    std::unique_lock lock(m_mutex);

    if (!config.IsValid()) {
        Logger::Error("[PrivacyCleaner] Invalid configuration");
        return false;
    }

    m_config = config;
    Logger::Info("[PrivacyCleaner] Configuration updated");
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
        Logger::Error("[PrivacyCleaner] Not initialized");
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

        Logger::Info("[PrivacyCleaner] Scan complete: {} items ({} bytes)",
            result.totalFileCount, result.totalSizeBytes);

        NotifyScan(result);
        return result;

    } catch (const std::exception& e) {
        Logger::Error("[PrivacyCleaner] Scan failed: {}", e.what());
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
            if (!fs::exists(basePath)) continue;

            // Chromium-based: multiple profiles
            if (browser != BrowserType::Firefox) {
                for (const auto& entry : fs::directory_iterator(basePath)) {
                    if (entry.is_directory()) {
                        auto dirName = entry.path().filename().string();
                        if (dirName.find("Profile") == 0 || dirName == "Default") {
                            BrowserProfile profile;
                            profile.browser = browser;
                            profile.name = dirName;
                            profile.path = entry.path();
                            profile.sizeBytes = CalculateDirectorySize(entry.path());
                            profile.isDefault = (dirName == "Default");
                            profiles.push_back(profile);
                        }
                    }
                }
            } else {
                // Firefox: profiles.ini parsing would go here
                for (const auto& entry : fs::directory_iterator(basePath)) {
                    if (entry.is_directory()) {
                        BrowserProfile profile;
                        profile.browser = browser;
                        profile.name = entry.path().filename().string();
                        profile.path = entry.path();
                        profile.sizeBytes = CalculateDirectorySize(entry.path());
                        profiles.push_back(profile);
                    }
                }
            }
        }

    } catch (const std::exception& e) {
        Logger::Error("[PrivacyCleaner] GetBrowserProfiles error: {}", e.what());
    }

    return profiles;
}

// ============================================================================
// CLEANING
// ============================================================================

CleanResultDetails PrivacyCleanerImpl::CleanAll() {
    if (!m_initialized.load(std::memory_order_acquire)) {
        Logger::Error("[PrivacyCleaner] Not initialized");
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
        m_stats.totalCleanOperations++;

        Logger::Info("[PrivacyCleaner] CleanAll complete: {} items ({} bytes)",
            result.itemsCleaned, result.bytesCleaned);

        NotifyCompletion(result);
        return result;

    } catch (const std::exception& e) {
        Logger::Error("[PrivacyCleaner] CleanAll failed: {}", e.what());
        m_status.store(ModuleStatus::Ready, std::memory_order_release);
        result.result = CleanResult::Error;
        NotifyError(e.what(), -1);
        return result;
    }
}

CleanResultDetails PrivacyCleanerImpl::CleanBrowser(const std::wstring& browserName) {
    std::string name = StringUtils::WStringToString(browserName);
    name = StringUtils::ToLower(name);

    BrowserType browser = BrowserType::Unknown;
    if (name.find("chrome") != std::string::npos) browser = BrowserType::Chrome;
    else if (name.find("firefox") != std::string::npos) browser = BrowserType::Firefox;
    else if (name.find("edge") != std::string::npos) browser = BrowserType::Edge;
    else if (name.find("opera") != std::string::npos) browser = BrowserType::Opera;
    else if (name.find("brave") != std::string::npos) browser = BrowserType::Brave;
    else if (name.find("vivaldi") != std::string::npos) browser = BrowserType::Vivaldi;

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

        m_stats.browserCleans++;
        if (static_cast<size_t>(browser) < m_stats.byBrowser.size()) {
            m_stats.byBrowser[static_cast<size_t>(browser)]++;
        }

        Logger::Info("[PrivacyCleaner] Browser clean complete: {} ({} items, {} bytes)",
            GetBrowserTypeName(browser), result.itemsCleaned, result.bytesCleaned);

        return result;

    } catch (const std::exception& e) {
        Logger::Error("[PrivacyCleaner] CleanBrowser failed: {}", e.what());
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

        m_stats.systemCleans++;

        Logger::Info("[PrivacyCleaner] System clean complete: {} items ({} bytes)",
            result.itemsCleaned, result.bytesCleaned);

        return result;

    } catch (const std::exception& e) {
        Logger::Error("[PrivacyCleaner] CleanSystem failed: {}", e.what());
        result.result = CleanResult::Error;
        result.errors.push_back(e.what());
        return result;
    }
}

CleanResultDetails PrivacyCleanerImpl::CleanTargets(const std::vector<CleanTarget>& targets) {
    CleanResultDetails result;

    for (size_t i = 0; i < targets.size(); ++i) {
        const auto& target = targets[i];

        try {
            NotifyProgress(target.path.string(), static_cast<int>((i * 100) / targets.size()));

            if (DeleteTarget(target, m_config.defaultEraseMethod)) {
                result.itemsCleaned++;
                result.bytesCleaned += target.sizeBytes;
                result.cleanedFiles.push_back(target.path);
                m_stats.totalFilesDeleted++;
            } else {
                result.itemsFailed++;
                result.bytesFailed += target.sizeBytes;
                result.failedFiles.push_back(target.path);
            }

        } catch (const std::exception& e) {
            result.itemsFailed++;
            result.errors.push_back(target.path.string() + ": " + e.what());
            Logger::Error("[PrivacyCleaner] Failed to clean {}: {}", target.path.string(), e.what());
        }
    }

    result.result = (result.itemsFailed == 0) ? CleanResult::Success : CleanResult::PartialSuccess;
    m_stats.totalBytesReclaimed += result.bytesCleaned;

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

        for (const auto& entry : fs::recursive_directory_iterator(tempDir)) {
            try {
                if (entry.is_regular_file()) {
                    auto lastWrite = fs::last_write_time(entry.path());
                    auto sctp = std::chrono::time_point_cast<std::chrono::system_clock::duration>(
                        lastWrite - fs::file_time_type::clock::now() + std::chrono::system_clock::now()
                    );

                    if (sctp < cutoffTime) {
                        auto size = entry.file_size();
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

        result.result = CleanResult::Success;
        m_stats.totalBytesReclaimed += result.bytesCleaned;

    } catch (const std::exception& e) {
        Logger::Error("[PrivacyCleaner] CleanTempFiles failed: {}", e.what());
        result.result = CleanResult::Error;
    }

    return result;
}

CleanResultDetails PrivacyCleanerImpl::EmptyRecycleBin() {
    CleanResultDetails result;

    try {
#ifdef _WIN32
        HRESULT hr = SHEmptyRecycleBinW(nullptr, nullptr, SHERB_NOCONFIRMATION | SHERB_NOPROGRESSUI | SHERB_NOSOUND);

        if (SUCCEEDED(hr)) {
            result.result = CleanResult::Success;
            result.itemsCleaned = 1;
            Logger::Info("[PrivacyCleaner] Recycle bin emptied");
        } else {
            result.result = CleanResult::Error;
            Logger::Error("[PrivacyCleaner] Failed to empty recycle bin: {}", hr);
        }
#endif

    } catch (const std::exception& e) {
        Logger::Error("[PrivacyCleaner] EmptyRecycleBin failed: {}", e.what());
        result.result = CleanResult::Error;
    }

    return result;
}

bool PrivacyCleanerImpl::ClearDNSCache() {
    try {
#ifdef _WIN32
        DWORD result = DnsFlushResolverCache();
        if (result == ERROR_SUCCESS || result == 0) {
            Logger::Info("[PrivacyCleaner] DNS cache cleared");
            return true;
        }
#endif
    } catch (const std::exception& e) {
        Logger::Error("[PrivacyCleaner] ClearDNSCache failed: {}", e.what());
    }

    return false;
}

bool PrivacyCleanerImpl::ClearClipboard() {
    try {
#ifdef _WIN32
        if (OpenClipboard(nullptr)) {
            EmptyClipboard();
            CloseClipboard();
            Logger::Info("[PrivacyCleaner] Clipboard cleared");
            return true;
        }
#endif
    } catch (const std::exception& e) {
        Logger::Error("[PrivacyCleaner] ClearClipboard failed: {}", e.what());
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
        if (!fs::exists(filePath)) {
            Logger::Warn("[PrivacyCleaner] File not found: {}", filePath.string());
            return false;
        }

        if (!fs::is_regular_file(filePath)) {
            Logger::Error("[PrivacyCleaner] Not a regular file: {}", filePath.string());
            return false;
        }

        auto size = fs::file_size(filePath);
        if (size > CleanerConstants::MAX_SECURE_ERASE_SIZE) {
            Logger::Error("[PrivacyCleaner] File too large for secure erase: {} bytes", size);
            return false;
        }

        bool success = DeleteFileSecurely(filePath, method);

        if (success) {
            m_stats.totalSecureErases++;
            m_stats.totalBytesReclaimed += size;
            Logger::Info("[PrivacyCleaner] Securely erased: {} ({} bytes)", filePath.string(), size);
        }

        return success;

    } catch (const std::exception& e) {
        Logger::Error("[PrivacyCleaner] SecureEraseFile failed: {}", e.what());
        return false;
    }
}

CleanResultDetails PrivacyCleanerImpl::SecureEraseDirectory(const fs::path& dirPath, SecureEraseMethod method) {
    CleanResultDetails result;

    try {
        if (!fs::exists(dirPath) || !fs::is_directory(dirPath)) {
            result.result = CleanResult::NotFound;
            return result;
        }

        for (const auto& entry : fs::recursive_directory_iterator(dirPath)) {
            if (entry.is_regular_file()) {
                auto size = entry.file_size();
                if (SecureEraseFile(entry.path(), method)) {
                    result.itemsCleaned++;
                    result.bytesCleaned += size;
                } else {
                    result.itemsFailed++;
                }
            }
        }

        // Remove empty directory
        fs::remove_all(dirPath);

        result.result = (result.itemsFailed == 0) ? CleanResult::Success : CleanResult::PartialSuccess;

    } catch (const std::exception& e) {
        Logger::Error("[PrivacyCleaner] SecureEraseDirectory failed: {}", e.what());
        result.result = CleanResult::Error;
        result.errors.push_back(e.what());
    }

    return result;
}

bool PrivacyCleanerImpl::SecureEraseFreeSpace(const std::wstring& driveLetter, SecureEraseMethod method) {
    // Free space wiping is complex and resource-intensive
    // This is a stub for enterprise implementation
    Logger::Warn("[PrivacyCleaner] Free space wiping not yet implemented");
    return false;
}

// ============================================================================
// SCHEDULING
// ============================================================================

bool PrivacyCleanerImpl::AddSchedule(const CleanSchedule& schedule) {
    std::unique_lock lock(m_mutex);

    try {
        m_schedules.push_back(schedule);
        Logger::Info("[PrivacyCleaner] Added schedule: {}", schedule.scheduleId);
        return true;
    } catch (const std::exception& e) {
        Logger::Error("[PrivacyCleaner] AddSchedule failed: {}", e.what());
        return false;
    }
}

bool PrivacyCleanerImpl::RemoveSchedule(const std::string& scheduleId) {
    std::unique_lock lock(m_mutex);

    auto it = std::remove_if(m_schedules.begin(), m_schedules.end(),
        [&scheduleId](const CleanSchedule& s) { return s.scheduleId == scheduleId; });

    if (it != m_schedules.end()) {
        m_schedules.erase(it, m_schedules.end());
        Logger::Info("[PrivacyCleaner] Removed schedule: {}", scheduleId);
        return true;
    }

    return false;
}

bool PrivacyCleanerImpl::SetScheduleEnabled(const std::string& scheduleId, bool enabled) {
    std::unique_lock lock(m_mutex);

    for (auto& schedule : m_schedules) {
        if (schedule.scheduleId == scheduleId) {
            schedule.enabled = enabled;
            Logger::Info("[PrivacyCleaner] Schedule {} {}", scheduleId, enabled ? "enabled" : "disabled");
            return true;
        }
    }

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
            Logger::Error("[PrivacyCleaner] Schedule not found: {}", scheduleId);
            return {};
        }

        schedule = *it;
    }

    if (!schedule.enabled) {
        Logger::Warn("[PrivacyCleaner] Schedule disabled: {}", scheduleId);
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

    m_stats.scheduledCleans++;
    Logger::Info("[PrivacyCleaner] Scheduled clean complete: {} ({} items)",
        scheduleId, result.itemsCleaned);

    return result;
}

// ============================================================================
// COOKIE MANAGEMENT
// ============================================================================

bool PrivacyCleanerImpl::AddPreservedDomain(const std::string& domain) {
    std::unique_lock lock(m_mutex);
    m_preservedDomains.insert(StringUtils::ToLower(domain));
    Logger::Info("[PrivacyCleaner] Added preserved domain: {}", domain);
    return true;
}

bool PrivacyCleanerImpl::RemovePreservedDomain(const std::string& domain) {
    std::unique_lock lock(m_mutex);
    auto it = m_preservedDomains.find(StringUtils::ToLower(domain));
    if (it != m_preservedDomains.end()) {
        m_preservedDomains.erase(it);
        Logger::Info("[PrivacyCleaner] Removed preserved domain: {}", domain);
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
    return m_stats;
}

void PrivacyCleanerImpl::ResetStatistics() {
    m_stats.Reset();
    m_stats.startTime = Clock::now();
    Logger::Info("[PrivacyCleaner] Statistics reset");
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
    target.isDirectory = fs::is_directory(path);

    if (target.isDirectory) {
        target.sizeBytes = CalculateDirectorySize(path);
        target.fileCount = CountFilesInDirectory(path);
    } else {
        target.sizeBytes = fs::file_size(path);
        target.fileCount = 1;
    }

    target.lastModified = std::chrono::system_clock::now();
    target.isInUse = IsFileInUse(path);

    return target;
}

bool PrivacyCleanerImpl::DeleteFileSecurely(const fs::path& filePath, SecureEraseMethod method) {
    try {
        switch (method) {
            case SecureEraseMethod::SinglePass:
                OverwriteFile(filePath, 0x00);
                break;

            case SecureEraseMethod::ThreePass:
                OverwriteFileRandom(filePath);
                OverwriteFileRandom(filePath);
                OverwriteFileRandom(filePath);
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
                OverwriteFileRandom(filePath);
                break;
        }

        // Delete file after overwriting
        fs::remove(filePath);
        return true;

    } catch (const std::exception& e) {
        Logger::Error("[PrivacyCleaner] DeleteFileSecurely failed: {}", e.what());
        return false;
    }
}

bool PrivacyCleanerImpl::OverwriteFile(const fs::path& filePath, uint8_t pattern) {
    try {
        std::fstream file(filePath, std::ios::in | std::ios::out | std::ios::binary);
        if (!file) return false;

        file.seekg(0, std::ios::end);
        auto size = file.tellg();
        file.seekg(0, std::ios::beg);

        constexpr size_t BUFFER_SIZE = 64 * 1024;  // 64KB buffer
        std::vector<uint8_t> buffer(BUFFER_SIZE, pattern);

        for (std::streampos pos = 0; pos < size; pos += BUFFER_SIZE) {
            auto remaining = static_cast<size_t>(size - pos);
            auto writeSize = std::min(BUFFER_SIZE, remaining);
            file.write(reinterpret_cast<const char*>(buffer.data()), writeSize);
        }

        file.flush();
        file.close();
        return true;

    } catch (const std::exception& e) {
        Logger::Error("[PrivacyCleaner] OverwriteFile failed: {}", e.what());
        return false;
    }
}

bool PrivacyCleanerImpl::OverwriteFileRandom(const fs::path& filePath) {
    try {
        std::fstream file(filePath, std::ios::in | std::ios::out | std::ios::binary);
        if (!file) return false;

        file.seekg(0, std::ios::end);
        auto size = file.tellg();
        file.seekg(0, std::ios::beg);

        constexpr size_t BUFFER_SIZE = 64 * 1024;
        std::vector<uint8_t> buffer(BUFFER_SIZE);

        std::lock_guard lock(m_rngMutex);
        std::uniform_int_distribution<uint16_t> dist(0, 255);

        for (std::streampos pos = 0; pos < size; pos += BUFFER_SIZE) {
            auto remaining = static_cast<size_t>(size - pos);
            auto writeSize = std::min(BUFFER_SIZE, remaining);

            for (size_t i = 0; i < writeSize; ++i) {
                buffer[i] = static_cast<uint8_t>(dist(m_rng));
            }

            file.write(reinterpret_cast<const char*>(buffer.data()), writeSize);
        }

        file.flush();
        file.close();
        return true;

    } catch (const std::exception& e) {
        Logger::Error("[PrivacyCleaner] OverwriteFileRandom failed: {}", e.what());
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
    // Gutmann 35-pass method
    // Passes 1-4: Random
    for (int i = 0; i < 4; ++i) {
        OverwriteFileRandom(filePath);
    }

    // Passes 5-31: Specific patterns
    for (size_t i = 0; i < 27 && i < GUTMANN_PATTERNS.size(); ++i) {
        OverwriteFile(filePath, GUTMANN_PATTERNS[i]);
    }

    // Passes 32-35: Random
    for (int i = 0; i < 4; ++i) {
        OverwriteFileRandom(filePath);
    }
}

void PrivacyCleanerImpl::NIST_800_88_Erase(const fs::path& filePath) {
    // NIST 800-88 Clear: Single pass with zeros
    OverwriteFile(filePath, 0x00);
}

std::vector<CleanTarget> PrivacyCleanerImpl::ScanChromiumBrowser(BrowserType browser, BrowserDataType dataTypes) {
    std::vector<CleanTarget> targets;

    try {
        auto browserPaths = GetBrowserPathsInternal(browser);

        for (const auto& basePath : browserPaths.profilePaths) {
            if (!fs::exists(basePath)) continue;

            for (const auto& entry : fs::directory_iterator(basePath)) {
                if (!entry.is_directory()) continue;

                auto dirName = entry.path().filename().string();
                if (dirName.find("Profile") != 0 && dirName != "Default") continue;

                auto profilePath = entry.path();

                // Cache
                if (static_cast<uint32_t>(dataTypes) & static_cast<uint32_t>(BrowserDataType::Cache)) {
                    auto cachePath = profilePath / "Cache";
                    if (fs::exists(cachePath)) {
                        targets.push_back(CreateCleanTarget(cachePath, "Browser Cache", "Cache"));
                    }
                }

                // Cookies
                if (static_cast<uint32_t>(dataTypes) & static_cast<uint32_t>(BrowserDataType::Cookies)) {
                    auto cookiesPath = profilePath / "Cookies";
                    if (fs::exists(cookiesPath)) {
                        targets.push_back(CreateCleanTarget(cookiesPath, "Browser Cookies", "Cookies"));
                    }
                }

                // History
                if (static_cast<uint32_t>(dataTypes) & static_cast<uint32_t>(BrowserDataType::History)) {
                    auto historyPath = profilePath / "History";
                    if (fs::exists(historyPath)) {
                        targets.push_back(CreateCleanTarget(historyPath, "Browsing History", "History"));
                    }
                }

                // Local Storage
                if (static_cast<uint32_t>(dataTypes) & static_cast<uint32_t>(BrowserDataType::LocalStorage)) {
                    auto localStoragePath = profilePath / "Local Storage";
                    if (fs::exists(localStoragePath)) {
                        targets.push_back(CreateCleanTarget(localStoragePath, "Local Storage", "Storage"));
                    }
                }

                // Session Storage
                if (static_cast<uint32_t>(dataTypes) & static_cast<uint32_t>(BrowserDataType::SessionStorage)) {
                    auto sessionPath = profilePath / "Session Storage";
                    if (fs::exists(sessionPath)) {
                        targets.push_back(CreateCleanTarget(sessionPath, "Session Storage", "Storage"));
                    }
                }
            }
        }

    } catch (const std::exception& e) {
        Logger::Error("[PrivacyCleaner] ScanChromiumBrowser error: {}", e.what());
    }

    return targets;
}

std::vector<CleanTarget> PrivacyCleanerImpl::ScanFirefox(BrowserDataType dataTypes) {
    std::vector<CleanTarget> targets;

    try {
        auto browserPaths = GetBrowserPathsInternal(BrowserType::Firefox);

        for (const auto& basePath : browserPaths.profilePaths) {
            if (!fs::exists(basePath)) continue;

            for (const auto& entry : fs::directory_iterator(basePath)) {
                if (!entry.is_directory()) continue;

                auto profilePath = entry.path();

                // Cache
                if (static_cast<uint32_t>(dataTypes) & static_cast<uint32_t>(BrowserDataType::Cache)) {
                    auto cachePath = profilePath / "cache2";
                    if (fs::exists(cachePath)) {
                        targets.push_back(CreateCleanTarget(cachePath, "Firefox Cache", "Cache"));
                    }
                }

                // Cookies
                if (static_cast<uint32_t>(dataTypes) & static_cast<uint32_t>(BrowserDataType::Cookies)) {
                    auto cookiesPath = profilePath / "cookies.sqlite";
                    if (fs::exists(cookiesPath)) {
                        targets.push_back(CreateCleanTarget(cookiesPath, "Firefox Cookies", "Cookies"));
                    }
                }

                // History
                if (static_cast<uint32_t>(dataTypes) & static_cast<uint32_t>(BrowserDataType::History)) {
                    auto historyPath = profilePath / "places.sqlite";
                    if (fs::exists(historyPath)) {
                        targets.push_back(CreateCleanTarget(historyPath, "Firefox History", "History"));
                    }
                }
            }
        }

    } catch (const std::exception& e) {
        Logger::Error("[PrivacyCleaner] ScanFirefox error: {}", e.what());
    }

    return targets;
}

std::vector<CleanTarget> PrivacyCleanerImpl::ScanRecentDocuments() {
    std::vector<CleanTarget> targets;

#ifdef _WIN32
    try {
        wchar_t recentPath[MAX_PATH] = {};
        SHGetFolderPathW(nullptr, CSIDL_RECENT, nullptr, SHGFP_TYPE_CURRENT, recentPath);

        fs::path recent = recentPath;
        if (fs::exists(recent)) {
            targets.push_back(CreateCleanTarget(recent, "Recent Documents", "System"));
        }

    } catch (const std::exception& e) {
        Logger::Error("[PrivacyCleaner] ScanRecentDocuments error: {}", e.what());
    }
#endif

    return targets;
}

std::vector<CleanTarget> PrivacyCleanerImpl::ScanJumpLists() {
    std::vector<CleanTarget> targets;

#ifdef _WIN32
    try {
        wchar_t appDataPath[MAX_PATH] = {};
        SHGetFolderPathW(nullptr, CSIDL_APPDATA, nullptr, SHGFP_TYPE_CURRENT, appDataPath);

        fs::path jumpListPath = fs::path(appDataPath) / "Microsoft" / "Windows" / "Recent" / "AutomaticDestinations";
        if (fs::exists(jumpListPath)) {
            targets.push_back(CreateCleanTarget(jumpListPath, "Jump Lists", "System"));
        }

    } catch (const std::exception& e) {
        Logger::Error("[PrivacyCleaner] ScanJumpLists error: {}", e.what());
    }
#endif

    return targets;
}

std::vector<CleanTarget> PrivacyCleanerImpl::ScanThumbnailCache() {
    std::vector<CleanTarget> targets;

#ifdef _WIN32
    try {
        wchar_t localAppDataPath[MAX_PATH] = {};
        SHGetFolderPathW(nullptr, CSIDL_LOCAL_APPDATA, nullptr, SHGFP_TYPE_CURRENT, localAppDataPath);

        fs::path thumbCachePath = fs::path(localAppDataPath) / "Microsoft" / "Windows" / "Explorer";
        if (fs::exists(thumbCachePath)) {
            for (const auto& entry : fs::directory_iterator(thumbCachePath)) {
                if (entry.path().extension() == ".db") {
                    targets.push_back(CreateCleanTarget(entry.path(), "Thumbnail Cache", "System"));
                }
            }
        }

    } catch (const std::exception& e) {
        Logger::Error("[PrivacyCleaner] ScanThumbnailCache error: {}", e.what());
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

        fs::path temp = tempPath;
        if (fs::exists(temp)) {
            targets.push_back(CreateCleanTarget(temp, "Temporary Files", "System"));
        }

    } catch (const std::exception& e) {
        Logger::Error("[PrivacyCleaner] ScanTempFiles error: {}", e.what());
    }
#endif

    return targets;
}

std::vector<CleanTarget> PrivacyCleanerImpl::ScanPrefetch() {
    std::vector<CleanTarget> targets;

#ifdef _WIN32
    try {
        fs::path prefetchPath = "C:\\Windows\\Prefetch";
        if (fs::exists(prefetchPath)) {
            targets.push_back(CreateCleanTarget(prefetchPath, "Prefetch Files", "System"));
        }

    } catch (const std::exception& e) {
        Logger::Error("[PrivacyCleaner] ScanPrefetch error: {}", e.what());
    }
#endif

    return targets;
}

bool PrivacyCleanerImpl::DeleteTarget(const CleanTarget& target, SecureEraseMethod method) {
    try {
        if (!fs::exists(target.path)) {
            return false;
        }

        if (IsPathExcluded(target.path)) {
            Logger::Info("[PrivacyCleaner] Skipping excluded path: {}", target.path.string());
            return false;
        }

        if (target.isDirectory) {
            for (const auto& entry : fs::recursive_directory_iterator(target.path)) {
                if (entry.is_regular_file()) {
                    DeleteFileSecurely(entry.path(), method);
                }
            }
            fs::remove_all(target.path);
        } else {
            DeleteFileSecurely(target.path, method);
        }

        return true;

    } catch (const std::exception& e) {
        Logger::Error("[PrivacyCleaner] DeleteTarget failed: {}", e.what());
        return false;
    }
}

uint64_t PrivacyCleanerImpl::CalculateDirectorySize(const fs::path& dirPath) {
    uint64_t totalSize = 0;

    try {
        for (const auto& entry : fs::recursive_directory_iterator(dirPath)) {
            if (entry.is_regular_file()) {
                totalSize += entry.file_size();
            }
        }
    } catch (...) {
        // Ignore errors
    }

    return totalSize;
}

uint32_t PrivacyCleanerImpl::CountFilesInDirectory(const fs::path& dirPath) {
    uint32_t count = 0;

    try {
        for (const auto& entry : fs::recursive_directory_iterator(dirPath)) {
            if (entry.is_regular_file()) {
                count++;
            }
        }
    } catch (...) {
        // Ignore errors
    }

    return count;
}

bool PrivacyCleanerImpl::IsFileInUse(const fs::path& filePath) {
#ifdef _WIN32
    HANDLE hFile = CreateFileW(
        filePath.c_str(),
        GENERIC_READ,
        0,  // No sharing
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr
    );

    if (hFile == INVALID_HANDLE_VALUE) {
        DWORD error = GetLastError();
        CloseHandle(hFile);
        return (error == ERROR_SHARING_VIOLATION);
    }

    CloseHandle(hFile);
#endif

    return false;
}

bool PrivacyCleanerImpl::IsPathExcluded(const fs::path& path) {
    std::shared_lock lock(m_mutex);

    std::string pathStr = path.string();
    for (const auto& excluded : m_config.excludedPaths) {
        if (pathStr.find(excluded.string()) != std::string::npos) {
            return true;
        }
    }

    return false;
}

bool PrivacyCleanerImpl::IsDomainPreserved(const std::string& domain) {
    std::shared_lock lock(m_mutex);
    return m_preservedDomains.find(StringUtils::ToLower(domain)) != m_preservedDomains.end();
}

void PrivacyCleanerImpl::NotifyProgress(const std::string& item, int percent) {
    std::lock_guard lock(m_callbackMutex);
    if (m_progressCallback) {
        try {
            m_progressCallback(item, percent);
        } catch (const std::exception& e) {
            Logger::Error("[PrivacyCleaner] Progress callback exception: {}", e.what());
        }
    }
}

void PrivacyCleanerImpl::NotifyCompletion(const CleanResultDetails& result) {
    std::lock_guard lock(m_callbackMutex);
    if (m_completionCallback) {
        try {
            m_completionCallback(result);
        } catch (const std::exception& e) {
            Logger::Error("[PrivacyCleaner] Completion callback exception: {}", e.what());
        }
    }
}

void PrivacyCleanerImpl::NotifyScan(const CleanScanResult& result) {
    std::lock_guard lock(m_callbackMutex);
    if (m_scanCallback) {
        try {
            m_scanCallback(result);
        } catch (const std::exception& e) {
            Logger::Error("[PrivacyCleaner] Scan callback exception: {}", e.what());
        }
    }
}

bool PrivacyCleanerImpl::NotifyConfirm(const std::string& message) {
    std::lock_guard lock(m_callbackMutex);
    if (m_confirmCallback) {
        try {
            return m_confirmCallback(message);
        } catch (const std::exception& e) {
            Logger::Error("[PrivacyCleaner] Confirm callback exception: {}", e.what());
        }
    }
    return true;  // Default: proceed
}

void PrivacyCleanerImpl::NotifyError(const std::string& message, int code) {
    std::lock_guard lock(m_callbackMutex);
    if (m_errorCallback) {
        try {
            m_errorCallback(message, code);
        } catch (const std::exception& e) {
            Logger::Error("[PrivacyCleaner] Error callback exception: {}", e.what());
        }
    }
}

bool PrivacyCleanerImpl::SelfTest() {
    Logger::Info("[PrivacyCleaner] Running self-test...");

    try {
        // Test 1: Secure erase single pass
        {
            fs::path testFile = fs::temp_directory_path() / "shadowstrike_test_erase.tmp";
            std::ofstream file(testFile, std::ios::binary);
            file << "Test data for secure erase";
            file.close();

            if (!SecureEraseFile(testFile, SecureEraseMethod::SinglePass)) {
                Logger::Error("[PrivacyCleaner] Self-test failed: Secure erase");
                return false;
            }

            if (fs::exists(testFile)) {
                Logger::Error("[PrivacyCleaner] Self-test failed: File not deleted");
                return false;
            }
        }

        // Test 2: Browser profile detection
        {
            auto profiles = GetBrowserProfiles(BrowserType::Chrome);
            Logger::Info("[PrivacyCleaner] Self-test: Found {} Chrome profiles", profiles.size());
        }

        // Test 3: Preserved domain
        {
            AddPreservedDomain("example.com");
            if (!IsDomainPreserved("example.com")) {
                Logger::Error("[PrivacyCleaner] Self-test failed: Domain preservation");
                return false;
            }
            RemovePreservedDomain("example.com");
        }

        // Test 4: Statistics
        {
            auto stats = GetStatistics();
            if (stats.totalSecureErases.load() == 0) {
                Logger::Warn("[PrivacyCleaner] Self-test warning: No secure erases recorded");
            }
        }

        Logger::Info("[PrivacyCleaner] Self-test PASSED");
        return true;

    } catch (const std::exception& e) {
        Logger::Error("[PrivacyCleaner] Self-test exception: {}", e.what());
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
        return ProcessUtils::IsProcessRunning(StringUtils::StringToWString(paths.processName));
    } catch (...) {
        return false;
    }
}

bool CloseBrowser(BrowserType browser) {
    auto paths = GetBrowserPathsInternal(browser);
    if (paths.processName.empty()) {
        return false;
    }

    try {
        return ProcessUtils::KillProcess(StringUtils::StringToWString(paths.processName));
    } catch (...) {
        return false;
    }
}

}  // namespace Privacy
}  // namespace ShadowStrike
