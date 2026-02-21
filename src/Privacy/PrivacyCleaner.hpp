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
 * ShadowStrike NGAV - PRIVACY CLEANER MODULE
 * ============================================================================
 *
 * @file PrivacyCleaner.hpp
 * @brief Enterprise-grade privacy cleaner with secure erasure, browser cleanup,
 *        system traces removal, and scheduled cleaning capabilities.
 *
 * Provides comprehensive digital footprint removal including browser data,
 * system traces, application logs, and secure file deletion.
 *
 * CLEANING CAPABILITIES:
 * ======================
 *
 * 1. BROWSER CLEANUP
 *    - Cookies (all/selective)
 *    - Cache (images, CSS, JS)
 *    - Browsing history
 *    - Download history
 *    - Form data / Autofill
 *    - Saved passwords
 *    - Session storage
 *    - Local storage
 *    - IndexedDB
 *    - Service workers
 *
 * 2. SYSTEM CLEANUP
 *    - Recent documents
 *    - Jump lists
 *    - Thumbnail cache
 *    - TEMP folders
 *    - Recycle bin
 *    - Prefetch files
 *    - Windows Search index
 *    - Event logs (optional)
 *    - DNS cache
 *
 * 3. APPLICATION CLEANUP
 *    - Office recent files
 *    - Media player history
 *    - Application logs
 *    - Registry MRU entries
 *    - Crash dumps
 *    - Temp files
 *
 * 4. SECURE ERASURE
 *    - DoD 5220.22-M standard
 *    - Gutmann 35-pass
 *    - Random overwrite
 *    - NIST 800-88
 *    - Single pass (fast)
 *
 * 5. SCHEDULING
 *    - On shutdown
 *    - On browser close
 *    - Scheduled intervals
 *    - On-demand
 *
 * SUPPORTED BROWSERS:
 * ===================
 * - Google Chrome / Chromium
 * - Mozilla Firefox
 * - Microsoft Edge
 * - Opera / Opera GX
 * - Brave Browser
 * - Vivaldi
 * - Internet Explorer (legacy)
 *
 * @note Some operations require elevated privileges.
 * @note Thread-safe singleton design.
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @date 2026
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 *
 * LICENSE: Proprietary - ShadowStrike Enterprise License
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
#include <map>
#include <unordered_map>
#include <unordered_set>
#include <set>
#include <optional>
#include <memory>
#include <functional>
#include <chrono>
#include <atomic>
#include <mutex>
#include <shared_mutex>
#include <filesystem>

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
#endif

// ============================================================================
// SHADOWSTRIKE INFRASTRUCTURE INCLUDES
// ============================================================================

#include "../Utils/Logger.hpp"
#include "../Utils/StringUtils.hpp"
#include "../Utils/FileUtils.hpp"

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

namespace ShadowStrike::Privacy {
    class PrivacyCleanerImpl;
}

namespace ShadowStrike {
namespace Privacy {

// ============================================================================
// COMPILE-TIME CONSTANTS
// ============================================================================

namespace CleanerConstants {

    inline constexpr uint32_t VERSION_MAJOR = 3;
    inline constexpr uint32_t VERSION_MINOR = 0;
    inline constexpr uint32_t VERSION_PATCH = 0;

    /// @brief DoD 5220.22-M passes
    inline constexpr int DOD_PASSES = 3;
    
    /// @brief Gutmann passes
    inline constexpr int GUTMANN_PASSES = 35;
    
    /// @brief Maximum file size for secure erase
    inline constexpr size_t MAX_SECURE_ERASE_SIZE = 10ULL * 1024 * 1024 * 1024;  // 10GB
    
    /// @brief Default temp folder age (hours)
    inline constexpr uint32_t DEFAULT_TEMP_AGE_HOURS = 24;

}  // namespace CleanerConstants

// ============================================================================
// TYPE ALIASES
// ============================================================================

using Clock = std::chrono::steady_clock;
using TimePoint = std::chrono::steady_clock::time_point;
using SystemTimePoint = std::chrono::system_clock::time_point;
namespace fs = std::filesystem;

// ============================================================================
// ENUMERATIONS
// ============================================================================

/**
 * @brief Browser type
 */
enum class BrowserType : uint8_t {
    Unknown         = 0,
    Chrome          = 1,
    Firefox         = 2,
    Edge            = 3,
    Opera           = 4,
    Brave           = 5,
    Vivaldi         = 6,
    IE              = 7,
    Chromium        = 8,
    All             = 255
};

/**
 * @brief Browser data type
 */
enum class BrowserDataType : uint32_t {
    None            = 0,
    Cookies         = 1 << 0,
    Cache           = 1 << 1,
    History         = 1 << 2,
    DownloadHistory = 1 << 3,
    FormData        = 1 << 4,
    Passwords       = 1 << 5,
    SessionStorage  = 1 << 6,
    LocalStorage    = 1 << 7,
    IndexedDB       = 1 << 8,
    ServiceWorkers  = 1 << 9,
    PluginData      = 1 << 10,
    BookmarksExport = 1 << 11,
    Extensions      = 1 << 12,
    All             = 0xFFFFFFFF
};

/**
 * @brief System data type
 */
enum class SystemDataType : uint32_t {
    None            = 0,
    RecentDocuments = 1 << 0,
    JumpLists       = 1 << 1,
    ThumbnailCache  = 1 << 2,
    TempFiles       = 1 << 3,
    RecycleBin      = 1 << 4,
    Prefetch        = 1 << 5,
    WindowsSearch   = 1 << 6,
    EventLogs       = 1 << 7,
    DNSCache        = 1 << 8,
    ClipboardHistory= 1 << 9,
    RunMRU          = 1 << 10,
    TypedURLs       = 1 << 11,
    FontCache       = 1 << 12,
    IconCache       = 1 << 13,
    MemoryDumps     = 1 << 14,
    UpdateCache     = 1 << 15,
    All             = 0xFFFFFFFF
};

/**
 * @brief Secure erase method
 */
enum class SecureEraseMethod : uint8_t {
    SinglePass      = 0,    ///< Single zero pass (fast)
    ThreePass       = 1,    ///< Three random passes
    DoD_5220_22_M   = 2,    ///< DoD 5220.22-M standard
    Gutmann         = 3,    ///< Gutmann 35-pass
    Random          = 4,    ///< Random passes
    NIST_800_88     = 5     ///< NIST 800-88 clear
};

/**
 * @brief Clean operation result
 */
enum class CleanResult : uint8_t {
    Success         = 0,
    PartialSuccess  = 1,
    AccessDenied    = 2,
    FileInUse       = 3,
    NotFound        = 4,
    Error           = 5
};

/**
 * @brief Cleaning scope
 */
enum class CleaningScope : uint8_t {
    CurrentUser     = 0,
    AllUsers        = 1,
    System          = 2,
    Full            = 3
};

/**
 * @brief Schedule type
 */
enum class ScheduleType : uint8_t {
    None            = 0,
    OnShutdown      = 1,
    OnBrowserClose  = 2,
    Daily           = 3,
    Weekly          = 4,
    OnDemand        = 5
};

/**
 * @brief Module status
 */
enum class ModuleStatus : uint8_t {
    Uninitialized   = 0,
    Initializing    = 1,
    Ready           = 2,
    Cleaning        = 3,
    Paused          = 4,
    Stopping        = 5,
    Stopped         = 6,
    Error           = 7
};

// ============================================================================
// STRUCTURES
// ============================================================================

/**
 * @brief Clean target
 */
struct CleanTarget {
    /// @brief Target path
    fs::path path;
    
    /// @brief Is directory
    bool isDirectory = false;
    
    /// @brief Size (bytes)
    uint64_t sizeBytes = 0;
    
    /// @brief File count (if directory)
    uint32_t fileCount = 0;
    
    /// @brief Description
    std::string description;
    
    /// @brief Category
    std::string category;
    
    /// @brief Last modified
    SystemTimePoint lastModified;
    
    /// @brief Requires elevation
    bool requiresElevation = false;
    
    /// @brief Is file in use
    bool isInUse = false;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Clean result details
 */
struct CleanResultDetails {
    /// @brief Overall result
    CleanResult result = CleanResult::Success;
    
    /// @brief Items cleaned
    uint32_t itemsCleaned = 0;
    
    /// @brief Items failed
    uint32_t itemsFailed = 0;
    
    /// @brief Items skipped
    uint32_t itemsSkipped = 0;
    
    /// @brief Bytes cleaned
    uint64_t bytesCleaned = 0;
    
    /// @brief Bytes failed
    uint64_t bytesFailed = 0;
    
    /// @brief Duration
    std::chrono::milliseconds duration{0};
    
    /// @brief Errors encountered
    std::vector<std::string> errors;
    
    /// @brief Files cleaned
    std::vector<fs::path> cleanedFiles;
    
    /// @brief Files failed
    std::vector<fs::path> failedFiles;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Browser profile
 */
struct BrowserProfile {
    /// @brief Profile name
    std::string name;
    
    /// @brief Profile path
    fs::path path;
    
    /// @brief Browser type
    BrowserType browser = BrowserType::Unknown;
    
    /// @brief User
    std::string user;
    
    /// @brief Profile size
    uint64_t sizeBytes = 0;
    
    /// @brief Cookie count
    uint32_t cookieCount = 0;
    
    /// @brief Cache size
    uint64_t cacheSize = 0;
    
    /// @brief History entries
    uint32_t historyCount = 0;
    
    /// @brief Is default profile
    bool isDefault = false;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Scan result
 */
struct CleanScanResult {
    /// @brief Browser targets
    std::vector<CleanTarget> browserTargets;
    
    /// @brief System targets
    std::vector<CleanTarget> systemTargets;
    
    /// @brief Application targets
    std::vector<CleanTarget> applicationTargets;
    
    /// @brief Total size
    uint64_t totalSizeBytes = 0;
    
    /// @brief Total file count
    uint32_t totalFileCount = 0;
    
    /// @brief Scan duration
    std::chrono::milliseconds scanDuration{0};
    
    /// @brief Browser profiles found
    std::vector<BrowserProfile> browserProfiles;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Clean schedule
 */
struct CleanSchedule {
    /// @brief Schedule ID
    std::string scheduleId;
    
    /// @brief Schedule type
    ScheduleType type = ScheduleType::None;
    
    /// @brief Is enabled
    bool enabled = true;
    
    /// @brief Browser data to clean
    BrowserDataType browserData = BrowserDataType::None;
    
    /// @brief System data to clean
    SystemDataType systemData = SystemDataType::None;
    
    /// @brief Browsers to clean
    std::vector<BrowserType> browsers;
    
    /// @brief Secure erase method
    SecureEraseMethod eraseMethod = SecureEraseMethod::SinglePass;
    
    /// @brief Time of day (for daily/weekly)
    int hourOfDay = 2;  // 2 AM default
    
    /// @brief Day of week (for weekly, 0=Sunday)
    int dayOfWeek = 0;
    
    /// @brief Last run
    SystemTimePoint lastRun;
    
    /// @brief Next run
    SystemTimePoint nextRun;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Statistics
 */
struct CleanerStatistics {
    std::atomic<uint64_t> totalCleanOperations{0};
    std::atomic<uint64_t> totalBytesReclaimed{0};
    std::atomic<uint64_t> totalFilesDeleted{0};
    std::atomic<uint64_t> totalSecureErases{0};
    std::atomic<uint64_t> browserCleans{0};
    std::atomic<uint64_t> systemCleans{0};
    std::atomic<uint64_t> scheduledCleans{0};
    std::atomic<uint64_t> failedOperations{0};
    std::atomic<uint64_t> cookiesDeleted{0};
    std::atomic<uint64_t> cacheCleared{0};
    std::atomic<uint64_t> historyCleared{0};
    std::array<std::atomic<uint64_t>, 8> byBrowser{};
    TimePoint startTime = Clock::now();
    
    void Reset() noexcept;
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Configuration
 */
struct CleanerConfiguration {
    /// @brief Enable cleaning
    bool enabled = true;
    
    /// @brief Default erase method
    SecureEraseMethod defaultEraseMethod = SecureEraseMethod::SinglePass;
    
    /// @brief Confirm before clean
    bool confirmBeforeClean = true;
    
    /// @brief Clean scope
    CleaningScope scope = CleaningScope::CurrentUser;
    
    /// @brief Preserve cookies (whitelist)
    std::vector<std::string> preservedCookieDomains;
    
    /// @brief Excluded paths
    std::vector<fs::path> excludedPaths;
    
    /// @brief Temp file age threshold
    std::chrono::hours tempFileAge{24};
    
    /// @brief Close browsers before cleaning
    bool closeBrowsersBeforeClean = false;
    
    /// @brief Schedules
    std::vector<CleanSchedule> schedules;
    
    /// @brief Verbose logging
    bool verboseLogging = false;
    
    [[nodiscard]] bool IsValid() const noexcept;
};

// ============================================================================
// CALLBACK TYPES
// ============================================================================

using ProgressCallback = std::function<void(const std::string& item, int percent)>;
using CompletionCallback = std::function<void(const CleanResultDetails&)>;
using ScanCallback = std::function<void(const CleanScanResult&)>;
using ConfirmCallback = std::function<bool(const std::string& message)>;
using ErrorCallback = std::function<void(const std::string& message, int code)>;

// ============================================================================
// PRIVACY CLEANER CLASS
// ============================================================================

/**
 * @class PrivacyCleaner
 * @brief Enterprise privacy cleaner
 */
class PrivacyCleaner final {
public:
    [[nodiscard]] static PrivacyCleaner& Instance() noexcept;
    [[nodiscard]] static bool HasInstance() noexcept;
    
    PrivacyCleaner(const PrivacyCleaner&) = delete;
    PrivacyCleaner& operator=(const PrivacyCleaner&) = delete;
    PrivacyCleaner(PrivacyCleaner&&) = delete;
    PrivacyCleaner& operator=(PrivacyCleaner&&) = delete;

    // ========================================================================
    // LIFECYCLE
    // ========================================================================
    
    [[nodiscard]] bool Initialize(const CleanerConfiguration& config = {});
    void Shutdown();
    [[nodiscard]] bool IsInitialized() const noexcept;
    [[nodiscard]] ModuleStatus GetStatus() const noexcept;
    
    [[nodiscard]] bool UpdateConfiguration(const CleanerConfiguration& config);
    [[nodiscard]] CleanerConfiguration GetConfiguration() const;

    // ========================================================================
    // SCANNING
    // ========================================================================
    
    /// @brief Scan for cleanable items
    [[nodiscard]] CleanScanResult ScanForCleanableItems();
    
    /// @brief Scan browser data
    [[nodiscard]] std::vector<CleanTarget> ScanBrowserData(
        BrowserType browser = BrowserType::All,
        BrowserDataType dataTypes = BrowserDataType::All);
    
    /// @brief Scan system data
    [[nodiscard]] std::vector<CleanTarget> ScanSystemData(
        SystemDataType dataTypes = SystemDataType::All);
    
    /// @brief Get browser profiles
    [[nodiscard]] std::vector<BrowserProfile> GetBrowserProfiles(
        BrowserType browser = BrowserType::All);

    // ========================================================================
    // CLEANING
    // ========================================================================
    
    /// @brief Clean all (full privacy clean)
    [[nodiscard]] CleanResultDetails CleanAll();
    
    /// @brief Clean browser data
    [[nodiscard]] CleanResultDetails CleanBrowser(
        const std::wstring& browserName);
    
    /// @brief Clean browser data (typed)
    [[nodiscard]] CleanResultDetails CleanBrowser(
        BrowserType browser,
        BrowserDataType dataTypes = BrowserDataType::All);
    
    /// @brief Clean system data
    [[nodiscard]] CleanResultDetails CleanSystem(
        SystemDataType dataTypes = SystemDataType::All);
    
    /// @brief Clean specific targets
    [[nodiscard]] CleanResultDetails CleanTargets(
        const std::vector<CleanTarget>& targets);
    
    /// @brief Clean temp files
    [[nodiscard]] CleanResultDetails CleanTempFiles(
        std::chrono::hours olderThan = std::chrono::hours{24});
    
    /// @brief Empty recycle bin
    [[nodiscard]] CleanResultDetails EmptyRecycleBin();
    
    /// @brief Clear DNS cache
    [[nodiscard]] bool ClearDNSCache();
    
    /// @brief Clear clipboard
    [[nodiscard]] bool ClearClipboard();

    // ========================================================================
    // SECURE ERASURE
    // ========================================================================
    
    /// @brief Secure erase file
    [[nodiscard]] bool SecureEraseFile(
        const fs::path& filePath,
        SecureEraseMethod method = SecureEraseMethod::DoD_5220_22_M);
    
    /// @brief Secure erase directory
    [[nodiscard]] CleanResultDetails SecureEraseDirectory(
        const fs::path& dirPath,
        SecureEraseMethod method = SecureEraseMethod::DoD_5220_22_M);
    
    /// @brief Secure erase free space
    [[nodiscard]] bool SecureEraseFreeSpace(
        const std::wstring& driveLetter,
        SecureEraseMethod method = SecureEraseMethod::SinglePass);

    // ========================================================================
    // SCHEDULING
    // ========================================================================
    
    /// @brief Add schedule
    [[nodiscard]] bool AddSchedule(const CleanSchedule& schedule);
    
    /// @brief Remove schedule
    [[nodiscard]] bool RemoveSchedule(const std::string& scheduleId);
    
    /// @brief Enable/disable schedule
    [[nodiscard]] bool SetScheduleEnabled(
        const std::string& scheduleId,
        bool enabled);
    
    /// @brief Get schedules
    [[nodiscard]] std::vector<CleanSchedule> GetSchedules() const;
    
    /// @brief Run scheduled clean
    [[nodiscard]] CleanResultDetails RunScheduledClean(
        const std::string& scheduleId);

    // ========================================================================
    // COOKIE MANAGEMENT
    // ========================================================================
    
    /// @brief Add preserved domain
    [[nodiscard]] bool AddPreservedDomain(const std::string& domain);
    
    /// @brief Remove preserved domain
    [[nodiscard]] bool RemovePreservedDomain(const std::string& domain);
    
    /// @brief Get preserved domains
    [[nodiscard]] std::vector<std::string> GetPreservedDomains() const;

    // ========================================================================
    // CALLBACKS
    // ========================================================================
    
    void RegisterProgressCallback(ProgressCallback callback);
    void RegisterCompletionCallback(CompletionCallback callback);
    void RegisterScanCallback(ScanCallback callback);
    void RegisterConfirmCallback(ConfirmCallback callback);
    void RegisterErrorCallback(ErrorCallback callback);
    void UnregisterCallbacks();

    // ========================================================================
    // STATISTICS
    // ========================================================================
    
    [[nodiscard]] CleanerStatistics GetStatistics() const;
    void ResetStatistics();
    
    [[nodiscard]] bool SelfTest();
    [[nodiscard]] static std::string GetVersionString() noexcept;

private:
    PrivacyCleaner();
    ~PrivacyCleaner();
    
    std::unique_ptr<PrivacyCleanerImpl> m_impl;
    static std::atomic<bool> s_instanceCreated;
};

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

[[nodiscard]] std::string_view GetBrowserTypeName(BrowserType browser) noexcept;
[[nodiscard]] std::string_view GetEraseMethodName(SecureEraseMethod method) noexcept;
[[nodiscard]] std::string_view GetCleanResultName(CleanResult result) noexcept;
[[nodiscard]] std::string_view GetScheduleTypeName(ScheduleType type) noexcept;

/// @brief Get browser profile paths
[[nodiscard]] std::vector<fs::path> GetBrowserProfilePaths(BrowserType browser);

/// @brief Get browser executable path
[[nodiscard]] fs::path GetBrowserPath(BrowserType browser);

/// @brief Is browser running
[[nodiscard]] bool IsBrowserRunning(BrowserType browser);

/// @brief Close browser
[[nodiscard]] bool CloseBrowser(BrowserType browser);

}  // namespace Privacy
}  // namespace ShadowStrike

// ============================================================================
// MACROS
// ============================================================================

#define SS_CLEAN_ALL() \
    ::ShadowStrike::Privacy::PrivacyCleaner::Instance().CleanAll()

#define SS_CLEAN_BROWSER(browser) \
    ::ShadowStrike::Privacy::PrivacyCleaner::Instance().CleanBrowser(browser)

#define SS_SECURE_ERASE(path) \
    ::ShadowStrike::Privacy::PrivacyCleaner::Instance().SecureEraseFile(path)

#define SS_SCAN_CLEANABLE() \
    ::ShadowStrike::Privacy::PrivacyCleaner::Instance().ScanForCleanableItems()
