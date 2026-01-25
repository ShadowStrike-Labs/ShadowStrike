/**
 * ============================================================================
 * ShadowStrike NGAV - UPDATE MANAGER MODULE
 * ============================================================================
 *
 * @file UpdateManager.hpp
 * @brief Enterprise-grade update orchestration with multi-channel delivery,
 *        staged rollouts, integrity verification, and automatic rollback.
 *
 * Provides comprehensive update management for signatures, program binaries,
 * and configuration data with enterprise deployment features.
 *
 * UPDATE CAPABILITIES:
 * ====================
 *
 * 1. UPDATE TYPES
 *    - Signature updates
 *    - Program updates
 *    - Driver updates
 *    - Configuration updates
 *    - Emergency patches
 *    - Critical hotfixes
 *
 * 2. DELIVERY METHODS
 *    - Direct download
 *    - CDN distribution
 *    - P2P distribution
 *    - Offline packages
 *    - Enterprise console push
 *
 * 3. STAGED ROLLOUTS
 *    - Canary releases
 *    - Percentage rollouts
 *    - Ring-based deployment
 *    - Geographic targeting
 *    - Customer segmentation
 *
 * 4. VERIFICATION
 *    - Code signing (RSA-4096)
 *    - Certificate chain validation
 *    - Checksum verification
 *    - Anti-downgrade protection
 *    - Tamper detection
 *
 * 5. RECOVERY
 *    - Automatic rollback
 *    - Boot loop detection
 *    - Health validation
 *    - Last known good state
 *
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
#include <set>
#include <optional>
#include <memory>
#include <functional>
#include <chrono>
#include <atomic>
#include <mutex>
#include <shared_mutex>
#include <future>
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
#include "../Utils/NetworkUtils.hpp"
#include "../Utils/CryptoUtils.hpp"
#include "SignatureUpdater.hpp"
#include "ProgramUpdater.hpp"

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

namespace ShadowStrike::Update {
    class UpdateManagerImpl;
}

namespace ShadowStrike {
namespace Update {

// ============================================================================
// COMPILE-TIME CONSTANTS
// ============================================================================

namespace UpdateConstants {

    inline constexpr uint32_t VERSION_MAJOR = 3;
    inline constexpr uint32_t VERSION_MINOR = 0;
    inline constexpr uint32_t VERSION_PATCH = 0;

    /// @brief Update server URL
    inline constexpr const char* UPDATE_SERVER_URL = "https://update.shadowstrike.io/v3";
    
    /// @brief Default check interval (hours)
    inline constexpr uint32_t DEFAULT_CHECK_INTERVAL_HOURS = 1;
    
    /// @brief Download timeout (seconds)
    inline constexpr uint32_t DOWNLOAD_TIMEOUT_SECONDS = 600;
    
    /// @brief Maximum retry attempts
    inline constexpr uint32_t MAX_RETRY_ATTEMPTS = 3;
    
    /// @brief Update staging directory
    inline constexpr const wchar_t* STAGING_DIRECTORY = L"Update\\Staging";

}  // namespace UpdateConstants

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
 * @brief Update status
 */
enum class UpdateStatus : uint8_t {
    Idle            = 0,
    Checking        = 1,
    Available       = 2,
    Downloading     = 3,
    Verifying       = 4,
    Staging         = 5,
    Applying        = 6,
    RebootRequired  = 7,
    Completed       = 8,
    RollingBack     = 9,
    Failed          = 10,
    Error           = 11
};

/**
 * @brief Update type
 */
enum class UpdateType : uint8_t {
    Signature       = 0,    ///< Malware signatures
    Program         = 1,    ///< Main program
    Driver          = 2,    ///< Kernel driver
    Configuration   = 3,    ///< Configuration
    Engine          = 4,    ///< Scan engine
    Heuristics      = 5,    ///< Heuristic rules
    Whitelist       = 6,    ///< Whitelist data
    Patterns        = 7,    ///< Pattern database
    Emergency       = 8     ///< Emergency patch
};

/**
 * @brief Update priority
 */
enum class UpdatePriority : uint8_t {
    Low             = 0,    ///< Optional
    Normal          = 1,    ///< Standard
    High            = 2,    ///< Important
    Critical        = 3,    ///< Security critical
    Emergency       = 4     ///< Zero-day response
};

/**
 * @brief Update channel
 */
enum class UpdateChannel : uint8_t {
    Stable          = 0,    ///< Production
    Beta            = 1,    ///< Beta testing
    Canary          = 2,    ///< Early adopters
    Developer       = 3,    ///< Internal testing
    Enterprise      = 4     ///< Enterprise managed
};

/**
 * @brief Download state
 */
enum class DownloadState : uint8_t {
    NotStarted      = 0,
    Connecting      = 1,
    Downloading     = 2,
    Paused          = 3,
    Completed       = 4,
    Failed          = 5,
    Cancelled       = 6
};

/**
 * @brief Module status
 */
enum class UpdateModuleStatus : uint8_t {
    Uninitialized   = 0,
    Initializing    = 1,
    Running         = 2,
    Updating        = 3,
    Paused          = 4,
    Stopping        = 5,
    Stopped         = 6,
    Error           = 7
};

// ============================================================================
// STRUCTURES
// ============================================================================

/**
 * @brief Version info
 */
struct VersionInfo {
    /// @brief Major version
    uint16_t major = 0;
    
    /// @brief Minor version
    uint16_t minor = 0;
    
    /// @brief Patch version
    uint16_t patch = 0;
    
    /// @brief Build number
    uint32_t build = 0;
    
    /// @brief Version string
    std::string versionString;
    
    /// @brief Release date
    SystemTimePoint releaseDate;
    
    [[nodiscard]] bool operator<(const VersionInfo& other) const noexcept;
    [[nodiscard]] bool operator>(const VersionInfo& other) const noexcept;
    [[nodiscard]] bool operator==(const VersionInfo& other) const noexcept;
    [[nodiscard]] std::string ToJson() const;
    [[nodiscard]] std::string ToString() const;
};

/**
 * @brief Update package info
 */
struct UpdatePackage {
    /// @brief Package ID
    std::string packageId;
    
    /// @brief Update type
    UpdateType type = UpdateType::Signature;
    
    /// @brief Priority
    UpdatePriority priority = UpdatePriority::Normal;
    
    /// @brief Current version
    VersionInfo currentVersion;
    
    /// @brief New version
    VersionInfo newVersion;
    
    /// @brief Package size (bytes)
    uint64_t packageSize = 0;
    
    /// @brief Download size (may be smaller with delta)
    uint64_t downloadSize = 0;
    
    /// @brief Download URL
    std::string downloadUrl;
    
    /// @brief Checksum (SHA-256)
    std::string checksum;
    
    /// @brief Signature
    std::vector<uint8_t> signature;
    
    /// @brief Release notes
    std::string releaseNotes;
    
    /// @brief Is delta update
    bool isDelta = false;
    
    /// @brief Requires reboot
    bool requiresReboot = false;
    
    /// @brief Is mandatory
    bool isMandatory = false;
    
    /// @brief Dependencies
    std::vector<std::string> dependencies;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Download progress
 */
struct DownloadProgress {
    /// @brief Package ID
    std::string packageId;
    
    /// @brief State
    DownloadState state = DownloadState::NotStarted;
    
    /// @brief Bytes downloaded
    uint64_t bytesDownloaded = 0;
    
    /// @brief Total bytes
    uint64_t totalBytes = 0;
    
    /// @brief Progress (0-100)
    uint8_t progressPercent = 0;
    
    /// @brief Speed (bytes/sec)
    uint64_t speedBps = 0;
    
    /// @brief ETA (seconds)
    uint32_t etaSeconds = 0;
    
    /// @brief Start time
    SystemTimePoint startTime;
    
    /// @brief Retry count
    uint32_t retryCount = 0;
    
    /// @brief Error message
    std::string errorMessage;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Update result
 */
struct UpdateResult {
    /// @brief Success
    bool success = false;
    
    /// @brief Update type
    UpdateType type = UpdateType::Signature;
    
    /// @brief Old version
    VersionInfo oldVersion;
    
    /// @brief New version
    VersionInfo newVersion;
    
    /// @brief Applied time
    SystemTimePoint appliedTime;
    
    /// @brief Requires reboot
    bool requiresReboot = false;
    
    /// @brief Was rollback
    bool wasRollback = false;
    
    /// @brief Error message
    std::string errorMessage;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Update history entry
 */
struct UpdateHistoryEntry {
    /// @brief Entry ID
    std::string entryId;
    
    /// @brief Update type
    UpdateType type = UpdateType::Signature;
    
    /// @brief Version
    VersionInfo version;
    
    /// @brief Applied time
    SystemTimePoint appliedTime;
    
    /// @brief Success
    bool success = false;
    
    /// @brief Was rollback
    bool wasRollback = false;
    
    /// @brief Size (bytes)
    uint64_t size = 0;
    
    /// @brief Duration (seconds)
    uint32_t durationSeconds = 0;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Statistics
 */
struct UpdateStatistics {
    std::atomic<uint64_t> checksPerformed{0};
    std::atomic<uint64_t> updatesApplied{0};
    std::atomic<uint64_t> updatesFailed{0};
    std::atomic<uint64_t> rollbacksPerformed{0};
    std::atomic<uint64_t> bytesDownloaded{0};
    std::atomic<uint64_t> deltaUpdates{0};
    std::array<std::atomic<uint64_t>, 16> byUpdateType{};
    TimePoint startTime = Clock::now();
    std::optional<SystemTimePoint> lastCheckTime;
    std::optional<SystemTimePoint> lastUpdateTime;
    
    void Reset() noexcept;
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Configuration
 */
struct UpdateConfiguration {
    /// @brief Enable updates
    bool enabled = true;
    
    /// @brief Enable auto-update
    bool autoUpdate = true;
    
    /// @brief Update channel
    UpdateChannel channel = UpdateChannel::Stable;
    
    /// @brief Check interval (hours)
    uint32_t checkIntervalHours = UpdateConstants::DEFAULT_CHECK_INTERVAL_HOURS;
    
    /// @brief Update server URL
    std::string serverUrl = UpdateConstants::UPDATE_SERVER_URL;
    
    /// @brief Proxy URL (empty = system proxy)
    std::string proxyUrl;
    
    /// @brief Download timeout (seconds)
    uint32_t downloadTimeoutSeconds = UpdateConstants::DOWNLOAD_TIMEOUT_SECONDS;
    
    /// @brief Max retry attempts
    uint32_t maxRetryAttempts = UpdateConstants::MAX_RETRY_ATTEMPTS;
    
    /// @brief Staging directory
    fs::path stagingDirectory;
    
    /// @brief Respect metered connection
    bool respectMeteredConnection = true;
    
    /// @brief Defer during gaming
    bool deferDuringGaming = true;
    
    /// @brief Defer during high CPU
    bool deferDuringHighCPU = true;
    
    /// @brief CPU threshold for deferral (%)
    uint8_t cpuDeferThreshold = 80;
    
    /// @brief Enable P2P distribution
    bool enableP2P = false;
    
    /// @brief Enterprise management URL
    std::string enterpriseManagementUrl;
    
    [[nodiscard]] bool IsValid() const noexcept;
};

// ============================================================================
// CALLBACK TYPES
// ============================================================================

using StatusCallback = std::function<void(UpdateStatus)>;
using ProgressCallback = std::function<void(const DownloadProgress&)>;
using CompletionCallback = std::function<void(const UpdateResult&)>;
using AvailableCallback = std::function<void(const std::vector<UpdatePackage>&)>;
using ErrorCallback = std::function<void(const std::string& message, int code)>;

// ============================================================================
// UPDATE MANAGER CLASS
// ============================================================================

/**
 * @class UpdateManager
 * @brief Enterprise update orchestration
 */
class UpdateManager final {
public:
    [[nodiscard]] static UpdateManager& Instance() noexcept;
    [[nodiscard]] static bool HasInstance() noexcept;
    
    UpdateManager(const UpdateManager&) = delete;
    UpdateManager& operator=(const UpdateManager&) = delete;
    UpdateManager(UpdateManager&&) = delete;
    UpdateManager& operator=(UpdateManager&&) = delete;

    // ========================================================================
    // LIFECYCLE
    // ========================================================================
    
    [[nodiscard]] bool Initialize(const UpdateConfiguration& config = {});
    void Shutdown();
    [[nodiscard]] bool IsInitialized() const noexcept;
    [[nodiscard]] UpdateModuleStatus GetModuleStatus() const noexcept;
    
    [[nodiscard]] bool UpdateConfiguration(const UpdateConfiguration& config);
    [[nodiscard]] UpdateConfiguration GetConfiguration() const;

    // ========================================================================
    // UPDATE OPERATIONS
    // ========================================================================
    
    /// @brief Check for all updates
    void CheckForUpdates();
    
    /// @brief Check for updates asynchronously
    [[nodiscard]] std::future<std::vector<UpdatePackage>> CheckForUpdatesAsync();
    
    /// @brief Check for specific update type
    [[nodiscard]] std::optional<UpdatePackage> CheckForUpdate(UpdateType type);
    
    /// @brief Start update process
    [[nodiscard]] bool StartUpdate();
    
    /// @brief Start specific update
    [[nodiscard]] bool StartUpdate(const std::string& packageId);
    
    /// @brief Start all pending updates
    [[nodiscard]] bool StartAllUpdates();
    
    /// @brief Pause update
    void PauseUpdate();
    
    /// @brief Resume update
    void ResumeUpdate();
    
    /// @brief Cancel update
    void CancelUpdate();
    
    /// @brief Get current status
    [[nodiscard]] UpdateStatus GetStatus() const noexcept;
    
    /// @brief Is update in progress
    [[nodiscard]] bool IsUpdateInProgress() const noexcept;

    // ========================================================================
    // VERSION INFORMATION
    // ========================================================================
    
    /// @brief Get current version
    [[nodiscard]] VersionInfo GetCurrentVersion(UpdateType type) const;
    
    /// @brief Get all current versions
    [[nodiscard]] std::map<UpdateType, VersionInfo> GetAllCurrentVersions() const;
    
    /// @brief Get available updates
    [[nodiscard]] std::vector<UpdatePackage> GetAvailableUpdates() const;
    
    /// @brief Has pending updates
    [[nodiscard]] bool HasPendingUpdates() const noexcept;

    // ========================================================================
    // DOWNLOAD MANAGEMENT
    // ========================================================================
    
    /// @brief Get download progress
    [[nodiscard]] std::optional<DownloadProgress> GetDownloadProgress() const;
    
    /// @brief Get all download progress
    [[nodiscard]] std::vector<DownloadProgress> GetAllDownloadProgress() const;

    // ========================================================================
    // HISTORY
    // ========================================================================
    
    /// @brief Get update history
    [[nodiscard]] std::vector<UpdateHistoryEntry> GetUpdateHistory(
        size_t limit = 100,
        std::optional<UpdateType> filterType = std::nullopt) const;
    
    /// @brief Get last update time
    [[nodiscard]] std::optional<SystemTimePoint> GetLastUpdateTime(UpdateType type) const;
    
    /// @brief Get last check time
    [[nodiscard]] std::optional<SystemTimePoint> GetLastCheckTime() const;

    // ========================================================================
    // REBOOT HANDLING
    // ========================================================================
    
    /// @brief Is reboot required
    [[nodiscard]] bool IsRebootRequired() const noexcept;
    
    /// @brief Get pending reboot updates
    [[nodiscard]] std::vector<UpdateType> GetPendingRebootUpdates() const;
    
    /// @brief Finalize pending updates (call after reboot)
    [[nodiscard]] bool FinalizePendingUpdates();

    // ========================================================================
    // CALLBACKS
    // ========================================================================
    
    void RegisterStatusCallback(StatusCallback callback);
    void RegisterProgressCallback(ProgressCallback callback);
    void RegisterCompletionCallback(CompletionCallback callback);
    void RegisterAvailableCallback(AvailableCallback callback);
    void RegisterErrorCallback(ErrorCallback callback);
    void UnregisterCallbacks();

    // ========================================================================
    // STATISTICS
    // ========================================================================
    
    [[nodiscard]] UpdateStatistics GetStatistics() const;
    void ResetStatistics();
    
    [[nodiscard]] bool SelfTest();
    [[nodiscard]] static std::string GetVersionString() noexcept;

private:
    UpdateManager();
    ~UpdateManager();
    
    std::unique_ptr<UpdateManagerImpl> m_impl;
    std::atomic<UpdateStatus> m_status{UpdateStatus::Idle};
    static std::atomic<bool> s_instanceCreated;
};

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

[[nodiscard]] std::string_view GetStatusName(UpdateStatus status) noexcept;
[[nodiscard]] std::string_view GetUpdateTypeName(UpdateType type) noexcept;
[[nodiscard]] std::string_view GetPriorityName(UpdatePriority priority) noexcept;
[[nodiscard]] std::string_view GetChannelName(UpdateChannel channel) noexcept;
[[nodiscard]] std::string_view GetDownloadStateName(DownloadState state) noexcept;

/// @brief Parse version string
[[nodiscard]] std::optional<VersionInfo> ParseVersionString(const std::string& version);

/// @brief Compare versions
[[nodiscard]] int CompareVersions(const VersionInfo& a, const VersionInfo& b);

/// @brief Format size
[[nodiscard]] std::string FormatDownloadSize(uint64_t bytes);

}  // namespace Update
}  // namespace ShadowStrike

// ============================================================================
// MACROS
// ============================================================================

#define SS_CHECK_UPDATES() \
    ::ShadowStrike::Update::UpdateManager::Instance().CheckForUpdates()

#define SS_START_UPDATE() \
    ::ShadowStrike::Update::UpdateManager::Instance().StartUpdate()
