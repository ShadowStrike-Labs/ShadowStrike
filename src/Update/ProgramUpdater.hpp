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
 * ShadowStrike NGAV - PROGRAM UPDATER MODULE
 * ============================================================================
 *
 * @file ProgramUpdater.hpp
 * @brief Enterprise-grade program update management with self-replacement,
 *        driver updates, service restart, and automatic rollback.
 *
 * Provides comprehensive program update capabilities including executable
 * replacement, kernel driver updates, and safe recovery mechanisms.
 *
 * UPDATE CAPABILITIES:
 * ====================
 *
 * 1. EXECUTABLE UPDATES
 *    - Self-replacement
 *    - Service updates
 *    - GUI updates
 *    - Helper tools
 *    - Tray applications
 *
 * 2. DRIVER UPDATES
 *    - Minifilter driver
 *    - Network driver
 *    - Kernel extensions
 *    - Staged installation
 *    - Certificate validation
 *
 * 3. SAFE UPDATE PROCESS
 *    - Shadow copy staging
 *    - Atomic replacement
 *    - Service restart handling
 *    - Reboot scheduling
 *    - Pending file renames
 *
 * 4. RECOVERY MECHANISMS
 *    - Automatic rollback
 *    - Boot loop detection
 *    - Health validation
 *    - Last known good
 *    - Emergency recovery
 *
 * 5. ENTERPRISE FEATURES
 *    - Scheduled deployment
 *    - Maintenance windows
 *    - Group policy respect
 *    - SCCM/Intune support
 *    - MSI/MSIX packaging
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
#include "../Utils/FileUtils.hpp"
#include "../Utils/CryptoUtils.hpp"

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

namespace ShadowStrike::Update {
    class ProgramUpdaterImpl;
}

namespace ShadowStrike {
namespace Update {

// ============================================================================
// COMPILE-TIME CONSTANTS
// ============================================================================

namespace ProgUpdateConstants {

    inline constexpr uint32_t VERSION_MAJOR = 3;
    inline constexpr uint32_t VERSION_MINOR = 0;
    inline constexpr uint32_t VERSION_PATCH = 0;

    /// @brief Update staging directory
    inline constexpr const wchar_t* STAGING_DIR = L"Update\\ProgramStaging";
    
    /// @brief Backup directory
    inline constexpr const wchar_t* BACKUP_DIR = L"Update\\Backup";
    
    /// @brief Maximum backup versions
    inline constexpr uint32_t MAX_BACKUP_VERSIONS = 3;
    
    /// @brief Boot loop threshold
    inline constexpr uint32_t BOOT_LOOP_THRESHOLD = 3;
    
    /// @brief Boot loop time window (minutes)
    inline constexpr uint32_t BOOT_LOOP_WINDOW_MINUTES = 5;

}  // namespace ProgUpdateConstants

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
 * @brief Component type
 */
enum class ComponentType : uint8_t {
    Service         = 0,    ///< Main service
    GUI             = 1,    ///< GUI application
    Tray            = 2,    ///< Tray icon
    CLI             = 3,    ///< Command-line tool
    MinifilterDriver = 4,   ///< Kernel minifilter
    NetworkDriver   = 5,    ///< Network driver
    Helper          = 6,    ///< Helper process
    SDK             = 7,    ///< SDK components
    Uninstaller     = 8     ///< Uninstaller
};

/**
 * @brief Update state
 */
enum class ProgUpdateState : uint8_t {
    Idle            = 0,
    Checking        = 1,
    Downloading     = 2,
    Staging         = 3,
    Validating      = 4,
    Stopping        = 5,
    Replacing       = 6,
    Starting        = 7,
    Verifying       = 8,
    Completed       = 9,
    Failed          = 10,
    RollingBack     = 11
};

/**
 * @brief Installation method
 */
enum class InstallMethod : uint8_t {
    InPlace         = 0,    ///< Direct file replacement
    ShadowCopy      = 1,    ///< Shadow copy staging
    Installer       = 2,    ///< Run installer package
    MoveFileEx      = 3     ///< Pending reboot replacement
};

/**
 * @brief Reboot requirement
 */
enum class RebootRequirement : uint8_t {
    None            = 0,    ///< No reboot needed
    Optional        = 1,    ///< Reboot recommended
    Required        = 2,    ///< Reboot required
    Immediate       = 3     ///< Immediate reboot
};

/**
 * @brief Module status
 */
enum class ProgUpdaterStatus : uint8_t {
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
struct ProgramVersion {
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
    
    /// @brief Product name
    std::string productName;
    
    /// @brief File description
    std::string fileDescription;
    
    /// @brief Copyright
    std::string copyright;
    
    [[nodiscard]] bool operator<(const ProgramVersion& other) const noexcept;
    [[nodiscard]] bool operator>(const ProgramVersion& other) const noexcept;
    [[nodiscard]] bool operator==(const ProgramVersion& other) const noexcept;
    [[nodiscard]] std::string ToJson() const;
    [[nodiscard]] std::string ToString() const;
};

/**
 * @brief Component info
 */
struct ComponentInfo {
    /// @brief Component type
    ComponentType type = ComponentType::Service;
    
    /// @brief Display name
    std::string displayName;
    
    /// @brief File name
    std::wstring fileName;
    
    /// @brief Install path
    fs::path installPath;
    
    /// @brief Current version
    ProgramVersion currentVersion;
    
    /// @brief File size (bytes)
    uint64_t fileSize = 0;
    
    /// @brief File hash (SHA-256)
    std::string fileHash;
    
    /// @brief Is installed
    bool isInstalled = false;
    
    /// @brief Is running
    bool isRunning = false;
    
    /// @brief Requires elevation
    bool requiresElevation = false;
    
    /// @brief Is driver
    bool isDriver = false;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Update package
 */
struct ProgramPackage {
    /// @brief Package ID
    std::string packageId;
    
    /// @brief Components included
    std::vector<ComponentType> components;
    
    /// @brief New version
    ProgramVersion newVersion;
    
    /// @brief Package size (bytes)
    uint64_t packageSize = 0;
    
    /// @brief Download URL
    std::string downloadUrl;
    
    /// @brief Checksum
    std::string checksum;
    
    /// @brief Digital signature
    std::vector<uint8_t> signature;
    
    /// @brief Installation method
    InstallMethod installMethod = InstallMethod::ShadowCopy;
    
    /// @brief Reboot requirement
    RebootRequirement rebootRequirement = RebootRequirement::None;
    
    /// @brief Is mandatory
    bool isMandatory = false;
    
    /// @brief Release notes
    std::string releaseNotes;
    
    /// @brief Changelog
    std::vector<std::string> changelog;
    
    /// @brief Dependencies
    std::vector<std::string> dependencies;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Update progress
 */
struct ProgUpdateProgress {
    /// @brief State
    ProgUpdateState state = ProgUpdateState::Idle;
    
    /// @brief Progress (0-100)
    uint8_t progressPercent = 0;
    
    /// @brief Current component
    std::optional<ComponentType> currentComponent;
    
    /// @brief Current operation
    std::string currentOperation;
    
    /// @brief Bytes downloaded
    uint64_t bytesDownloaded = 0;
    
    /// @brief Total bytes
    uint64_t totalBytes = 0;
    
    /// @brief Components completed
    uint32_t componentsCompleted = 0;
    
    /// @brief Components total
    uint32_t componentsTotal = 0;
    
    /// @brief Error message
    std::string errorMessage;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Update result
 */
struct ProgUpdateResult {
    /// @brief Success
    bool success = false;
    
    /// @brief Old version
    ProgramVersion oldVersion;
    
    /// @brief New version
    ProgramVersion newVersion;
    
    /// @brief Updated components
    std::vector<ComponentType> updatedComponents;
    
    /// @brief Reboot required
    bool rebootRequired = false;
    
    /// @brief Was rollback
    bool wasRollback = false;
    
    /// @brief Applied time
    SystemTimePoint appliedTime;
    
    /// @brief Duration (seconds)
    uint32_t durationSeconds = 0;
    
    /// @brief Error message
    std::string errorMessage;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Statistics
 */
struct ProgUpdaterStatistics {
    std::atomic<uint64_t> updatesApplied{0};
    std::atomic<uint64_t> updatesFailed{0};
    std::atomic<uint64_t> rollbacksPerformed{0};
    std::atomic<uint64_t> driverUpdates{0};
    std::atomic<uint64_t> serviceRestarts{0};
    std::atomic<uint64_t> rebootsScheduled{0};
    std::atomic<uint64_t> bytesDownloaded{0};
    TimePoint startTime = Clock::now();
    std::optional<SystemTimePoint> lastUpdateTime;
    
    void Reset() noexcept;
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Configuration
 */
struct ProgramUpdaterConfiguration {
    /// @brief Enable updates
    bool enabled = true;
    
    /// @brief Enable auto-update
    bool autoUpdate = false;  // Program updates usually need confirmation
    
    /// @brief Staging directory
    fs::path stagingDirectory;
    
    /// @brief Backup directory
    fs::path backupDirectory;
    
    /// @brief Max backup versions
    uint32_t maxBackupVersions = ProgUpdateConstants::MAX_BACKUP_VERSIONS;
    
    /// @brief Enable boot loop detection
    bool enableBootLoopDetection = true;
    
    /// @brief Boot loop threshold
    uint32_t bootLoopThreshold = ProgUpdateConstants::BOOT_LOOP_THRESHOLD;
    
    /// @brief Boot loop window (minutes)
    uint32_t bootLoopWindowMinutes = ProgUpdateConstants::BOOT_LOOP_WINDOW_MINUTES;
    
    /// @brief Auto-rollback on failure
    bool autoRollbackOnFailure = true;
    
    /// @brief Verify after update
    bool verifyAfterUpdate = true;
    
    /// @brief Allow driver updates
    bool allowDriverUpdates = true;
    
    [[nodiscard]] bool IsValid() const noexcept;
};

// ============================================================================
// CALLBACK TYPES
// ============================================================================

using ProgProgressCallback = std::function<void(const ProgUpdateProgress&)>;
using ProgCompletionCallback = std::function<void(const ProgUpdateResult&)>;
using ServiceControlCallback = std::function<bool(bool stop)>;  // true = stop, false = start
using ErrorCallback = std::function<void(const std::string& message, int code)>;

// ============================================================================
// PROGRAM UPDATER CLASS
// ============================================================================

/**
 * @class ProgramUpdater
 * @brief Enterprise program updates
 */
class ProgramUpdater final {
public:
    [[nodiscard]] static ProgramUpdater& Instance() noexcept;
    [[nodiscard]] static bool HasInstance() noexcept;
    
    ProgramUpdater(const ProgramUpdater&) = delete;
    ProgramUpdater& operator=(const ProgramUpdater&) = delete;
    ProgramUpdater(ProgramUpdater&&) = delete;
    ProgramUpdater& operator=(ProgramUpdater&&) = delete;

    // ========================================================================
    // LIFECYCLE
    // ========================================================================
    
    [[nodiscard]] bool Initialize(const ProgramUpdaterConfiguration& config = {});
    void Shutdown();
    [[nodiscard]] bool IsInitialized() const noexcept;
    [[nodiscard]] ProgUpdaterStatus GetStatus() const noexcept;
    
    [[nodiscard]] bool UpdateConfiguration(const ProgramUpdaterConfiguration& config);
    [[nodiscard]] ProgramUpdaterConfiguration GetConfiguration() const;

    // ========================================================================
    // VERSION CHECK
    // ========================================================================
    
    /// @brief Check for new version
    [[nodiscard]] bool IsNewVersionAvailable();
    
    /// @brief Check for updates
    [[nodiscard]] std::optional<ProgramPackage> CheckForUpdate();
    
    /// @brief Get current version
    [[nodiscard]] ProgramVersion GetCurrentVersion() const;
    
    /// @brief Get component info
    [[nodiscard]] std::vector<ComponentInfo> GetInstalledComponents() const;
    
    /// @brief Get specific component info
    [[nodiscard]] std::optional<ComponentInfo> GetComponentInfo(ComponentType type) const;

    // ========================================================================
    // UPDATE OPERATIONS
    // ========================================================================
    
    /// @brief Apply program update
    [[nodiscard]] bool ApplyProgramUpdate();
    
    /// @brief Apply specific package
    [[nodiscard]] bool ApplyPackage(const ProgramPackage& package);
    
    /// @brief Stage update (download and prepare)
    [[nodiscard]] bool StageUpdate(const ProgramPackage& package);
    
    /// @brief Apply staged update
    [[nodiscard]] bool ApplyStagedUpdate();
    
    /// @brief Cancel update
    void CancelUpdate();
    
    /// @brief Get update state
    [[nodiscard]] ProgUpdateState GetUpdateState() const noexcept;
    
    /// @brief Is update in progress
    [[nodiscard]] bool IsUpdateInProgress() const noexcept;

    // ========================================================================
    // PROGRESS
    // ========================================================================
    
    /// @brief Get current progress
    [[nodiscard]] ProgUpdateProgress GetProgress() const;

    // ========================================================================
    // ROLLBACK
    // ========================================================================
    
    /// @brief Can rollback
    [[nodiscard]] bool CanRollback() const;
    
    /// @brief Perform rollback
    [[nodiscard]] bool PerformRollback();
    
    /// @brief Get available rollback versions
    [[nodiscard]] std::vector<ProgramVersion> GetRollbackVersions() const;

    // ========================================================================
    // REBOOT HANDLING
    // ========================================================================
    
    /// @brief Is reboot required
    [[nodiscard]] bool IsRebootRequired() const noexcept;
    
    /// @brief Schedule reboot
    [[nodiscard]] bool ScheduleReboot(uint32_t delayMinutes = 5);
    
    /// @brief Cancel scheduled reboot
    void CancelScheduledReboot();
    
    /// @brief Finalize pending updates (post-reboot)
    [[nodiscard]] bool FinalizePendingUpdates();

    // ========================================================================
    // HEALTH CHECK
    // ========================================================================
    
    /// @brief Verify installation health
    [[nodiscard]] bool VerifyInstallationHealth();
    
    /// @brief Check for boot loop
    [[nodiscard]] bool IsBootLoopDetected() const;
    
    /// @brief Clear boot loop counter
    void ClearBootLoopCounter();

    // ========================================================================
    // CALLBACKS
    // ========================================================================
    
    void RegisterProgressCallback(ProgProgressCallback callback);
    void RegisterCompletionCallback(ProgCompletionCallback callback);
    void RegisterServiceControlCallback(ServiceControlCallback callback);
    void RegisterErrorCallback(ErrorCallback callback);
    void UnregisterCallbacks();

    // ========================================================================
    // STATISTICS
    // ========================================================================
    
    [[nodiscard]] ProgUpdaterStatistics GetStatistics() const;
    void ResetStatistics();
    
    [[nodiscard]] bool SelfTest();
    [[nodiscard]] static std::string GetVersionString() noexcept;

private:
    ProgramUpdater();
    ~ProgramUpdater();
    
    std::unique_ptr<ProgramUpdaterImpl> m_impl;
    static std::atomic<bool> s_instanceCreated;
};

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

[[nodiscard]] std::string_view GetComponentTypeName(ComponentType type) noexcept;
[[nodiscard]] std::string_view GetUpdateStateName(ProgUpdateState state) noexcept;
[[nodiscard]] std::string_view GetInstallMethodName(InstallMethod method) noexcept;
[[nodiscard]] std::string_view GetRebootRequirementName(RebootRequirement req) noexcept;

/// @brief Get file version info
[[nodiscard]] std::optional<ProgramVersion> GetFileVersionInfo(const fs::path& filePath);

/// @brief Verify code signature
[[nodiscard]] bool VerifyCodeSignature(const fs::path& filePath);

/// @brief Compare program versions
[[nodiscard]] int CompareVersions(const ProgramVersion& a, const ProgramVersion& b);

}  // namespace Update
}  // namespace ShadowStrike

// ============================================================================
// MACROS
// ============================================================================

#define SS_CHECK_PROGRAM_UPDATE() \
    ::ShadowStrike::Update::ProgramUpdater::Instance().IsNewVersionAvailable()

#define SS_APPLY_PROGRAM_UPDATE() \
    ::ShadowStrike::Update::ProgramUpdater::Instance().ApplyProgramUpdate()
