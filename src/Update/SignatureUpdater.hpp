/**
 * ============================================================================
 * ShadowStrike NGAV - SIGNATURE UPDATER MODULE
 * ============================================================================
 *
 * @file SignatureUpdater.hpp
 * @brief Enterprise-grade signature database updates with delta patching,
 *        hot-reload capability, and distributed delivery.
 *
 * Provides comprehensive signature update management including differential
 * downloads, atomic database swaps, and multi-source delivery.
 *
 * UPDATE CAPABILITIES:
 * ====================
 *
 * 1. DELTA UPDATES
 *    - Binary diff patching
 *    - Incremental updates
 *    - Minimal bandwidth
 *    - Version chaining
 *    - Rollup packages
 *
 * 2. HOT-RELOAD
 *    - Atomic database swap
 *    - Zero-downtime updates
 *    - Memory-mapped reload
 *    - Concurrent access safety
 *    - Scan continuation
 *
 * 3. VALIDATION
 *    - Cryptographic verification
 *    - Integrity checking
 *    - Version validation
 *    - Schema compatibility
 *    - Self-test after load
 *
 * 4. DELIVERY
 *    - CDN distribution
 *    - Mirror selection
 *    - Resume support
 *    - Compression
 *    - P2P option
 *
 * 5. DATABASE TYPES
 *    - Malware signatures
 *    - Heuristic rules
 *    - YARA rules
 *    - URL blacklists
 *    - Hash databases
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
#include "../Utils/NetworkUtils.hpp"
#include "../Utils/CryptoUtils.hpp"
#include "../SignatureStore/SignatureStore.hpp"

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

namespace ShadowStrike::Update {
    class SignatureUpdaterImpl;
}

namespace ShadowStrike {
namespace Update {

// ============================================================================
// COMPILE-TIME CONSTANTS
// ============================================================================

namespace SigUpdateConstants {

    inline constexpr uint32_t VERSION_MAJOR = 3;
    inline constexpr uint32_t VERSION_MINOR = 0;
    inline constexpr uint32_t VERSION_PATCH = 0;

    /// @brief Signature server URL
    inline constexpr const char* SIGNATURE_SERVER_URL = "https://signatures.shadowstrike.io/v3";
    
    /// @brief Default update interval (minutes)
    inline constexpr uint32_t DEFAULT_UPDATE_INTERVAL_MINUTES = 60;
    
    /// @brief Maximum delta chain length
    inline constexpr uint32_t MAX_DELTA_CHAIN_LENGTH = 10;
    
    /// @brief Database backup count
    inline constexpr uint32_t DATABASE_BACKUP_COUNT = 3;

}  // namespace SigUpdateConstants

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
 * @brief Signature database type
 */
enum class SignatureDatabaseType : uint8_t {
    Main            = 0,    ///< Main signature database
    Heuristic       = 1,    ///< Heuristic rules
    YARA            = 2,    ///< YARA rules
    URLs            = 3,    ///< URL blacklist
    Hashes          = 4,    ///< Hash database
    Patterns        = 5,    ///< Pattern database
    Behavioral      = 6,    ///< Behavioral signatures
    Emergency       = 7     ///< Emergency definitions
};

/**
 * @brief Update state
 */
enum class SigUpdateState : uint8_t {
    Idle            = 0,
    Checking        = 1,
    Downloading     = 2,
    Patching        = 3,
    Validating      = 4,
    Reloading       = 5,
    Completed       = 6,
    Failed          = 7
};

/**
 * @brief Update method
 */
enum class UpdateMethod : uint8_t {
    Full            = 0,    ///< Full database download
    Delta           = 1,    ///< Delta patch
    Incremental     = 2,    ///< Incremental update
    Rollup          = 3     ///< Rollup package
};

/**
 * @brief Module status
 */
enum class SigUpdaterStatus : uint8_t {
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
 * @brief Database version info
 */
struct DatabaseVersion {
    /// @brief Database type
    SignatureDatabaseType type = SignatureDatabaseType::Main;
    
    /// @brief Version number
    uint64_t versionNumber = 0;
    
    /// @brief Version string
    std::string versionString;
    
    /// @brief Signature count
    uint64_t signatureCount = 0;
    
    /// @brief Database size (bytes)
    uint64_t sizeBytes = 0;
    
    /// @brief Build date
    SystemTimePoint buildDate;
    
    /// @brief Release date
    SystemTimePoint releaseDate;
    
    /// @brief Checksum (SHA-256)
    std::string checksum;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Delta patch info
 */
struct DeltaPatchInfo {
    /// @brief Patch ID
    std::string patchId;
    
    /// @brief From version
    uint64_t fromVersion = 0;
    
    /// @brief To version
    uint64_t toVersion = 0;
    
    /// @brief Patch size (bytes)
    uint64_t patchSize = 0;
    
    /// @brief Download URL
    std::string downloadUrl;
    
    /// @brief Checksum
    std::string checksum;
    
    /// @brief Signature
    std::vector<uint8_t> signature;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Update package info
 */
struct SignaturePackage {
    /// @brief Package ID
    std::string packageId;
    
    /// @brief Database type
    SignatureDatabaseType type = SignatureDatabaseType::Main;
    
    /// @brief Update method
    UpdateMethod method = UpdateMethod::Delta;
    
    /// @brief Target version
    DatabaseVersion targetVersion;
    
    /// @brief Download size (bytes)
    uint64_t downloadSize = 0;
    
    /// @brief Download URL
    std::string downloadUrl;
    
    /// @brief Delta patches (for incremental)
    std::vector<DeltaPatchInfo> deltaPatches;
    
    /// @brief Is mandatory
    bool isMandatory = false;
    
    /// @brief Release notes
    std::string releaseNotes;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Update progress
 */
struct SigUpdateProgress {
    /// @brief Database type
    SignatureDatabaseType type = SignatureDatabaseType::Main;
    
    /// @brief State
    SigUpdateState state = SigUpdateState::Idle;
    
    /// @brief Progress (0-100)
    uint8_t progressPercent = 0;
    
    /// @brief Current operation
    std::string currentOperation;
    
    /// @brief Bytes downloaded
    uint64_t bytesDownloaded = 0;
    
    /// @brief Total bytes
    uint64_t totalBytes = 0;
    
    /// @brief Speed (bytes/sec)
    uint64_t speedBps = 0;
    
    /// @brief ETA (seconds)
    uint32_t etaSeconds = 0;
    
    /// @brief Error message
    std::string errorMessage;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Update result
 */
struct SigUpdateResult {
    /// @brief Success
    bool success = false;
    
    /// @brief Database type
    SignatureDatabaseType type = SignatureDatabaseType::Main;
    
    /// @brief Old version
    DatabaseVersion oldVersion;
    
    /// @brief New version
    DatabaseVersion newVersion;
    
    /// @brief Update method used
    UpdateMethod methodUsed = UpdateMethod::Delta;
    
    /// @brief Bytes downloaded
    uint64_t bytesDownloaded = 0;
    
    /// @brief Duration (seconds)
    uint32_t durationSeconds = 0;
    
    /// @brief Applied time
    SystemTimePoint appliedTime;
    
    /// @brief Error message
    std::string errorMessage;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Statistics
 */
struct SigUpdaterStatistics {
    std::atomic<uint64_t> updatesApplied{0};
    std::atomic<uint64_t> updatesFailed{0};
    std::atomic<uint64_t> deltaPatchesApplied{0};
    std::atomic<uint64_t> fullDownloads{0};
    std::atomic<uint64_t> bytesDownloaded{0};
    std::atomic<uint64_t> bytesSaved{0};  // vs full download
    std::atomic<uint64_t> hotReloads{0};
    std::array<std::atomic<uint64_t>, 16> byDatabaseType{};
    TimePoint startTime = Clock::now();
    std::optional<SystemTimePoint> lastUpdateTime;
    
    void Reset() noexcept;
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Configuration
 */
struct SignatureUpdaterConfiguration {
    /// @brief Enable updates
    bool enabled = true;
    
    /// @brief Enable auto-update
    bool autoUpdate = true;
    
    /// @brief Signature server URL
    std::string serverUrl = SigUpdateConstants::SIGNATURE_SERVER_URL;
    
    /// @brief Update interval (minutes)
    uint32_t updateIntervalMinutes = SigUpdateConstants::DEFAULT_UPDATE_INTERVAL_MINUTES;
    
    /// @brief Prefer delta updates
    bool preferDeltaUpdates = true;
    
    /// @brief Maximum delta chain
    uint32_t maxDeltaChain = SigUpdateConstants::MAX_DELTA_CHAIN_LENGTH;
    
    /// @brief Enable hot-reload
    bool enableHotReload = true;
    
    /// @brief Backup count
    uint32_t backupCount = SigUpdateConstants::DATABASE_BACKUP_COUNT;
    
    /// @brief Database directory
    fs::path databaseDirectory;
    
    /// @brief Staging directory
    fs::path stagingDirectory;
    
    /// @brief Enabled database types
    std::set<SignatureDatabaseType> enabledTypes = {
        SignatureDatabaseType::Main,
        SignatureDatabaseType::Heuristic,
        SignatureDatabaseType::Hashes
    };
    
    [[nodiscard]] bool IsValid() const noexcept;
};

// ============================================================================
// CALLBACK TYPES
// ============================================================================

using SigProgressCallback = std::function<void(const SigUpdateProgress&)>;
using SigCompletionCallback = std::function<void(const SigUpdateResult&)>;
using SigReloadCallback = std::function<void(SignatureDatabaseType)>;
using ErrorCallback = std::function<void(const std::string& message, int code)>;

// ============================================================================
// SIGNATURE UPDATER CLASS
// ============================================================================

/**
 * @class SignatureUpdater
 * @brief Enterprise signature updates
 */
class SignatureUpdater final {
public:
    [[nodiscard]] static SignatureUpdater& Instance() noexcept;
    [[nodiscard]] static bool HasInstance() noexcept;
    
    SignatureUpdater(const SignatureUpdater&) = delete;
    SignatureUpdater& operator=(const SignatureUpdater&) = delete;
    SignatureUpdater(SignatureUpdater&&) = delete;
    SignatureUpdater& operator=(SignatureUpdater&&) = delete;

    // ========================================================================
    // LIFECYCLE
    // ========================================================================
    
    [[nodiscard]] bool Initialize(const SignatureUpdaterConfiguration& config = {});
    void Shutdown();
    [[nodiscard]] bool IsInitialized() const noexcept;
    [[nodiscard]] SigUpdaterStatus GetStatus() const noexcept;
    
    [[nodiscard]] bool UpdateConfiguration(const SignatureUpdaterConfiguration& config);
    [[nodiscard]] SignatureUpdaterConfiguration GetConfiguration() const;

    // ========================================================================
    // UPDATE OPERATIONS
    // ========================================================================
    
    /// @brief Update signatures (all enabled types)
    [[nodiscard]] bool UpdateSignatures();
    
    /// @brief Update specific database
    [[nodiscard]] bool UpdateDatabase(SignatureDatabaseType type);
    
    /// @brief Check for updates
    [[nodiscard]] std::vector<SignaturePackage> CheckForUpdates();
    
    /// @brief Check specific database
    [[nodiscard]] std::optional<SignaturePackage> CheckForUpdate(SignatureDatabaseType type);
    
    /// @brief Apply specific package
    [[nodiscard]] bool ApplyPackage(const SignaturePackage& package);
    
    /// @brief Get update state
    [[nodiscard]] SigUpdateState GetUpdateState() const noexcept;
    
    /// @brief Is updating
    [[nodiscard]] bool IsUpdating() const noexcept;

    // ========================================================================
    // VERSION INFORMATION
    // ========================================================================
    
    /// @brief Get current version
    [[nodiscard]] std::string GetCurrentVersion();
    
    /// @brief Get database version
    [[nodiscard]] DatabaseVersion GetDatabaseVersion(SignatureDatabaseType type) const;
    
    /// @brief Get all database versions
    [[nodiscard]] std::map<SignatureDatabaseType, DatabaseVersion> GetAllVersions() const;

    // ========================================================================
    // PROGRESS
    // ========================================================================
    
    /// @brief Get current progress
    [[nodiscard]] std::optional<SigUpdateProgress> GetProgress() const;
    
    /// @brief Get all progress
    [[nodiscard]] std::vector<SigUpdateProgress> GetAllProgress() const;

    // ========================================================================
    // HOT-RELOAD
    // ========================================================================
    
    /// @brief Trigger hot-reload
    [[nodiscard]] bool TriggerHotReload(SignatureDatabaseType type);
    
    /// @brief Is database loaded
    [[nodiscard]] bool IsDatabaseLoaded(SignatureDatabaseType type) const;

    // ========================================================================
    // BACKUP/RESTORE
    // ========================================================================
    
    /// @brief Create backup
    [[nodiscard]] bool CreateBackup(SignatureDatabaseType type);
    
    /// @brief Restore from backup
    [[nodiscard]] bool RestoreFromBackup(SignatureDatabaseType type, uint32_t backupIndex = 0);
    
    /// @brief Get available backups
    [[nodiscard]] std::vector<DatabaseVersion> GetAvailableBackups(SignatureDatabaseType type) const;

    // ========================================================================
    // CALLBACKS
    // ========================================================================
    
    void RegisterProgressCallback(SigProgressCallback callback);
    void RegisterCompletionCallback(SigCompletionCallback callback);
    void RegisterReloadCallback(SigReloadCallback callback);
    void RegisterErrorCallback(ErrorCallback callback);
    void UnregisterCallbacks();

    // ========================================================================
    // STATISTICS
    // ========================================================================
    
    [[nodiscard]] SigUpdaterStatistics GetStatistics() const;
    void ResetStatistics();
    
    [[nodiscard]] bool SelfTest();
    [[nodiscard]] static std::string GetVersionString() noexcept;

private:
    SignatureUpdater();
    ~SignatureUpdater();
    
    std::unique_ptr<SignatureUpdaterImpl> m_impl;
    static std::atomic<bool> s_instanceCreated;
};

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

[[nodiscard]] std::string_view GetDatabaseTypeName(SignatureDatabaseType type) noexcept;
[[nodiscard]] std::string_view GetUpdateStateName(SigUpdateState state) noexcept;
[[nodiscard]] std::string_view GetUpdateMethodName(UpdateMethod method) noexcept;

/// @brief Get database file extension
[[nodiscard]] std::string_view GetDatabaseExtension(SignatureDatabaseType type) noexcept;

/// @brief Calculate delta path
[[nodiscard]] std::vector<DeltaPatchInfo> CalculateDeltaPath(
    uint64_t fromVersion,
    uint64_t toVersion,
    const std::vector<DeltaPatchInfo>& availablePatches);

}  // namespace Update
}  // namespace ShadowStrike

// ============================================================================
// MACROS
// ============================================================================

#define SS_UPDATE_SIGNATURES() \
    ::ShadowStrike::Update::SignatureUpdater::Instance().UpdateSignatures()

#define SS_GET_SIG_VERSION() \
    ::ShadowStrike::Update::SignatureUpdater::Instance().GetCurrentVersion()
