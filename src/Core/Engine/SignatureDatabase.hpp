/**
 * ============================================================================
 * ShadowStrike NGAV - SIGNATURE DATABASE MODULE
 * ============================================================================
 *
 * @file SignatureDatabase.hpp
 * @brief Enterprise-grade unified signature database management system with
 *        multi-source loading, incremental updates, and query optimization.
 *
 * High-level manager for signature collections, providing unified access to
 * all detection signatures across multiple database files.
 *
 * SIGNATURE DATABASE CAPABILITIES:
 * =================================
 *
 * 1. DATABASE MANAGEMENT
 *    - Multi-file database loading
 *    - Incremental database updates
 *    - Version control
 *    - Integrity verification
 *    - Hot-reload support
 *
 * 2. QUERY INTERFACE
 *    - Hash-based lookups
 *    - Pattern matching
 *    - YARA rule queries
 *    - Behavioral signatures
 *    - Fuzzy matching
 *
 * 3. DATABASE TYPES
 *    - Malware signatures
 *    - PUP (Potentially Unwanted)
 *    - Adware
 *    - Exploit signatures
 *    - Network IOCs
 *    - Behavioral rules
 *
 * 4. OPTIMIZATION
 *    - Memory-mapped storage
 *    - Query caching
 *    - Parallel lookups
 *    - Index optimization
 *
 * 5. UPDATE MANAGEMENT
 *    - Delta updates
 *    - Full database updates
 *    - Rollback support
 *    - Validation
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
#include <set>
#include <optional>
#include <memory>
#include <functional>
#include <chrono>
#include <atomic>
#include <mutex>
#include <shared_mutex>
#include <filesystem>
#include <span>

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

#include "../../SignatureStore/SignatureStore.hpp"
#include "../../Utils/Logger.hpp"
#include "../../Utils/FileUtils.hpp"
#include "../../Utils/HashUtils.hpp"
#include "../../Utils/CryptoUtils.hpp"

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

namespace ShadowStrike::Core::Engine {
    class SignatureDatabaseImpl;
}

namespace ShadowStrike {
namespace Core {
namespace Engine {

// ============================================================================
// COMPILE-TIME CONSTANTS
// ============================================================================

namespace SigDBConstants {

    inline constexpr uint32_t VERSION_MAJOR = 3;
    inline constexpr uint32_t VERSION_MINOR = 0;
    inline constexpr uint32_t VERSION_PATCH = 0;

    /// @brief Maximum databases
    inline constexpr size_t MAX_DATABASES = 64;
    
    /// @brief Database file extension
    inline constexpr const char* DATABASE_EXTENSION = ".ssdb";
    
    /// @brief Query cache size
    inline constexpr size_t QUERY_CACHE_SIZE = 100000;
    
    /// @brief Update check interval (hours)
    inline constexpr uint32_t UPDATE_CHECK_INTERVAL_HOURS = 1;

}  // namespace SigDBConstants

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
 * @brief Database type
 */
enum class DatabaseType : uint8_t {
    Main            = 0,    ///< Primary malware signatures
    Extended        = 1,    ///< Extended detection
    PUP             = 2,    ///< Potentially Unwanted Programs
    Adware          = 3,    ///< Adware signatures
    Exploit         = 4,    ///< Exploit signatures
    Ransomware      = 5,    ///< Ransomware-specific
    Network         = 6,    ///< Network IOCs
    Behavioral      = 7,    ///< Behavioral rules
    YARA            = 8,    ///< YARA rules
    Custom          = 9     ///< Custom/user-defined
};

/**
 * @brief Detection type
 */
enum class DetectionType : uint8_t {
    ExactHash       = 0,    ///< Exact hash match
    PartialHash     = 1,    ///< Section/segment hash
    FuzzyHash       = 2,    ///< SSDEEP/TLSH
    BytePattern     = 3,    ///< Byte sequence
    YARARule        = 4,    ///< YARA rule
    Behavioral      = 5,    ///< Behavioral indicator
    Heuristic       = 6,    ///< Heuristic detection
    MachineLearning = 7,    ///< ML-based
    Generic         = 8     ///< Generic detection
};

/**
 * @brief Threat category
 */
enum class ThreatCategory : uint8_t {
    Virus           = 0,
    Trojan          = 1,
    Worm            = 2,
    Ransomware      = 3,
    Backdoor        = 4,
    Spyware         = 5,
    Rootkit         = 6,
    Keylogger       = 7,
    Miner           = 8,
    PUP             = 9,
    Adware          = 10,
    Exploit         = 11,
    Dropper         = 12,
    Downloader      = 13,
    HackTool        = 14,
    Unknown         = 15
};

/**
 * @brief Database status
 */
enum class DBStatus : uint8_t {
    NotLoaded       = 0,
    Loading         = 1,
    Loaded          = 2,
    Updating        = 3,
    Corrupted       = 4,
    OutOfDate       = 5,
    Error           = 6
};

/**
 * @brief Manager status
 */
enum class SigDBStatus : uint8_t {
    Uninitialized   = 0,
    Initializing    = 1,
    Running         = 2,
    Updating        = 3,
    Error           = 4,
    Stopping        = 5,
    Stopped         = 6
};

// ============================================================================
// STRUCTURES
// ============================================================================

/**
 * @brief Database version info
 */
struct DatabaseVersion {
    /// @brief Major version
    uint32_t major = 0;
    
    /// @brief Minor version
    uint32_t minor = 0;
    
    /// @brief Build number
    uint32_t build = 0;
    
    /// @brief Release date
    SystemTimePoint releaseDate;
    
    /// @brief Signature count
    uint64_t signatureCount = 0;
    
    /// @brief Database size (bytes)
    uint64_t databaseSize = 0;
    
    [[nodiscard]] std::string ToString() const;
    [[nodiscard]] std::string ToJson() const;
    
    [[nodiscard]] bool operator<(const DatabaseVersion& other) const noexcept;
    [[nodiscard]] bool operator==(const DatabaseVersion& other) const noexcept;
};

/**
 * @brief Database info
 */
struct DatabaseInfo {
    /// @brief Database name
    std::string name;
    
    /// @brief Database type
    DatabaseType type = DatabaseType::Main;
    
    /// @brief Status
    DBStatus status = DBStatus::NotLoaded;
    
    /// @brief File path
    fs::path filePath;
    
    /// @brief Version
    DatabaseVersion version;
    
    /// @brief Signature count
    uint64_t signatureCount = 0;
    
    /// @brief File size
    uint64_t fileSize = 0;
    
    /// @brief Memory usage
    uint64_t memoryUsage = 0;
    
    /// @brief Last loaded
    SystemTimePoint lastLoaded;
    
    /// @brief Last updated
    SystemTimePoint lastUpdated;
    
    /// @brief Checksum (SHA-256)
    std::string checksum;
    
    [[nodiscard]] bool IsValid() const noexcept;
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Signature match
 */
struct SignatureMatch {
    /// @brief Detection name
    std::string detectionName;
    
    /// @brief Threat category
    ThreatCategory category = ThreatCategory::Unknown;
    
    /// @brief Detection type
    DetectionType detectionType = DetectionType::ExactHash;
    
    /// @brief Severity (1-10)
    uint32_t severity = 5;
    
    /// @brief Database that matched
    std::string database;
    
    /// @brief Signature ID
    std::string signatureId;
    
    /// @brief Match confidence (0.0 - 1.0)
    float confidence = 1.0f;
    
    /// @brief Matched pattern (for byte patterns)
    std::optional<std::string> matchedPattern;
    
    /// @brief Matched hash
    std::optional<std::string> matchedHash;
    
    /// @brief File offset of match
    std::optional<uint64_t> matchOffset;
    
    /// @brief Malware family
    std::string family;
    
    /// @brief Variant
    std::string variant;
    
    /// @brief Description
    std::string description;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Query result
 */
struct QueryResult {
    /// @brief Is malicious
    bool isMalicious = false;
    
    /// @brief Matches found
    std::vector<SignatureMatch> matches;
    
    /// @brief Highest severity
    uint32_t highestSeverity = 0;
    
    /// @brief Primary detection name
    std::string primaryDetection;
    
    /// @brief Query time (microseconds)
    uint64_t queryTimeUs = 0;
    
    /// @brief Databases queried
    std::vector<std::string> databasesQueried;
    
    /// @brief From cache
    bool fromCache = false;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Query options
 */
struct QueryOptions {
    /// @brief Databases to query (empty = all)
    std::set<DatabaseType> databases;
    
    /// @brief Detection types to use
    std::set<DetectionType> detectionTypes;
    
    /// @brief Minimum severity
    uint32_t minSeverity = 0;
    
    /// @brief Enable caching
    bool useCache = true;
    
    /// @brief Maximum matches to return
    size_t maxMatches = 10;
    
    /// @brief Timeout (milliseconds)
    uint32_t timeoutMs = 5000;
    
    [[nodiscard]] bool IsValid() const noexcept;
};

/**
 * @brief Update info
 */
struct DatabaseUpdateInfo {
    /// @brief Database name
    std::string databaseName;
    
    /// @brief Current version
    DatabaseVersion currentVersion;
    
    /// @brief Available version
    DatabaseVersion availableVersion;
    
    /// @brief Update size (bytes)
    uint64_t updateSize = 0;
    
    /// @brief Is delta update
    bool isDelta = false;
    
    /// @brief New signatures
    uint64_t newSignatures = 0;
    
    /// @brief Modified signatures
    uint64_t modifiedSignatures = 0;
    
    /// @brief Removed signatures
    uint64_t removedSignatures = 0;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Statistics
 */
struct SigDBStatistics {
    std::atomic<uint64_t> totalQueries{0};
    std::atomic<uint64_t> matchesFound{0};
    std::atomic<uint64_t> cacheHits{0};
    std::atomic<uint64_t> cacheMisses{0};
    std::atomic<uint64_t> hashQueries{0};
    std::atomic<uint64_t> patternQueries{0};
    std::atomic<uint64_t> yaraQueries{0};
    std::atomic<uint64_t> databaseLoads{0};
    std::atomic<uint64_t> databaseUpdates{0};
    std::atomic<uint64_t> totalSignaturesLoaded{0};
    std::atomic<uint64_t> totalQueryTimeUs{0};
    TimePoint startTime = Clock::now();
    
    void Reset() noexcept;
    [[nodiscard]] double GetAverageQueryTimeUs() const noexcept;
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Configuration
 */
struct SignatureDatabaseConfiguration {
    /// @brief Database directory
    fs::path databaseDirectory;
    
    /// @brief Enable query caching
    bool enableCaching = true;
    
    /// @brief Cache size
    size_t cacheSize = SigDBConstants::QUERY_CACHE_SIZE;
    
    /// @brief Cache TTL (seconds)
    uint32_t cacheTtlSeconds = 3600;
    
    /// @brief Enable parallel loading
    bool parallelLoading = true;
    
    /// @brief Auto-check for updates
    bool autoCheckUpdates = true;
    
    /// @brief Update check interval (hours)
    uint32_t updateCheckIntervalHours = SigDBConstants::UPDATE_CHECK_INTERVAL_HOURS;
    
    /// @brief Validate database integrity on load
    bool validateOnLoad = true;
    
    /// @brief Memory limit (MB, 0 = unlimited)
    uint32_t memoryLimitMb = 0;
    
    [[nodiscard]] bool IsValid() const noexcept;
};

// ============================================================================
// CALLBACK TYPES
// ============================================================================

using LoadProgressCallback = std::function<void(const std::string& database, uint32_t progress)>;
using UpdateCallback = std::function<void(const DatabaseUpdateInfo& updateInfo)>;
using QueryCallback = std::function<void(const QueryResult& result)>;
using ErrorCallback = std::function<void(const std::string& message, int code)>;

// ============================================================================
// SIGNATURE DATABASE CLASS
// ============================================================================

/**
 * @class SignatureDatabase
 * @brief Enterprise signature database
 */
class SignatureDatabase final {
public:
    [[nodiscard]] static SignatureDatabase& Instance() noexcept;
    [[nodiscard]] static bool HasInstance() noexcept;
    
    SignatureDatabase(const SignatureDatabase&) = delete;
    SignatureDatabase& operator=(const SignatureDatabase&) = delete;
    SignatureDatabase(SignatureDatabase&&) = delete;
    SignatureDatabase& operator=(SignatureDatabase&&) = delete;

    // ========================================================================
    // LIFECYCLE
    // ========================================================================
    
    [[nodiscard]] bool Initialize(const SignatureDatabaseConfiguration& config = {});
    void Shutdown();
    [[nodiscard]] bool IsInitialized() const noexcept;
    [[nodiscard]] SigDBStatus GetStatus() const noexcept;

    // ========================================================================
    // DATABASE LOADING
    // ========================================================================
    
    /// @brief Load all databases from directory
    [[nodiscard]] bool LoadAll(const std::wstring& directoryPath);
    
    /// @brief Load all from configured directory
    [[nodiscard]] bool LoadAll();
    
    /// @brief Load specific database
    [[nodiscard]] bool LoadDatabase(const fs::path& databasePath);
    
    /// @brief Load database by type
    [[nodiscard]] bool LoadDatabase(DatabaseType type);
    
    /// @brief Unload database
    [[nodiscard]] bool UnloadDatabase(const std::string& name);
    
    /// @brief Reload database
    [[nodiscard]] bool ReloadDatabase(const std::string& name);
    
    /// @brief Reload all databases
    [[nodiscard]] bool ReloadAll();

    // ========================================================================
    // QUERIES
    // ========================================================================
    
    /// @brief Query by hash
    [[nodiscard]] QueryResult QueryByHash(const std::string& hash, const QueryOptions& options = {});
    
    /// @brief Query by multiple hashes
    [[nodiscard]] std::vector<QueryResult> QueryByHashes(
        const std::vector<std::string>& hashes,
        const QueryOptions& options = {});
    
    /// @brief Query file
    [[nodiscard]] QueryResult QueryFile(const fs::path& filePath, const QueryOptions& options = {});
    
    /// @brief Query buffer
    [[nodiscard]] QueryResult QueryBuffer(std::span<const uint8_t> data, const QueryOptions& options = {});
    
    /// @brief Async query
    void QueryAsync(const std::string& hash, QueryCallback callback, const QueryOptions& options = {});

    // ========================================================================
    // DATABASE INFO
    // ========================================================================
    
    /// @brief Get database info
    [[nodiscard]] std::optional<DatabaseInfo> GetDatabaseInfo(const std::string& dbName) const;
    
    /// @brief Get all database info
    [[nodiscard]] std::vector<DatabaseInfo> GetAllDatabaseInfo() const;
    
    /// @brief Get database version
    [[nodiscard]] std::string GetDatabaseVersion(const std::string& dbName) const;
    
    /// @brief Get total signature count
    [[nodiscard]] uint64_t GetTotalSignatureCount() const;
    
    /// @brief Is database loaded
    [[nodiscard]] bool IsDatabaseLoaded(const std::string& dbName) const;

    // ========================================================================
    // UPDATE MANAGEMENT
    // ========================================================================
    
    /// @brief Check if database needs update
    [[nodiscard]] bool NeedsUpdate(const std::string& dbName) const;
    
    /// @brief Check for available updates
    [[nodiscard]] std::vector<DatabaseUpdateInfo> CheckForUpdates() const;
    
    /// @brief Apply database update
    [[nodiscard]] bool ApplyUpdate(const fs::path& updatePath, const std::string& dbName);
    
    /// @brief Rollback database to previous version
    [[nodiscard]] bool RollbackDatabase(const std::string& dbName);

    // ========================================================================
    // CACHE MANAGEMENT
    // ========================================================================
    
    /// @brief Clear query cache
    void ClearCache();
    
    /// @brief Get cache statistics
    [[nodiscard]] std::pair<size_t, size_t> GetCacheStats() const;  // (hits, total)
    
    /// @brief Set cache enabled
    void SetCacheEnabled(bool enabled);

    // ========================================================================
    // CALLBACKS
    // ========================================================================
    
    void RegisterLoadProgressCallback(LoadProgressCallback callback);
    void RegisterUpdateCallback(UpdateCallback callback);
    void RegisterErrorCallback(ErrorCallback callback);
    void UnregisterCallbacks();

    // ========================================================================
    // STATISTICS
    // ========================================================================
    
    [[nodiscard]] SigDBStatistics GetStatistics() const;
    void ResetStatistics();
    
    [[nodiscard]] bool SelfTest();
    [[nodiscard]] static std::string GetVersionString() noexcept;

private:
    SignatureDatabase();
    ~SignatureDatabase();
    
    std::unique_ptr<SignatureDatabaseImpl> m_impl;
    std::unique_ptr<SignatureStore::SignatureStore> m_masterStore;
    static std::atomic<bool> s_instanceCreated;
};

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

[[nodiscard]] std::string_view GetDatabaseTypeName(DatabaseType type) noexcept;
[[nodiscard]] std::string_view GetDetectionTypeName(DetectionType type) noexcept;
[[nodiscard]] std::string_view GetThreatCategoryName(ThreatCategory category) noexcept;
[[nodiscard]] std::string_view GetDBStatusName(DBStatus status) noexcept;

/// @brief Parse detection name to components
[[nodiscard]] std::tuple<ThreatCategory, std::string, std::string> ParseDetectionName(const std::string& name);

/// @brief Format detection name from components
[[nodiscard]] std::string FormatDetectionName(ThreatCategory category, const std::string& family, const std::string& variant);

}  // namespace Engine
}  // namespace Core
}  // namespace ShadowStrike

// ============================================================================
// MACROS
// ============================================================================

#define SS_SIGDB_QUERY(hash) \
    ::ShadowStrike::Core::Engine::SignatureDatabase::Instance().QueryByHash(hash)

#define SS_SIGDB_IS_MALICIOUS(hash) \
    ::ShadowStrike::Core::Engine::SignatureDatabase::Instance().QueryByHash(hash).isMalicious
