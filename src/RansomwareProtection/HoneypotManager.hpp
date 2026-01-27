/**
 * ============================================================================
 * ShadowStrike Ransomware Protection - HONEYPOT MANAGER
 * ============================================================================
 *
 * @file HoneypotManager.hpp
 * @brief Enterprise-grade decoy file management system for ransomware trapping
 *        using strategically placed canary files and directories.
 *
 * This module provides comprehensive honeypot capabilities by deploying
 * realistic-looking decoy files in user directories that legitimate users
 * never access, enabling instant ransomware detection upon modification.
 *
 * HONEYPOT CAPABILITIES:
 * ======================
 *
 * 1. STRATEGIC PLACEMENT
 *    - User Documents folder
 *    - Desktop
 *    - Pictures/Videos/Music
 *    - Root drives (C:\, D:\, etc.)
 *    - Network shares
 *    - Cloud sync folders (OneDrive, Dropbox)
 *
 * 2. FILE TYPES
 *    - Office documents (.docx, .xlsx, .pptx)
 *    - PDF files
 *    - Image files (.jpg, .png)
 *    - Database files (.sql, .mdb)
 *    - Configuration files
 *    - Cryptocurrency wallets
 *    - Password managers
 *
 * 3. STEALTH FEATURES
 *    - Hidden/System attributes
 *    - Realistic file headers
 *    - Appropriate file sizes
 *    - Fake metadata/timestamps
 *    - Directory hierarchies
 *
 * 4. MONITORING
 *    - Real-time access detection
 *    - Read/write/delete tracking
 *    - Process identification
 *    - Timestamp logging
 *    - Alert generation
 *
 * 5. PERSISTENCE
 *    - Auto-regeneration on deletion
 *    - Integrity verification
 *    - Scheduled health checks
 *    - Configuration backup
 *
 * 6. RESPONSE
 *    - Instant alert generation
 *    - Process termination
 *    - Forensic data collection
 *    - Network isolation trigger
 *
 * INTEGRATION:
 * ============
 * - Core::FileSystem::FileWatcher for monitoring
 * - Ransomware::RansomwareDetector for alerts
 * - Utils::FileUtils for file operations
 *
 * @note Honeypots should be indistinguishable from real user files.
 * @note False positive rate should be near-zero for legitimate users.
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @date 2026
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 *
 * COMPLIANCE: SOC2, ISO 27001
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
#include <variant>
#include <memory>
#include <functional>
#include <chrono>
#include <atomic>
#include <mutex>
#include <shared_mutex>
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

#include "../Utils/Logger.hpp"
#include "../Utils/FileUtils.hpp"
#include "../Utils/ProcessUtils.hpp"
#include "../Utils/HashUtils.hpp"

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

namespace ShadowStrike::Ransomware {
    class HoneypotManagerImpl;
    class RansomwareDetector;
}

namespace ShadowStrike {
namespace Ransomware {

// ============================================================================
// COMPILE-TIME CONSTANTS
// ============================================================================

namespace HoneypotConstants {

    // ========================================================================
    // VERSION
    // ========================================================================
    
    inline constexpr uint32_t VERSION_MAJOR = 3;
    inline constexpr uint32_t VERSION_MINOR = 0;
    inline constexpr uint32_t VERSION_PATCH = 0;

    // ========================================================================
    // LIMITS
    // ========================================================================
    
    /// @brief Maximum honeypots per location
    inline constexpr size_t MAX_HONEYPOTS_PER_LOCATION = 10;
    
    /// @brief Maximum total honeypots
    inline constexpr size_t MAX_TOTAL_HONEYPOTS = 500;
    
    /// @brief Maximum honeypot file size
    inline constexpr size_t MAX_HONEYPOT_SIZE = 10 * 1024 * 1024;  // 10MB
    
    /// @brief Minimum honeypot file size
    inline constexpr size_t MIN_HONEYPOT_SIZE = 1024;  // 1KB

    // ========================================================================
    // TIMING
    // ========================================================================
    
    /// @brief Health check interval (seconds)
    inline constexpr uint32_t HEALTH_CHECK_INTERVAL_SECS = 300;  // 5 minutes
    
    /// @brief Regeneration cooldown (seconds)
    inline constexpr uint32_t REGENERATION_COOLDOWN_SECS = 60;

    // ========================================================================
    // FILE NAMES
    // ========================================================================
    
    /// @brief Default honeypot names
    inline constexpr const wchar_t* DEFAULT_NAMES[] = {
        L"Passwords.txt",
        L"Banking_Info.xlsx",
        L"Tax_Return_2025.pdf",
        L"Private_Keys.txt",
        L"Bitcoin_Wallet.dat",
        L"Family_Photos",
        L"Confidential_Report.docx",
        L"Medical_Records.pdf",
        L"SSN_Documents.docx"
    };

}  // namespace HoneypotConstants

// ============================================================================
// TYPE ALIASES
// ============================================================================

using Clock = std::chrono::steady_clock;
using TimePoint = std::chrono::steady_clock::time_point;
using SystemTimePoint = std::chrono::system_clock::time_point;
using Hash256 = std::array<uint8_t, 32>;

// ============================================================================
// ENUMERATIONS
// ============================================================================

/**
 * @brief Honeypot type
 */
enum class HoneypotType : uint8_t {
    File        = 0,    ///< Regular file
    Directory   = 1,    ///< Directory with files
    Shortcut    = 2,    ///< Shortcut/link
    Stream      = 3     ///< Alternate data stream
};

/**
 * @brief Honeypot file type
 */
enum class HoneypotFileType : uint8_t {
    Document    = 0,    ///< Office documents
    Spreadsheet = 1,    ///< Excel files
    Presentation= 2,    ///< PowerPoint files
    PDF         = 3,    ///< PDF files
    Image       = 4,    ///< Image files
    Database    = 5,    ///< Database files
    Text        = 6,    ///< Text files
    Archive     = 7,    ///< Archive files
    Crypto      = 8,    ///< Cryptocurrency wallets
    Password    = 9,    ///< Password files
    Config      = 10,   ///< Configuration files
    Source      = 11,   ///< Source code
    Custom      = 255   ///< Custom type
};

/**
 * @brief Honeypot location type
 */
enum class LocationType : uint8_t {
    UserDocuments   = 0,
    UserDesktop     = 1,
    UserPictures    = 2,
    UserDownloads   = 3,
    RootDrive       = 4,
    NetworkShare    = 5,
    CloudSync       = 6,
    Custom          = 7
};

/**
 * @brief Access type detected
 */
enum class HoneypotAccessType : uint8_t {
    Unknown     = 0,
    Read        = 1,
    Write       = 2,
    Delete      = 3,
    Rename      = 4,
    Enumerate   = 5,
    SetInfo     = 6
};

/**
 * @brief Honeypot status
 */
enum class HoneypotStatus : uint8_t {
    Active      = 0,    ///< Honeypot is active
    Inactive    = 1,    ///< Honeypot is inactive
    Missing     = 2,    ///< Honeypot file missing
    Modified    = 3,    ///< Honeypot was modified
    Compromised = 4,    ///< Honeypot was accessed by malware
    Disabled    = 5     ///< Honeypot disabled
};

/**
 * @brief Module status
 */
enum class ModuleStatus : uint8_t {
    Uninitialized   = 0,
    Initializing    = 1,
    Running         = 2,
    Degraded        = 3,
    Paused          = 4,
    Stopping        = 5,
    Stopped         = 6,
    Error           = 7
};

// ============================================================================
// STRUCTURES
// ============================================================================

/**
 * @brief Honeypot file information
 */
struct HoneyFile {
    /// @brief Honeypot ID
    std::string honeypotId;
    
    /// @brief File path
    std::wstring path;
    
    /// @brief Original name (for regeneration)
    std::wstring originalName;
    
    /// @brief Honeypot type
    HoneypotType type = HoneypotType::File;
    
    /// @brief File type
    HoneypotFileType fileType = HoneypotFileType::Document;
    
    /// @brief Location type
    LocationType location = LocationType::UserDocuments;
    
    /// @brief Status
    HoneypotStatus status = HoneypotStatus::Active;
    
    /// @brief File size
    uint64_t fileSize = 0;
    
    /// @brief Content hash
    Hash256 contentHash{};
    
    /// @brief Creation time
    SystemTimePoint creationTime;
    
    /// @brief Last verification time
    TimePoint lastVerified;
    
    /// @brief Last access time (by us)
    TimePoint lastAccessed;
    
    /// @brief Is directory
    bool isDirectory = false;
    
    /// @brief Is hidden
    bool isHidden = true;
    
    /// @brief Is system file
    bool isSystem = false;
    
    /// @brief Auto-regenerate on deletion
    bool autoRegenerate = true;
    
    /**
     * @brief Serialize to JSON
     */
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Honeypot access event
 */
struct HoneypotAccessEvent {
    /// @brief Event ID
    uint64_t eventId = 0;
    
    /// @brief Timestamp
    SystemTimePoint timestamp;
    
    /// @brief Honeypot ID
    std::string honeypotId;
    
    /// @brief Honeypot path
    std::wstring honeypotPath;
    
    /// @brief Accessing process ID
    uint32_t processId = 0;
    
    /// @brief Accessing process name
    std::wstring processName;
    
    /// @brief Process path
    std::wstring processPath;
    
    /// @brief Process command line
    std::wstring commandLine;
    
    /// @brief Parent process ID
    uint32_t parentPid = 0;
    
    /// @brief Access type
    HoneypotAccessType accessType = HoneypotAccessType::Unknown;
    
    /// @brief User SID
    std::wstring userSid;
    
    /// @brief User name
    std::wstring userName;
    
    /// @brief Is suspicious
    bool isSuspicious = true;
    
    /// @brief Action taken
    std::string actionTaken;
    
    /// @brief Additional details
    std::wstring details;
    
    /**
     * @brief Serialize to JSON
     */
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Honeypot template
 */
struct HoneypotTemplate {
    /// @brief Template name
    std::string templateName;
    
    /// @brief File type
    HoneypotFileType fileType = HoneypotFileType::Document;
    
    /// @brief Filename patterns
    std::vector<std::wstring> filenamePatterns;
    
    /// @brief File extension
    std::wstring extension;
    
    /// @brief Magic bytes (file header)
    std::vector<uint8_t> magicBytes;
    
    /// @brief Content template
    std::vector<uint8_t> contentTemplate;
    
    /// @brief Minimum size
    size_t minSize = HoneypotConstants::MIN_HONEYPOT_SIZE;
    
    /// @brief Maximum size
    size_t maxSize = HoneypotConstants::MAX_HONEYPOT_SIZE;
    
    /// @brief Randomize content
    bool randomizeContent = true;
    
    /// @brief Include realistic metadata
    bool includeMetadata = true;
};

/**
 * @brief Deployment location
 */
struct DeploymentLocation {
    /// @brief Location type
    LocationType type = LocationType::UserDocuments;
    
    /// @brief Directory path
    std::wstring path;
    
    /// @brief Is enabled
    bool isEnabled = true;
    
    /// @brief Maximum honeypots here
    size_t maxHoneypots = HoneypotConstants::MAX_HONEYPOTS_PER_LOCATION;
    
    /// @brief Current honeypot count
    size_t currentCount = 0;
    
    /// @brief Priority (higher = deploy first)
    uint8_t priority = 5;
};

/**
 * @brief Honeypot configuration
 */
struct HoneypotManagerConfiguration {
    /// @brief Enable honeypot system
    bool enabled = true;
    
    /// @brief Deployment locations
    std::vector<DeploymentLocation> locations;
    
    /// @brief Templates to use
    std::vector<HoneypotTemplate> templates;
    
    /// @brief Auto-deploy on startup
    bool autoDeployOnStartup = true;
    
    /// @brief Auto-regenerate deleted honeypots
    bool autoRegenerate = true;
    
    /// @brief Health check interval (seconds)
    uint32_t healthCheckIntervalSecs = HoneypotConstants::HEALTH_CHECK_INTERVAL_SECS;
    
    /// @brief Make files hidden
    bool hideFiles = true;
    
    /// @brief Make files system files
    bool makeSystemFiles = false;
    
    /// @brief Kill process on access
    bool killOnAccess = true;
    
    /// @brief Collect forensic data
    bool collectForensics = true;
    
    /// @brief Alert on enumeration
    bool alertOnEnumeration = false;
    
    /// @brief Maximum total honeypots
    size_t maxTotalHoneypots = HoneypotConstants::MAX_TOTAL_HONEYPOTS;
    
    /// @brief Configuration file path
    std::wstring configPath;
    
    /// @brief Verbose logging
    bool verboseLogging = false;
    
    /**
     * @brief Validate configuration
     */
    [[nodiscard]] bool IsValid() const noexcept;
    
    /**
     * @brief Load default locations
     */
    void LoadDefaultLocations();
    
    /**
     * @brief Load default templates
     */
    void LoadDefaultTemplates();
};

/**
 * @brief Honeypot statistics
 */
struct HoneypotStatistics {
    /// @brief Total honeypots deployed
    std::atomic<uint64_t> totalDeployed{0};
    
    /// @brief Currently active
    std::atomic<uint64_t> currentlyActive{0};
    
    /// @brief Access events
    std::atomic<uint64_t> accessEvents{0};
    
    /// @brief Processes killed
    std::atomic<uint64_t> processesKilled{0};
    
    /// @brief Regenerations
    std::atomic<uint64_t> regenerations{0};
    
    /// @brief False positives
    std::atomic<uint64_t> falsePositives{0};
    
    /// @brief Events by access type
    std::array<std::atomic<uint64_t>, 8> eventsByType{};
    
    /// @brief Start time
    TimePoint startTime = Clock::now();
    
    /**
     * @brief Reset statistics
     */
    void Reset() noexcept;
    
    /**
     * @brief Serialize to JSON
     */
    [[nodiscard]] std::string ToJson() const;
};

// ============================================================================
// CALLBACK TYPES
// ============================================================================

/// @brief Access callback
using HoneypotAccessCallback = std::function<void(const HoneypotAccessEvent&)>;

/// @brief Status callback
using HoneypotStatusCallback = std::function<void(const HoneyFile&, HoneypotStatus)>;

// ============================================================================
// HONEYPOT MANAGER CLASS
// ============================================================================

/**
 * @class HoneypotManager
 * @brief Enterprise-grade honeypot management system
 *
 * Provides strategic deployment and monitoring of decoy files
 * for instant ransomware detection.
 *
 * THREAD SAFETY: All public methods are thread-safe.
 *
 * USAGE:
 * @code
 *     auto& honeypot = HoneypotManager::Instance();
 *     honeypot.DeployTraps();
 *     
 *     // Fast lookup during file operations
 *     if (honeypot.IsTrap(filePath)) {
 *         // ALERT! Ransomware detected
 *     }
 * @endcode
 */
class HoneypotManager final {
public:
    // ========================================================================
    // SINGLETON ACCESS
    // ========================================================================
    
    /**
     * @brief Get singleton instance
     */
    [[nodiscard]] static HoneypotManager& Instance() noexcept;
    
    /**
     * @brief Check if instance exists
     */
    [[nodiscard]] static bool HasInstance() noexcept;
    
    // Non-copyable, non-movable
    HoneypotManager(const HoneypotManager&) = delete;
    HoneypotManager& operator=(const HoneypotManager&) = delete;
    HoneypotManager(HoneypotManager&&) = delete;
    HoneypotManager& operator=(HoneypotManager&&) = delete;

    // ========================================================================
    // LIFECYCLE MANAGEMENT
    // ========================================================================
    
    /**
     * @brief Initialize honeypot manager
     */
    [[nodiscard]] bool Initialize(const HoneypotManagerConfiguration& config = {});
    
    /**
     * @brief Shutdown honeypot manager
     */
    void Shutdown();
    
    /**
     * @brief Check if initialized
     */
    [[nodiscard]] bool IsInitialized() const noexcept;
    
    /**
     * @brief Get current status
     */
    [[nodiscard]] ModuleStatus GetStatus() const noexcept;
    
    // ========================================================================
    // DEPLOYMENT
    // ========================================================================
    
    /**
     * @brief Deploy honeyfiles to strategic locations
     * @return True if deployment successful
     */
    [[nodiscard]] bool DeployTraps();
    
    /**
     * @brief Deploy to specific location
     */
    [[nodiscard]] bool DeployToLocation(const DeploymentLocation& location);
    
    /**
     * @brief Deploy single honeypot
     */
    [[nodiscard]] std::optional<std::string> DeployHoneypot(
        std::wstring_view directory, const HoneypotTemplate& tmpl);
    
    /**
     * @brief Remove all honeyfiles
     */
    void RemoveTraps();
    
    /**
     * @brief Remove specific honeypot
     */
    void RemoveHoneypot(const std::string& honeypotId);
    
    /**
     * @brief Remove honeypot by path
     */
    void RemoveHoneypotByPath(std::wstring_view path);
    
    // ========================================================================
    // TRAP DETECTION
    // ========================================================================
    
    /**
     * @brief Check if a given path is a known honeyfile
     * Fast O(1) lookup for use in file system filter
     */
    [[nodiscard]] bool IsTrap(const std::wstring& filePath) const;
    
    /**
     * @brief Check if path is a trap (string_view version)
     */
    [[nodiscard]] bool IsTrap(std::wstring_view filePath) const;
    
    /**
     * @brief Get honeypot by path
     */
    [[nodiscard]] std::optional<HoneyFile> GetHoneypot(std::wstring_view path) const;
    
    /**
     * @brief Get honeypot by ID
     */
    [[nodiscard]] std::optional<HoneyFile> GetHoneypotById(
        const std::string& honeypotId) const;
    
    /**
     * @brief Get all active honeypots
     */
    [[nodiscard]] std::vector<HoneyFile> GetActiveHoneypots() const;
    
    /**
     * @brief Get honeypots in directory
     */
    [[nodiscard]] std::vector<HoneyFile> GetHoneypotsInDirectory(
        std::wstring_view directory) const;
    
    // ========================================================================
    // REGENERATION
    // ========================================================================
    
    /**
     * @brief Regenerate a trap if it was deleted
     */
    void RegenerateTrap(const std::wstring& filePath);
    
    /**
     * @brief Regenerate by ID
     */
    void RegenerateTrap(const std::string& honeypotId);
    
    /**
     * @brief Regenerate all missing honeypots
     */
    void RegenerateAllMissing();
    
    // ========================================================================
    // HEALTH CHECKS
    // ========================================================================
    
    /**
     * @brief Verify honeypot integrity
     */
    [[nodiscard]] bool VerifyHoneypot(const std::string& honeypotId);
    
    /**
     * @brief Verify all honeypots
     */
    [[nodiscard]] std::vector<std::string> VerifyAllHoneypots();
    
    /**
     * @brief Run health check
     */
    void RunHealthCheck();
    
    // ========================================================================
    // ACCESS HANDLING
    // ========================================================================
    
    /**
     * @brief Called when honeypot is accessed
     */
    void OnHoneypotAccessed(std::wstring_view path, uint32_t pid,
                           HoneypotAccessType accessType);
    
    /**
     * @brief Report false positive
     */
    void ReportFalsePositive(uint64_t eventId, const std::string& reason);
    
    /**
     * @brief Get recent access events
     */
    [[nodiscard]] std::vector<HoneypotAccessEvent> GetRecentAccessEvents(
        size_t maxCount = 100) const;
    
    // ========================================================================
    // CALLBACKS
    // ========================================================================
    
    /**
     * @brief Set access callback
     */
    void SetAccessCallback(HoneypotAccessCallback callback);
    
    /**
     * @brief Set status callback
     */
    void SetStatusCallback(HoneypotStatusCallback callback);
    
    // ========================================================================
    // STATISTICS
    // ========================================================================
    
    /**
     * @brief Get statistics
     */
    [[nodiscard]] HoneypotStatistics GetStatistics() const;
    
    /**
     * @brief Reset statistics
     */
    void ResetStatistics();
    
    /**
     * @brief Get honeypot count
     */
    [[nodiscard]] size_t GetHoneypotCount() const noexcept;
    
    /**
     * @brief Get active honeypot count
     */
    [[nodiscard]] size_t GetActiveHoneypotCount() const noexcept;
    
    // ========================================================================
    // TEMPLATES
    // ========================================================================
    
    /**
     * @brief Add template
     */
    void AddTemplate(const HoneypotTemplate& tmpl);
    
    /**
     * @brief Remove template
     */
    void RemoveTemplate(const std::string& templateName);
    
    /**
     * @brief Get templates
     */
    [[nodiscard]] std::vector<HoneypotTemplate> GetTemplates() const;
    
    // ========================================================================
    // UTILITY
    // ========================================================================
    
    /**
     * @brief Create decoy file with specified type
     */
    void CreateDecoyFile(std::wstring_view path, HoneypotFileType type);
    
    /**
     * @brief Self-test
     */
    [[nodiscard]] bool SelfTest();
    
    /**
     * @brief Get version string
     */
    [[nodiscard]] static std::string GetVersionString() noexcept;

private:
    // ========================================================================
    // PRIVATE CONSTRUCTOR
    // ========================================================================
    
    HoneypotManager();
    ~HoneypotManager();
    
    // ========================================================================
    // PIMPL
    // ========================================================================
    
    std::unique_ptr<HoneypotManagerImpl> m_impl;
    
    // ========================================================================
    // STATIC INSTANCE FLAG
    // ========================================================================
    
    static std::atomic<bool> s_instanceCreated;
};

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

/**
 * @brief Get honeypot type name
 */
[[nodiscard]] std::string_view GetHoneypotTypeName(HoneypotType type) noexcept;

/**
 * @brief Get file type name
 */
[[nodiscard]] std::string_view GetHoneypotFileTypeName(HoneypotFileType type) noexcept;

/**
 * @brief Get location type name
 */
[[nodiscard]] std::string_view GetLocationTypeName(LocationType type) noexcept;

/**
 * @brief Get access type name
 */
[[nodiscard]] std::string_view GetAccessTypeName(HoneypotAccessType type) noexcept;

/**
 * @brief Get honeypot status name
 */
[[nodiscard]] std::string_view GetHoneypotStatusName(HoneypotStatus status) noexcept;

/**
 * @brief Get default template for file type
 */
[[nodiscard]] HoneypotTemplate GetDefaultTemplate(HoneypotFileType type);

/**
 * @brief Generate realistic filename
 */
[[nodiscard]] std::wstring GenerateHoneypotFilename(HoneypotFileType type);

}  // namespace Ransomware
}  // namespace ShadowStrike

// ============================================================================
// MACROS
// ============================================================================

/**
 * @brief Check if path is honeypot
 */
#define SS_IS_HONEYPOT(path) \
    ::ShadowStrike::Ransomware::HoneypotManager::Instance().IsTrap(path)

/**
 * @brief Deploy honeypots
 */
#define SS_DEPLOY_HONEYPOTS() \
    ::ShadowStrike::Ransomware::HoneypotManager::Instance().DeployTraps()
