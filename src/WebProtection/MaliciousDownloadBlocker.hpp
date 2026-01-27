/**
 * ============================================================================
 * ShadowStrike NGAV - MALICIOUS DOWNLOAD BLOCKER MODULE
 * ============================================================================
 *
 * @file MaliciousDownloadBlocker.hpp
 * @brief Enterprise-grade download protection with real-time scanning,
 *        reputation checking, and sandbox analysis for downloaded files.
 *
 * Provides comprehensive download protection including file scanning, reputation
 * checking, extension verification, and sandbox detonation for zero-day threats.
 *
 * PROTECTION CAPABILITIES:
 * ========================
 *
 * 1. DOWNLOAD MONITORING
 *    - Browser download interception
 *    - Download folder watching
 *    - Partial file monitoring
 *    - Resume detection
 *    - Network stream scanning
 *
 * 2. FILE ANALYSIS
 *    - Signature scanning
 *    - Heuristic analysis
 *    - Machine learning classification
 *    - Static PE analysis
 *    - Macro detection
 *    - Archive inspection
 *
 * 3. REPUTATION CHECKING
 *    - File hash reputation
 *    - URL source reputation
 *    - Publisher verification
 *    - Certificate validation
 *    - First-seen analysis
 *
 * 4. SANDBOX ANALYSIS
 *    - Behavioral analysis
 *    - API monitoring
 *    - Network activity
 *    - File system changes
 *    - Registry modifications
 *
 * 5. POLICY ENFORCEMENT
 *    - File type blocking
 *    - Extension whitelist/blacklist
 *    - Size limits
 *    - Source restrictions
 *
 * INTEGRATION:
 * ============
 * - SignatureStore for malware signatures
 * - HashStore for known-bad hashes
 * - ThreatIntel for reputation data
 * - SafeBrowsingAPI for URL checks
 *
 * @note Monitors multiple download locations.
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
#include <queue>
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
#include "../Utils/StringUtils.hpp"
#include "../Utils/FileUtils.hpp"
#include "../Utils/CryptoUtils.hpp"
#include "../HashStore/HashStore.hpp"
#include "../SignatureStore/SignatureStore.hpp"
#include "../ThreatIntel/ThreatIntelManager.hpp"
#include "../Whitelist/WhiteListStore.hpp"

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

namespace ShadowStrike::WebBrowser {
    class MaliciousDownloadBlockerImpl;
    class SafeBrowsingAPI;
}

namespace ShadowStrike {
namespace WebBrowser {

// ============================================================================
// COMPILE-TIME CONSTANTS
// ============================================================================

namespace DownloadBlockerConstants {

    inline constexpr uint32_t VERSION_MAJOR = 3;
    inline constexpr uint32_t VERSION_MINOR = 0;
    inline constexpr uint32_t VERSION_PATCH = 0;

    /// @brief Maximum file size to scan
    inline constexpr size_t MAX_SCAN_SIZE = 500 * 1024 * 1024;  // 500MB
    
    /// @brief Sandbox timeout
    inline constexpr uint32_t SANDBOX_TIMEOUT_MS = 60000;  // 60 seconds
    
    /// @brief Default scan timeout
    inline constexpr uint32_t DEFAULT_SCAN_TIMEOUT_MS = 30000;
    
    /// @brief Queue size
    inline constexpr size_t DEFAULT_QUEUE_SIZE = 1000;

    /// @brief High-risk extensions
    inline constexpr const char* HIGH_RISK_EXTENSIONS[] = {
        ".exe", ".com", ".bat", ".cmd", ".ps1", ".vbs", ".js",
        ".jse", ".wsh", ".wsf", ".scr", ".hta", ".pif", ".reg",
        ".msi", ".msp", ".dll", ".cpl", ".jar", ".lnk", ".inf"
    };

    /// @brief Archive extensions requiring deep scan
    inline constexpr const char* ARCHIVE_EXTENSIONS[] = {
        ".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".xz",
        ".cab", ".iso", ".img", ".arj", ".lzh", ".ace"
    };

    /// @brief Document extensions with potential macros
    inline constexpr const char* MACRO_EXTENSIONS[] = {
        ".doc", ".docm", ".xls", ".xlsm", ".ppt", ".pptm",
        ".dotm", ".xlsb", ".mdb", ".accdb", ".rtf"
    };

}  // namespace DownloadBlockerConstants

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
 * @brief Download scan verdict
 */
enum class DownloadVerdict : uint8_t {
    Safe            = 0,    ///< File is safe
    Clean           = 1,    ///< No threats found
    Suspicious      = 2,    ///< Suspicious characteristics
    Malware         = 3,    ///< Malware detected
    PUP             = 4,    ///< Potentially Unwanted Program
    Ransomware      = 5,    ///< Ransomware detected
    Trojan          = 6,    ///< Trojan detected
    Worm            = 7,    ///< Worm detected
    Rootkit         = 8,    ///< Rootkit detected
    Blocked         = 9,    ///< Blocked by policy
    Unknown         = 10,   ///< Cannot determine
    Error           = 255   ///< Scan error
};

/**
 * @brief Download action
 */
enum class DownloadAction : uint8_t {
    Allow           = 0,    ///< Allow download
    Block           = 1,    ///< Block and delete
    Quarantine      = 2,    ///< Move to quarantine
    Warn            = 3,    ///< Warn user
    Sandbox         = 4,    ///< Analyze in sandbox
    Defer           = 5,    ///< Defer decision
    Rename          = 6     ///< Rename to safe extension
};

/**
 * @brief Download status
 */
enum class DownloadStatus : uint8_t {
    Pending         = 0,    ///< Waiting to be scanned
    Scanning        = 1,    ///< Being scanned
    Sandboxing      = 2,    ///< In sandbox analysis
    Completed       = 3,    ///< Scan completed
    Allowed         = 4,    ///< Download allowed
    Blocked         = 5,    ///< Download blocked
    Quarantined     = 6,    ///< Moved to quarantine
    Error           = 7     ///< Scan error
};

/**
 * @brief Risk level
 */
enum class RiskLevel : uint8_t {
    None            = 0,
    Low             = 1,
    Medium          = 2,
    High            = 3,
    Critical        = 4
};

/**
 * @brief Threat indicator
 */
enum class ThreatIndicator : uint32_t {
    None                    = 0,
    KnownMalware            = 1 << 0,
    SignatureMatch          = 1 << 1,
    HeuristicMatch          = 1 << 2,
    MLClassification        = 1 << 3,
    BadReputation           = 1 << 4,
    NewFile                 = 1 << 5,
    UnsignedExecutable      = 1 << 6,
    InvalidSignature        = 1 << 7,
    RevokedCertificate      = 1 << 8,
    SuspiciousImports       = 1 << 9,
    PackedExecutable        = 1 << 10,
    HiddenExtension         = 1 << 11,
    DoubleExtension         = 1 << 12,
    TypeMismatch            = 1 << 13,
    SuspiciousMacro         = 1 << 14,
    EncryptedArchive        = 1 << 15,
    BadSourceURL            = 1 << 16,
    SandboxDetection        = 1 << 17,
    NetworkActivity         = 1 << 18,
    PersistenceMechanism    = 1 << 19
};

/**
 * @brief Module status
 */
enum class ModuleStatus : uint8_t {
    Uninitialized   = 0,
    Initializing    = 1,
    Running         = 2,
    Scanning        = 3,
    Paused          = 4,
    Stopping        = 5,
    Stopped         = 6,
    Error           = 7
};

// ============================================================================
// STRUCTURES
// ============================================================================

/**
 * @brief Download information
 */
struct DownloadInfo {
    /// @brief Download ID
    std::string downloadId;
    
    /// @brief File path
    fs::path filePath;
    
    /// @brief Original filename
    std::string originalFilename;
    
    /// @brief Source URL
    std::string sourceUrl;
    
    /// @brief Referrer URL
    std::string referrerUrl;
    
    /// @brief MIME type
    std::string mimeType;
    
    /// @brief File size
    size_t fileSize = 0;
    
    /// @brief File extension
    std::string extension;
    
    /// @brief Browser process ID
    uint32_t browserPid = 0;
    
    /// @brief Browser name
    std::string browserName;
    
    /// @brief SHA-256 hash
    std::string sha256;
    
    /// @brief MD5 hash
    std::string md5;
    
    /// @brief SHA-1 hash
    std::string sha1;
    
    /// @brief Download start time
    SystemTimePoint startTime;
    
    /// @brief Download complete time
    SystemTimePoint completeTime;
    
    /// @brief Content-Disposition header
    std::string contentDisposition;
    
    /// @brief Server
    std::string server;
    
    /// @brief Is partial download
    bool isPartial = false;
    
    /// @brief Is resumed download
    bool isResumed = false;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief File analysis result
 */
struct FileAnalysisResult {
    /// @brief Detected file type (magic)
    std::string detectedType;
    
    /// @brief MIME type
    std::string mimeType;
    
    /// @brief Extension matches type
    bool extensionMatches = true;
    
    /// @brief Is executable
    bool isExecutable = false;
    
    /// @brief Is archive
    bool isArchive = false;
    
    /// @brief Is document
    bool isDocument = false;
    
    /// @brief Has macros
    bool hasMacros = false;
    
    /// @brief Is packed/compressed
    bool isPacked = false;
    
    /// @brief Packer name
    std::string packerName;
    
    /// @brief Has digital signature
    bool hasSignature = false;
    
    /// @brief Signature valid
    bool signatureValid = false;
    
    /// @brief Publisher name
    std::string publisher;
    
    /// @brief Certificate issuer
    std::string certificateIssuer;
    
    /// @brief Certificate valid from
    SystemTimePoint certValidFrom;
    
    /// @brief Certificate valid to
    SystemTimePoint certValidTo;
    
    /// @brief Entropy
    double entropy = 0.0;
    
    /// @brief Import count (for PE)
    size_t importCount = 0;
    
    /// @brief Suspicious imports
    std::vector<std::string> suspiciousImports;
    
    /// @brief Embedded files (if archive)
    std::vector<std::string> embeddedFiles;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Reputation result
 */
struct ReputationResult {
    /// @brief Hash reputation score (0-100)
    int hashReputation = 50;
    
    /// @brief URL reputation score (0-100)
    int urlReputation = 50;
    
    /// @brief Publisher reputation
    int publisherReputation = 50;
    
    /// @brief Is known file
    bool isKnownFile = false;
    
    /// @brief Is known malware
    bool isKnownMalware = false;
    
    /// @brief Is whitelisted
    bool isWhitelisted = false;
    
    /// @brief First seen date
    SystemTimePoint firstSeen;
    
    /// @brief Prevalence (how common)
    int prevalence = 0;
    
    /// @brief Detection count (VirusTotal style)
    int detectionCount = 0;
    
    /// @brief Total engines
    int totalEngines = 0;
    
    /// @brief Detection names
    std::vector<std::string> detectionNames;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Sandbox result
 */
struct SandboxResult {
    /// @brief Was sandboxed
    bool wasSandboxed = false;
    
    /// @brief Sandbox verdict
    DownloadVerdict verdict = DownloadVerdict::Unknown;
    
    /// @brief Sandbox score (0-100)
    int sandboxScore = 0;
    
    /// @brief Behaviors observed
    std::vector<std::string> behaviors;
    
    /// @brief Network connections
    std::vector<std::string> networkConnections;
    
    /// @brief Files created
    std::vector<std::string> filesCreated;
    
    /// @brief Registry modifications
    std::vector<std::string> registryMods;
    
    /// @brief Processes spawned
    std::vector<std::string> processesSpawned;
    
    /// @brief Analysis duration
    std::chrono::milliseconds analysisDuration{0};
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Download scan result
 */
struct DownloadScanResult {
    /// @brief Download ID
    std::string downloadId;
    
    /// @brief File path
    fs::path filePath;
    
    /// @brief Verdict
    DownloadVerdict verdict = DownloadVerdict::Unknown;
    
    /// @brief Action taken
    DownloadAction action = DownloadAction::Allow;
    
    /// @brief Status
    DownloadStatus status = DownloadStatus::Pending;
    
    /// @brief Is clean
    bool isClean = true;
    
    /// @brief Should block
    bool shouldBlock = false;
    
    /// @brief Risk level
    RiskLevel riskLevel = RiskLevel::None;
    
    /// @brief Risk score (0-100)
    int riskScore = 0;
    
    /// @brief Threat indicators (bitmask)
    ThreatIndicator indicators = ThreatIndicator::None;
    
    /// @brief Threat name
    std::string threatName;
    
    /// @brief Threat family
    std::string threatFamily;
    
    /// @brief File analysis
    FileAnalysisResult fileAnalysis;
    
    /// @brief Reputation result
    ReputationResult reputation;
    
    /// @brief Sandbox result
    SandboxResult sandbox;
    
    /// @brief Matched signatures
    std::vector<std::string> matchedSignatures;
    
    /// @brief Heuristic detections
    std::vector<std::string> heuristicDetections;
    
    /// @brief Scan duration
    std::chrono::microseconds scanDuration{0};
    
    /// @brief Scan timestamp
    SystemTimePoint scanTimestamp;
    
    /// @brief User notification shown
    bool userNotified = false;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Statistics
 */
struct DownloadBlockerStatistics {
    std::atomic<uint64_t> totalDownloads{0};
    std::atomic<uint64_t> scannedDownloads{0};
    std::atomic<uint64_t> cleanDownloads{0};
    std::atomic<uint64_t> blockedDownloads{0};
    std::atomic<uint64_t> quarantinedDownloads{0};
    std::atomic<uint64_t> malwareDetected{0};
    std::atomic<uint64_t> pupDetected{0};
    std::atomic<uint64_t> suspiciousDetected{0};
    std::atomic<uint64_t> sandboxedFiles{0};
    std::atomic<uint64_t> signatureMatches{0};
    std::atomic<uint64_t> heuristicMatches{0};
    std::atomic<uint64_t> reputationBlocks{0};
    std::atomic<uint64_t> policyBlocks{0};
    std::atomic<uint64_t> scanErrors{0};
    std::atomic<uint64_t> bytesScanned{0};
    std::array<std::atomic<uint64_t>, 16> byVerdict{};
    std::array<std::atomic<uint64_t>, 32> byIndicator{};
    TimePoint startTime = Clock::now();
    
    void Reset() noexcept;
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Configuration
 */
struct DownloadBlockerConfiguration {
    /// @brief Enable blocker
    bool enabled = true;
    
    /// @brief Enable signature scanning
    bool enableSignatureScanning = true;
    
    /// @brief Enable heuristic scanning
    bool enableHeuristicScanning = true;
    
    /// @brief Enable reputation checking
    bool enableReputationChecking = true;
    
    /// @brief Enable sandbox analysis
    bool enableSandbox = false;
    
    /// @brief Enable archive scanning
    bool enableArchiveScanning = true;
    
    /// @brief Enable macro analysis
    bool enableMacroAnalysis = true;
    
    /// @brief Block high-risk extensions
    bool blockHighRiskExtensions = false;
    
    /// @brief Block unsigned executables
    bool blockUnsignedExecutables = false;
    
    /// @brief Block new files (first-seen)
    bool blockNewFiles = false;
    
    /// @brief New file threshold (hours)
    int newFileThresholdHours = 24;
    
    /// @brief Maximum scan size
    size_t maxScanSize = DownloadBlockerConstants::MAX_SCAN_SIZE;
    
    /// @brief Scan timeout
    uint32_t scanTimeoutMs = DownloadBlockerConstants::DEFAULT_SCAN_TIMEOUT_MS;
    
    /// @brief Sandbox timeout
    uint32_t sandboxTimeoutMs = DownloadBlockerConstants::SANDBOX_TIMEOUT_MS;
    
    /// @brief Blocked extensions
    std::vector<std::string> blockedExtensions;
    
    /// @brief Allowed extensions (whitelist)
    std::vector<std::string> allowedExtensions;
    
    /// @brief Monitored directories
    std::vector<fs::path> monitoredDirectories;
    
    /// @brief Quarantine path
    fs::path quarantinePath;
    
    /// @brief Show user notification
    bool showNotification = true;
    
    /// @brief Allow user override
    bool allowUserOverride = false;
    
    /// @brief Verbose logging
    bool verboseLogging = false;
    
    [[nodiscard]] bool IsValid() const noexcept;
};

// ============================================================================
// CALLBACK TYPES
// ============================================================================

using ScanResultCallback = std::function<void(const DownloadScanResult&)>;
using DownloadBlockedCallback = std::function<void(const DownloadInfo&, const DownloadScanResult&)>;
using SandboxCompleteCallback = std::function<void(const std::string& downloadId, const SandboxResult&)>;
using ErrorCallback = std::function<void(const std::string& message, int code)>;

/// @brief Pre-download callback (return false to block)
using PreDownloadCallback = std::function<bool(const DownloadInfo&)>;

// ============================================================================
// MALICIOUS DOWNLOAD BLOCKER CLASS
// ============================================================================

/**
 * @class MaliciousDownloadBlocker
 * @brief Enterprise download protection engine
 */
class MaliciousDownloadBlocker final {
public:
    [[nodiscard]] static MaliciousDownloadBlocker& Instance() noexcept;
    [[nodiscard]] static bool HasInstance() noexcept;
    
    MaliciousDownloadBlocker(const MaliciousDownloadBlocker&) = delete;
    MaliciousDownloadBlocker& operator=(const MaliciousDownloadBlocker&) = delete;
    MaliciousDownloadBlocker(MaliciousDownloadBlocker&&) = delete;
    MaliciousDownloadBlocker& operator=(MaliciousDownloadBlocker&&) = delete;

    // ========================================================================
    // LIFECYCLE
    // ========================================================================
    
    [[nodiscard]] bool Initialize(const DownloadBlockerConfiguration& config = {});
    void Shutdown();
    [[nodiscard]] bool IsInitialized() const noexcept;
    [[nodiscard]] ModuleStatus GetStatus() const noexcept;
    
    [[nodiscard]] bool UpdateConfiguration(const DownloadBlockerConfiguration& config);
    [[nodiscard]] DownloadBlockerConfiguration GetConfiguration() const;

    // ========================================================================
    // DOWNLOAD EVENTS
    // ========================================================================
    
    /// @brief Handle download complete event
    void OnDownloadComplete(const std::wstring& filePath, const std::string& sourceUrl);
    
    /// @brief Handle download complete (extended)
    void OnDownloadComplete(const DownloadInfo& download);
    
    /// @brief Handle download start (for pre-filtering)
    [[nodiscard]] bool OnDownloadStart(const DownloadInfo& download);

    // ========================================================================
    // SCANNING
    // ========================================================================
    
    /// @brief Scan downloaded file
    [[nodiscard]] DownloadScanResult ScanFile(const fs::path& filePath);
    
    /// @brief Scan file with source info
    [[nodiscard]] DownloadScanResult ScanFile(
        const fs::path& filePath,
        const std::string& sourceUrl);
    
    /// @brief Scan asynchronously
    [[nodiscard]] std::future<DownloadScanResult> ScanFileAsync(
        const fs::path& filePath,
        const std::string& sourceUrl = "");
    
    /// @brief Quick reputation check
    [[nodiscard]] int GetFileReputation(const fs::path& filePath);
    
    /// @brief Check if extension is blocked
    [[nodiscard]] bool IsExtensionBlocked(const std::string& extension) const;

    // ========================================================================
    // MONITORING
    // ========================================================================
    
    /// @brief Start monitoring download directories
    [[nodiscard]] bool StartMonitoring();
    
    /// @brief Stop monitoring
    void StopMonitoring();
    
    /// @brief Is monitoring active
    [[nodiscard]] bool IsMonitoring() const noexcept;
    
    /// @brief Add directory to monitor
    [[nodiscard]] bool AddMonitoredDirectory(const fs::path& directory);
    
    /// @brief Remove directory from monitoring
    [[nodiscard]] bool RemoveMonitoredDirectory(const fs::path& directory);
    
    /// @brief Get monitored directories
    [[nodiscard]] std::vector<fs::path> GetMonitoredDirectories() const;

    // ========================================================================
    // SANDBOX
    // ========================================================================
    
    /// @brief Submit file to sandbox
    [[nodiscard]] std::future<SandboxResult> SubmitToSandbox(const fs::path& filePath);
    
    /// @brief Get sandbox result
    [[nodiscard]] std::optional<SandboxResult> GetSandboxResult(
        const std::string& downloadId);

    // ========================================================================
    // QUARANTINE
    // ========================================================================
    
    /// @brief Quarantine file
    [[nodiscard]] bool QuarantineFile(const fs::path& filePath);
    
    /// @brief Restore from quarantine
    [[nodiscard]] bool RestoreFromQuarantine(const std::string& quarantineId);
    
    /// @brief Delete from quarantine
    [[nodiscard]] bool DeleteFromQuarantine(const std::string& quarantineId);

    // ========================================================================
    // POLICY
    // ========================================================================
    
    /// @brief Add blocked extension
    [[nodiscard]] bool AddBlockedExtension(const std::string& extension);
    
    /// @brief Remove blocked extension
    [[nodiscard]] bool RemoveBlockedExtension(const std::string& extension);
    
    /// @brief Add allowed extension
    [[nodiscard]] bool AddAllowedExtension(const std::string& extension);

    // ========================================================================
    // CALLBACKS
    // ========================================================================
    
    void RegisterScanCallback(ScanResultCallback callback);
    void RegisterBlockedCallback(DownloadBlockedCallback callback);
    void RegisterSandboxCallback(SandboxCompleteCallback callback);
    void RegisterPreDownloadCallback(PreDownloadCallback callback);
    void RegisterErrorCallback(ErrorCallback callback);
    void UnregisterCallbacks();

    // ========================================================================
    // STATISTICS
    // ========================================================================
    
    [[nodiscard]] DownloadBlockerStatistics GetStatistics() const;
    void ResetStatistics();
    
    [[nodiscard]] bool SelfTest();
    [[nodiscard]] static std::string GetVersionString() noexcept;

private:
    MaliciousDownloadBlocker();
    ~MaliciousDownloadBlocker();
    
    std::unique_ptr<MaliciousDownloadBlockerImpl> m_impl;
    static std::atomic<bool> s_instanceCreated;
};

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

[[nodiscard]] std::string_view GetDownloadVerdictName(DownloadVerdict verdict) noexcept;
[[nodiscard]] std::string_view GetDownloadActionName(DownloadAction action) noexcept;
[[nodiscard]] std::string_view GetDownloadStatusName(DownloadStatus status) noexcept;
[[nodiscard]] std::string_view GetRiskLevelName(RiskLevel level) noexcept;
[[nodiscard]] std::string_view GetThreatIndicatorName(ThreatIndicator indicator) noexcept;

/// @brief Check if file is high-risk type
[[nodiscard]] bool IsHighRiskFile(const fs::path& filePath);

/// @brief Get file type from magic bytes
[[nodiscard]] std::string DetectFileType(const fs::path& filePath);

/// @brief Get default download directories
[[nodiscard]] std::vector<fs::path> GetDefaultDownloadDirectories();

}  // namespace WebBrowser
}  // namespace ShadowStrike

// ============================================================================
// MACROS
// ============================================================================

#define SS_DOWNLOAD_SCAN(path) \
    ::ShadowStrike::WebBrowser::MaliciousDownloadBlocker::Instance().ScanFile(path)

#define SS_DOWNLOAD_ON_COMPLETE(path, url) \
    ::ShadowStrike::WebBrowser::MaliciousDownloadBlocker::Instance().OnDownloadComplete(path, url)

#define SS_DOWNLOAD_IS_BLOCKED(ext) \
    ::ShadowStrike::WebBrowser::MaliciousDownloadBlocker::Instance().IsExtensionBlocked(ext)
