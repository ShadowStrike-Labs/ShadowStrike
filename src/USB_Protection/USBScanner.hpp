/**
 * ============================================================================
 * ShadowStrike NGAV - USB SCANNER MODULE
 * ============================================================================
 *
 * @file USBScanner.hpp
 * @brief Enterprise-grade USB drive malware scanner optimized for removable
 *        media with comprehensive threat detection capabilities.
 *
 * Provides thorough scanning of USB drives with optimizations for removable
 * media characteristics (variable speed, ejection handling, resume support).
 *
 * SCANNING CAPABILITIES:
 * ======================
 *
 * 1. SIGNATURE-BASED DETECTION
 *    - Hash-based detection (SHA-256, SHA-1, MD5)
 *    - YARA rule scanning
 *    - Pattern matching
 *    - Byte sequence signatures
 *
 * 2. HEURISTIC ANALYSIS
 *    - Suspicious file attributes
 *    - Hidden/system file analysis
 *    - Autorun correlation
 *    - Icon spoofing detection
 *    - Double extension detection
 *
 * 3. FILE TYPE COVERAGE
 *    - Executable files (PE, ELF, Mach-O)
 *    - Scripts (VBS, JS, PS1, BAT)
 *    - Documents (Office, PDF)
 *    - Archives (ZIP, RAR, 7z)
 *    - Disk images (ISO, IMG)
 *
 * 4. REMOVABLE MEDIA OPTIMIZATION
 *    - Transfer speed adaptation
 *    - Safe ejection handling
 *    - Scan resume support
 *    - Cache management
 *    - Priority file scanning
 *
 * 5. THREAT RESPONSE
 *    - Quarantine infected files
 *    - Delete malware
 *    - Report findings
 *    - Block device access
 *
 * INTEGRATION:
 * ============
 * - HashStore for known malware
 * - SignatureStore for detection rules
 * - PatternStore for patterns
 * - ThreatIntel for IOC correlation
 * - USBDeviceMonitor for events
 *
 * @note Optimized for variable USB transfer speeds.
 * @note Supports scan pause/resume on ejection.
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
#include <thread>
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
#include "../Utils/HashUtils.hpp"
#include "../HashStore/HashStore.hpp"
#include "../PatternStore/PatternStore.hpp"
#include "../SignatureStore/SignatureStore.hpp"
#include "../ThreatIntel/ThreatIntelManager.hpp"

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

namespace ShadowStrike::USB {
    class USBScannerImpl;
}

namespace ShadowStrike {
namespace USB {

// ============================================================================
// COMPILE-TIME CONSTANTS
// ============================================================================

namespace USBScannerConstants {

    inline constexpr uint32_t VERSION_MAJOR = 3;
    inline constexpr uint32_t VERSION_MINOR = 0;
    inline constexpr uint32_t VERSION_PATCH = 0;

    /// @brief Default maximum file size for scanning (500 MB)
    inline constexpr uint64_t DEFAULT_MAX_FILE_SIZE = 500 * 1024 * 1024ULL;
    
    /// @brief Maximum scan depth
    inline constexpr size_t MAX_SCAN_DEPTH = 64;
    
    /// @brief Default scan depth
    inline constexpr size_t DEFAULT_SCAN_DEPTH = 32;
    
    /// @brief Scan buffer size
    inline constexpr size_t SCAN_BUFFER_SIZE = 4 * 1024 * 1024;  // 4 MB
    
    /// @brief Progress update interval (files)
    inline constexpr size_t PROGRESS_UPDATE_INTERVAL = 100;
    
    /// @brief Priority file extensions (scan first)
    inline constexpr const char* PRIORITY_EXTENSIONS[] = {
        ".exe", ".dll", ".scr", ".com", ".bat", ".cmd",
        ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh",
        ".ps1", ".psm1", ".psd1", ".msi", ".msp",
        ".hta", ".lnk", ".inf"
    };

}  // namespace USBScannerConstants

// ============================================================================
// TYPE ALIASES
// ============================================================================

using Clock = std::chrono::steady_clock;
using TimePoint = std::chrono::steady_clock::time_point;
using SystemTimePoint = std::chrono::system_clock::time_point;

// ============================================================================
// ENUMERATIONS
// ============================================================================

/**
 * @brief Scan status
 */
enum class ScanStatus : uint8_t {
    NotStarted      = 0,
    Initializing    = 1,
    Scanning        = 2,
    Paused          = 3,
    Completing      = 4,
    Completed       = 5,
    Cancelled       = 6,
    Error           = 7,
    DeviceRemoved   = 8
};

/**
 * @brief File scan result
 */
enum class FileScanResult : uint8_t {
    Clean           = 0,
    Infected        = 1,
    Suspicious      = 2,
    Encrypted       = 3,
    Corrupted       = 4,
    AccessDenied    = 5,
    Skipped         = 6,
    Error           = 255
};

/**
 * @brief Detection type
 */
enum class DetectionType : uint8_t {
    None            = 0,
    HashMatch       = 1,    ///< Known malware hash
    SignatureMatch  = 2,    ///< Signature/pattern match
    YARAMatch       = 3,    ///< YARA rule match
    Heuristic       = 4,    ///< Heuristic detection
    Behavioral      = 5,    ///< Behavioral indicator
    ThreatIntel     = 6,    ///< Threat intelligence
    MachineLearning = 7     ///< ML-based detection
};

/**
 * @brief Scan priority
 */
enum class ScanPriority : uint8_t {
    Low             = 0,
    Normal          = 1,
    High            = 2,
    Critical        = 3
};

/**
 * @brief Action on detection
 */
enum class DetectionAction : uint8_t {
    None            = 0,
    Report          = 1,
    Quarantine      = 2,
    Delete          = 3,
    Block           = 4,
    Disinfect       = 5
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
 * @brief Scan configuration
 */
struct USBScanConfig {
    /// @brief Scan archives
    bool scanArchives = true;
    
    /// @brief Scan hidden files
    bool scanHiddenFiles = true;
    
    /// @brief Scan system files
    bool scanSystemFiles = true;
    
    /// @brief Scan encrypted files
    bool scanEncryptedFiles = false;
    
    /// @brief Use heuristics
    bool useHeuristics = true;
    
    /// @brief Use YARA rules
    bool useYARA = true;
    
    /// @brief Check threat intelligence
    bool checkThreatIntel = true;
    
    /// @brief Maximum file size (bytes)
    uint64_t maxFileSize = USBScannerConstants::DEFAULT_MAX_FILE_SIZE;
    
    /// @brief Scan depth
    size_t scanDepth = USBScannerConstants::DEFAULT_SCAN_DEPTH;
    
    /// @brief Maximum archive nesting
    size_t maxArchiveDepth = 5;
    
    /// @brief Scan priority
    ScanPriority priority = ScanPriority::Normal;
    
    /// @brief Action on detection
    DetectionAction detectionAction = DetectionAction::Quarantine;
    
    /// @brief File type filter (empty = all)
    std::vector<std::string> fileTypeFilter;
    
    /// @brief Excluded paths
    std::vector<std::string> excludedPaths;
    
    /// @brief Scan priority files first
    bool priorityFilesFirst = true;
    
    /// @brief Resume on reconnect
    bool resumeOnReconnect = true;
    
    [[nodiscard]] bool IsValid() const noexcept;
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Detected threat info
 */
struct DetectedThreat {
    /// @brief Detection type
    DetectionType type = DetectionType::None;
    
    /// @brief Threat name
    std::string threatName;
    
    /// @brief Threat family
    std::string threatFamily;
    
    /// @brief Signature ID
    std::string signatureId;
    
    /// @brief Risk score (0-100)
    int riskScore = 0;
    
    /// @brief Confidence (0-100)
    int confidence = 0;
    
    /// @brief MITRE ATT&CK technique
    std::string mitreAttackId;
    
    /// @brief Additional details
    std::string details;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief File scan result info
 */
struct FileScanResultInfo {
    /// @brief File path
    std::filesystem::path filePath;
    
    /// @brief Relative path from scan root
    std::filesystem::path relativePath;
    
    /// @brief Scan result
    FileScanResult result = FileScanResult::Clean;
    
    /// @brief Detected threats
    std::vector<DetectedThreat> threats;
    
    /// @brief Primary threat name
    std::string primaryThreatName;
    
    /// @brief File size
    uint64_t fileSize = 0;
    
    /// @brief File hash (SHA-256)
    std::string sha256;
    
    /// @brief File hash (SHA-1)
    std::string sha1;
    
    /// @brief File hash (MD5)
    std::string md5;
    
    /// @brief Action taken
    DetectionAction actionTaken = DetectionAction::None;
    
    /// @brief Quarantine path (if quarantined)
    std::filesystem::path quarantinePath;
    
    /// @brief Scan time
    SystemTimePoint scanTime;
    
    /// @brief Scan duration
    std::chrono::microseconds scanDuration{0};
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Scan progress
 */
struct USBScanProgress {
    /// @brief Current status
    ScanStatus status = ScanStatus::NotStarted;
    
    /// @brief Progress percentage (0.0 - 100.0)
    float progressPercent = 0.0f;
    
    /// @brief Files scanned
    uint64_t filesScanned = 0;
    
    /// @brief Total files (estimated)
    uint64_t totalFiles = 0;
    
    /// @brief Bytes scanned
    uint64_t bytesScanned = 0;
    
    /// @brief Total bytes (estimated)
    uint64_t totalBytes = 0;
    
    /// @brief Current file being scanned
    std::string currentFile;
    
    /// @brief Current directory
    std::string currentDirectory;
    
    /// @brief Threats found so far
    uint32_t threatsFound = 0;
    
    /// @brief Estimated time remaining
    std::chrono::seconds estimatedTimeRemaining{0};
    
    /// @brief Scan speed (bytes/sec)
    double scanSpeedBps = 0.0;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Scan result summary
 */
struct USBScanResultSummary {
    /// @brief Final status
    ScanStatus status = ScanStatus::NotStarted;
    
    /// @brief Drive path scanned
    std::string drivePath;
    
    /// @brief Volume label
    std::string volumeLabel;
    
    /// @brief Files scanned
    uint64_t filesScanned = 0;
    
    /// @brief Directories scanned
    uint64_t directoriesScanned = 0;
    
    /// @brief Bytes scanned
    uint64_t bytesScanned = 0;
    
    /// @brief Files infected
    uint64_t filesInfected = 0;
    
    /// @brief Files suspicious
    uint64_t filesSuspicious = 0;
    
    /// @brief Files quarantined
    uint64_t filesQuarantined = 0;
    
    /// @brief Files deleted
    uint64_t filesDeleted = 0;
    
    /// @brief Files skipped
    uint64_t filesSkipped = 0;
    
    /// @brief Errors encountered
    uint64_t errors = 0;
    
    /// @brief Detected threats
    std::vector<FileScanResultInfo> infectedFiles;
    
    /// @brief Suspicious files
    std::vector<FileScanResultInfo> suspiciousFiles;
    
    /// @brief Scan start time
    SystemTimePoint startTime;
    
    /// @brief Scan end time
    SystemTimePoint endTime;
    
    /// @brief Total scan duration
    std::chrono::seconds totalDuration{0};
    
    /// @brief Average scan speed (bytes/sec)
    double averageSpeedBps = 0.0;
    
    [[nodiscard]] std::string ToJson() const;
    [[nodiscard]] bool IsClean() const noexcept;
};

/**
 * @brief Statistics
 */
struct USBScanStatistics {
    std::atomic<uint64_t> totalScans{0};
    std::atomic<uint64_t> completedScans{0};
    std::atomic<uint64_t> cancelledScans{0};
    std::atomic<uint64_t> erroredScans{0};
    std::atomic<uint64_t> totalFilesScanned{0};
    std::atomic<uint64_t> totalBytesScanned{0};
    std::atomic<uint64_t> totalThreatsFound{0};
    std::atomic<uint64_t> totalFilesQuarantined{0};
    std::atomic<uint64_t> totalFilesDeleted{0};
    std::atomic<uint64_t> hashMatches{0};
    std::atomic<uint64_t> signatureMatches{0};
    std::atomic<uint64_t> yaraMatches{0};
    std::atomic<uint64_t> heuristicDetections{0};
    std::array<std::atomic<uint64_t>, 8> byDetectionType{};
    TimePoint startTime = Clock::now();
    
    void Reset() noexcept;
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Scanner configuration
 */
struct USBScannerConfiguration {
    /// @brief Enable scanner
    bool enabled = true;
    
    /// @brief Default scan config
    USBScanConfig defaultScanConfig;
    
    /// @brief Auto-scan on mount
    bool autoScanOnMount = true;
    
    /// @brief Thread pool size
    size_t threadPoolSize = 2;
    
    /// @brief Use memory-mapped files
    bool useMemoryMappedFiles = true;
    
    /// @brief Cache scan results
    bool cacheScanResults = true;
    
    /// @brief Cache duration (hours)
    uint32_t cacheHours = 24;
    
    /// @brief Verbose logging
    bool verboseLogging = false;
    
    [[nodiscard]] bool IsValid() const noexcept;
};

// ============================================================================
// CALLBACK TYPES
// ============================================================================

using ProgressCallback = std::function<void(const USBScanProgress&)>;
using ThreatDetectedCallback = std::function<void(const FileScanResultInfo&)>;
using ScanCompleteCallback = std::function<void(const USBScanResultSummary&)>;
using ErrorCallback = std::function<void(const std::string& message, int code)>;

// ============================================================================
// USB SCANNER CLASS
// ============================================================================

/**
 * @class USBScanner
 * @brief Enterprise USB drive malware scanner
 */
class USBScanner final {
public:
    [[nodiscard]] static USBScanner& Instance() noexcept;
    [[nodiscard]] static bool HasInstance() noexcept;
    
    USBScanner(const USBScanner&) = delete;
    USBScanner& operator=(const USBScanner&) = delete;
    USBScanner(USBScanner&&) = delete;
    USBScanner& operator=(USBScanner&&) = delete;

    // ========================================================================
    // LIFECYCLE
    // ========================================================================
    
    [[nodiscard]] bool Initialize(const USBScannerConfiguration& config = {});
    void Shutdown();
    [[nodiscard]] bool IsInitialized() const noexcept;
    [[nodiscard]] ModuleStatus GetStatus() const noexcept;
    
    [[nodiscard]] bool UpdateConfiguration(const USBScannerConfiguration& config);
    [[nodiscard]] USBScannerConfiguration GetConfiguration() const;

    // ========================================================================
    // SCANNING
    // ========================================================================
    
    /// @brief Start scan on drive
    [[nodiscard]] bool ScanDrive(
        const std::string& rootPath,
        const USBScanConfig& config = {});
    
    /// @brief Start scan with default config
    [[nodiscard]] bool ScanDriveAsync(
        const std::string& rootPath,
        ProgressCallback progressCallback = nullptr);
    
    /// @brief Scan specific file
    [[nodiscard]] FileScanResultInfo ScanFile(const std::filesystem::path& filePath);
    
    /// @brief Pause current scan
    void PauseScan();
    
    /// @brief Resume paused scan
    void ResumeScan();
    
    /// @brief Cancel current scan
    void CancelScan();
    
    /// @brief Wait for scan completion
    [[nodiscard]] USBScanResultSummary WaitForCompletion();

    // ========================================================================
    // STATUS
    // ========================================================================
    
    /// @brief Get current progress
    [[nodiscard]] USBScanProgress GetProgress() const;
    
    /// @brief Is scanning
    [[nodiscard]] bool IsScanning() const noexcept;
    
    /// @brief Get last scan result
    [[nodiscard]] std::optional<USBScanResultSummary> GetLastScanResult() const;

    // ========================================================================
    // CALLBACKS
    // ========================================================================
    
    void RegisterProgressCallback(ProgressCallback callback);
    void RegisterThreatCallback(ThreatDetectedCallback callback);
    void RegisterCompleteCallback(ScanCompleteCallback callback);
    void RegisterErrorCallback(ErrorCallback callback);
    void UnregisterCallbacks();

    // ========================================================================
    // STATISTICS
    // ========================================================================
    
    [[nodiscard]] USBScanStatistics GetStatistics() const;
    void ResetStatistics();
    
    [[nodiscard]] bool SelfTest();
    [[nodiscard]] static std::string GetVersionString() noexcept;

private:
    USBScanner();
    ~USBScanner();
    
    std::unique_ptr<USBScannerImpl> m_impl;
    static std::atomic<bool> s_instanceCreated;
};

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

[[nodiscard]] std::string_view GetScanStatusName(ScanStatus status) noexcept;
[[nodiscard]] std::string_view GetFileScanResultName(FileScanResult result) noexcept;
[[nodiscard]] std::string_view GetDetectionTypeName(DetectionType type) noexcept;
[[nodiscard]] std::string_view GetScanPriorityName(ScanPriority priority) noexcept;
[[nodiscard]] std::string_view GetDetectionActionName(DetectionAction action) noexcept;
[[nodiscard]] bool IsPriorityFileExtension(std::string_view extension) noexcept;

}  // namespace USB
}  // namespace ShadowStrike

// ============================================================================
// MACROS
// ============================================================================

#define SS_USB_SCAN(rootPath) \
    ::ShadowStrike::USB::USBScanner::Instance().ScanDrive(rootPath)

#define SS_USB_SCAN_FILE(filePath) \
    ::ShadowStrike::USB::USBScanner::Instance().ScanFile(filePath)