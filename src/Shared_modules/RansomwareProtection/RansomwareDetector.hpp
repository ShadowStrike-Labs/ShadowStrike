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
 * ShadowStrike Ransomware Protection - BEHAVIORAL RANSOMWARE DETECTOR
 * ============================================================================
 *
 * @file RansomwareDetector.hpp
 * @brief Enterprise-grade real-time behavioral ransomware detection engine
 *        with heuristic analysis, entropy monitoring, and honeypot integration.
 *
 * This module provides comprehensive ransomware detection capabilities using
 * multiple detection techniques including entropy analysis, behavioral patterns,
 * file mutation tracking, and decoy file monitoring.
 *
 * DETECTION TECHNIQUES:
 * =====================
 *
 * 1. ENTROPY ANALYSIS
 *    - Shannon entropy calculation (>7.5 = encrypted)
 *    - Rolling entropy windows
 *    - Chi-squared distribution test
 *    - Monte Carlo Pi calculation
 *    - Serial correlation coefficient
 *
 * 2. BEHAVIORAL PATTERNS
 *    - Rapid file modifications
 *    - Bulk file renaming
 *    - Mass deletions
 *    - Extension changes
 *    - Directory traversal patterns
 *
 * 3. FILE MUTATION TRACKING
 *    - MFT timestamp analysis
 *    - File size ratio monitoring
 *    - Magic byte corruption
 *    - Header structure analysis
 *    - Content randomization
 *
 * 4. HONEYPOT INTEGRATION
 *    - Canary file access detection
 *    - Decoy directory monitoring
 *    - Immediate process termination
 *
 * 5. PROCESS CORRELATION
 *    - Per-process IO statistics
 *    - Activity velocity tracking
 *    - Resource consumption anomalies
 *    - Network correlation (C2)
 *
 * 6. FAMILY IDENTIFICATION
 *    - Known ransomware patterns
 *    - Extension signature matching
 *    - Ransom note templates
 *    - Encryption algorithm fingerprinting
 *
 * INTEGRATION:
 * ============
 * - Core::FileSystem::FileWatcher for file events
 * - Core::Engine::BehaviorAnalyzer for central processing
 * - Ransomware::HoneypotManager for canary files
 * - Ransomware::FileBackupManager for JIT backups
 *
 * @note Pre-write analysis enables blocking before damage.
 * @note Low false-positive design with multi-factor confidence scoring.
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @date 2026
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 *
 * COMPLIANCE: SOC2, ISO 27001, NIST CSF
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
#include <queue>

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
#include "../Utils/CryptoUtils.hpp"
#include "../Utils/HashUtils.hpp"
#include "../PatternStore/PatternStore.hpp"
#include "../SignatureStore/SignatureStore.hpp"
#include "../ThreatIntel/ThreatIntelManager.hpp"

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

namespace ShadowStrike::Ransomware {
    class RansomwareDetectorImpl;
    class HoneypotManager;
    class FileBackupManager;
}

namespace ShadowStrike {
namespace Ransomware {

// ============================================================================
// COMPILE-TIME CONSTANTS
// ============================================================================

namespace RansomwareConstants {

    // ========================================================================
    // VERSION
    // ========================================================================
    
    inline constexpr uint32_t VERSION_MAJOR = 3;
    inline constexpr uint32_t VERSION_MINOR = 1;
    inline constexpr uint32_t VERSION_PATCH = 0;

    // ========================================================================
    // ENTROPY THRESHOLDS
    // ========================================================================
    
    /// @brief Shannon entropy threshold for encryption detection
    inline constexpr double ENTROPY_THRESHOLD = 7.5;
    
    /// @brief Minimum entropy for suspicion
    inline constexpr double MIN_SUSPICION_ENTROPY = 7.0;
    
    /// @brief Chi-squared threshold for randomness
    inline constexpr double CHI_SQUARED_THRESHOLD = 293.25;
    
    /// @brief Monte Carlo Pi deviation threshold
    inline constexpr double PI_DEVIATION_THRESHOLD = 0.01;

    // ========================================================================
    // RATE LIMITS
    // ========================================================================
    
    /// @brief Maximum writes per second before suspicious
    inline constexpr uint32_t MAX_WRITES_PER_SECOND = 50;
    
    /// @brief Maximum renames per second before suspicious
    inline constexpr uint32_t MAX_RENAMES_PER_SECOND = 10;
    
    /// @brief Maximum deletes per second before suspicious
    inline constexpr uint32_t MAX_DELETES_PER_SECOND = 20;
    
    /// @brief Maximum high-entropy writes before blocking
    inline constexpr uint32_t MAX_HIGH_ENTROPY_WRITES = 5;

    // ========================================================================
    // TIME WINDOWS
    // ========================================================================
    
    /// @brief Sliding window for rate calculations (seconds)
    inline constexpr uint32_t RATE_WINDOW_SECS = 5;
    
    /// @brief Stats retention period (seconds)
    inline constexpr uint32_t STATS_RETENTION_SECS = 300;
    
    /// @brief Cooldown after block (seconds)
    inline constexpr uint32_t BLOCK_COOLDOWN_SECS = 30;

    /// @brief Detection score expiry — indicators older than this decay to zero
    inline constexpr uint32_t SCORE_EXPIRY_SECS = 60;

    /// @brief Maximum recent detection events retained
    inline constexpr size_t MAX_RECENT_DETECTIONS = 1000;

    /// @brief Maximum registered family signatures
    inline constexpr size_t MAX_FAMILY_SIGNATURES = 64;

    /// @brief Composite score threshold to fire an alert
    inline constexpr double ALERT_SCORE_THRESHOLD = 50.0;

    /// @brief Composite score threshold to block + kill
    inline constexpr double BLOCK_SCORE_THRESHOLD = 75.0;

    // ========================================================================
    // LIMITS
    // ========================================================================
    
    /// @brief Maximum tracked processes
    inline constexpr size_t MAX_TRACKED_PROCESSES = 1000;
    
    /// @brief Maximum extensions per process
    inline constexpr size_t MAX_EXTENSIONS_PER_PROCESS = 100;
    
    /// @brief Maximum file paths per process
    inline constexpr size_t MAX_PATHS_PER_PROCESS = 10000;
    
    /// @brief Minimum buffer size for entropy analysis
    inline constexpr size_t MIN_ENTROPY_BUFFER_SIZE = 256;
    
    /// @brief Entropy sample size
    inline constexpr size_t ENTROPY_SAMPLE_SIZE = 4096;

    // ========================================================================
    // CONFIDENCE SCORING
    // ========================================================================
    
    /// @brief Minimum confidence for alert
    inline constexpr double MIN_ALERT_CONFIDENCE = 0.5;
    
    /// @brief Minimum confidence for block
    inline constexpr double MIN_BLOCK_CONFIDENCE = 0.7;
    
    /// @brief Minimum confidence for kill
    inline constexpr double MIN_KILL_CONFIDENCE = 0.9;

}  // namespace RansomwareConstants

// ============================================================================
// TYPE ALIASES
// ============================================================================

using Clock = std::chrono::steady_clock;
using TimePoint = std::chrono::steady_clock::time_point;
using SystemTimePoint = std::chrono::system_clock::time_point;
using Duration = std::chrono::steady_clock::duration;
using Hash256 = std::array<uint8_t, 32>;

// ============================================================================
// ENUMERATIONS
// ============================================================================

/**
 * @brief Detection verdict
 */
enum class DetectionVerdict : uint8_t {
    Clean           = 0,    ///< No ransomware detected
    Suspicious      = 1,    ///< Suspicious activity
    PossibleRansom  = 2,    ///< Likely ransomware
    ConfirmedRansom = 3,    ///< Confirmed ransomware
    Honeypot        = 4     ///< Honeypot triggered
};

/**
 * @brief Action to take
 */
enum class DetectionAction : uint8_t {
    Allow           = 0,    ///< Allow operation
    AllowWithBackup = 1,    ///< Allow but backup first
    Block           = 2,    ///< Block operation
    BlockAndKill    = 3,    ///< Block and terminate process
    Quarantine      = 4     ///< Quarantine process files
};

/**
 * @brief Detection technique
 */
enum class DetectionTechnique : uint16_t {
    None                = 0x0000,
    EntropyAnalysis     = 0x0001,
    RapidWrites         = 0x0002,
    MassRename          = 0x0004,
    MassDelete          = 0x0008,
    ExtensionChange     = 0x0010,
    HoneypotAccess      = 0x0020,
    KnownFamily         = 0x0040,
    RansomNote          = 0x0080,
    VssDestruction      = 0x0100,
    BackupDeletion      = 0x0200,
    MagicCorruption     = 0x0400,
    DirectoryTraversal  = 0x0800,
    C2Communication     = 0x1000,
    ProcessHollowing    = 0x2000,
    PrivilegeEscalation = 0x4000
};

/**
 * @brief File operation type
 */
enum class FileOperationType : uint8_t {
    Unknown     = 0,
    Create      = 1,
    Write       = 2,
    Rename      = 3,
    Delete      = 4,
    SetInfo     = 5,
    SetSecurity = 6
};

/**
 * @brief Ransomware family
 */
enum class RansomwareFamily : uint16_t {
    Unknown         = 0,
    WannaCry        = 1,
    Locky           = 2,
    CryptoLocker    = 3,
    TeslaCrypt      = 4,
    Cerber          = 5,
    Petya           = 6,
    NotPetya        = 7,
    Ryuk            = 8,
    REvil           = 9,
    Conti           = 10,
    LockBit         = 11,
    BlackCat        = 12,
    Hive            = 13,
    BlackBasta      = 14,
    Royal           = 15,
    Play            = 16,
    Clop            = 17,
    Maze            = 18,
    Ragnar          = 19,
    Custom          = 0xFFFF
};

/**
 * @brief Process risk level
 */
enum class ProcessRiskLevel : uint8_t {
    Unknown     = 0,
    Safe        = 1,
    Low         = 2,
    Medium      = 3,
    High        = 4,
    Critical    = 5
};

/**
 * @brief Module status
 */
#ifndef SHADOWSTRIKE_RANSOMWARE_MODULE_STATUS_DEFINED
#define SHADOWSTRIKE_RANSOMWARE_MODULE_STATUS_DEFINED
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
#endif

// ============================================================================
// STRUCTURES
// ============================================================================

/**
 * @brief Entropy analysis result
 */
struct EntropyResult {
    /// @brief Shannon entropy (0-8 bits)
    double shannonEntropy = 0.0;
    
    /// @brief Chi-squared value
    double chiSquared = 0.0;
    
    /// @brief Arithmetic mean
    double arithmeticMean = 0.0;
    
    /// @brief Monte Carlo Pi estimation
    double monteCarloPi = 0.0;
    
    /// @brief Serial correlation coefficient
    double serialCorrelation = 0.0;
    
    /// @brief Compression ratio estimate
    double compressionRatio = 0.0;
    
    /// @brief Is encrypted (based on all metrics)
    bool isEncrypted = false;
    
    /// @brief Confidence in encryption determination
    double confidence = 0.0;
    
    /**
     * @brief Serialize to JSON
     */
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief IO statistics for a process
 */
struct IOStats {
    /// @brief Process ID
    uint32_t pid = 0;
    
    /// @brief Process name
    std::wstring processName;
    
    /// @brief Write count
    std::atomic<uint32_t> writeCount{0};
    
    /// @brief Rename count
    std::atomic<uint32_t> renameCount{0};
    
    /// @brief Delete count
    std::atomic<uint32_t> deleteCount{0};
    
    /// @brief High entropy writes count
    std::atomic<uint32_t> highEntropyWrites{0};
    
    /// @brief Total bytes written
    std::atomic<uint64_t> bytesWritten{0};
    
    /// @brief Encrypted bytes written
    std::atomic<uint64_t> encryptedBytesWritten{0};
    
    /// @brief Affected file extensions
    std::unordered_set<std::wstring> affectedExtensions;
    
    /// @brief Original extensions before rename
    std::unordered_set<std::wstring> originalExtensions;
    
    /// @brief New extensions after rename
    std::unordered_set<std::wstring> newExtensions;
    
    /// @brief Affected directories
    std::unordered_set<std::wstring> affectedDirectories;
    
    /// @brief First activity time
    TimePoint firstActivity;
    
    /// @brief Last activity time
    TimePoint lastActivity;
    
    /// @brief Activity timestamps for rate calculation
    std::vector<TimePoint> writeTimestamps;
    std::vector<TimePoint> renameTimestamps;
    std::vector<TimePoint> deleteTimestamps;
    
    /// @brief Current risk level
    ProcessRiskLevel riskLevel = ProcessRiskLevel::Unknown;
    
    /// @brief Detection techniques triggered
    uint16_t detectionFlags = 0;
    
    /// @brief Confidence score (0-1)
    double confidenceScore = 0.0;
    
    /// @brief Has been blocked
    bool isBlocked = false;
    
    /// @brief Mutex for thread-safe access to non-atomic fields
    mutable std::mutex mutex;

    // Explicit constructors — atomics and mutex require manual copy
    IOStats() noexcept;
    explicit IOStats(const IOStats& other);
    IOStats& operator=(const IOStats&) = delete;
    IOStats(IOStats&&) = delete;
    IOStats& operator=(IOStats&&) = delete;

    /**
     * @brief Reset statistics
     */
    void Reset() noexcept;
    
    /**
     * @brief Calculate write rate (per second)
     */
    [[nodiscard]] double GetWriteRate() const;
    
    /**
     * @brief Calculate rename rate (per second)
     */
    [[nodiscard]] double GetRenameRate() const;
    
    /**
     * @brief Serialize to JSON
     */
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Detection event
 */
struct DetectionEvent {
    /// @brief Event ID
    uint64_t eventId = 0;
    
    /// @brief Timestamp
    SystemTimePoint timestamp;
    
    /// @brief Process ID
    uint32_t pid = 0;
    
    /// @brief Process name
    std::wstring processName;
    
    /// @brief Process path
    std::wstring processPath;
    
    /// @brief File path
    std::wstring filePath;
    
    /// @brief Operation type
    FileOperationType operationType = FileOperationType::Unknown;
    
    /// @brief Verdict
    DetectionVerdict verdict = DetectionVerdict::Clean;
    
    /// @brief Action taken
    DetectionAction action = DetectionAction::Allow;
    
    /// @brief Detection techniques
    uint16_t detectionFlags = 0;
    
    /// @brief Ransomware family (if identified)
    RansomwareFamily family = RansomwareFamily::Unknown;
    
    /// @brief Confidence score
    double confidence = 0.0;
    
    /// @brief Entropy result (if applicable)
    std::optional<EntropyResult> entropyResult;
    
    /// @brief Details
    std::wstring details;
    
    /**
     * @brief Serialize to JSON
     */
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Ransomware family signature
 */
struct FamilySignature {
    /// @brief Family identifier
    RansomwareFamily family = RansomwareFamily::Unknown;
    
    /// @brief Family name
    std::string familyName;
    
    /// @brief File extensions used
    std::vector<std::wstring> extensions;
    
    /// @brief Ransom note patterns
    std::vector<std::wstring> ransomNotePatterns;
    
    /// @brief Known mutex names
    std::vector<std::wstring> mutexNames;
    
    /// @brief Known registry keys
    std::vector<std::wstring> registryKeys;
    
    /// @brief File marker/magic bytes
    std::vector<std::vector<uint8_t>> fileMarkers;
    
    /// @brief C2 domains
    std::vector<std::string> c2Domains;
    
    /// @brief Process name patterns
    std::vector<std::wstring> processPatterns;
    
    /// @brief Encryption algorithm hints
    std::string encryptionAlgorithm;
    
    /// @brief Is worm (self-propagating)
    bool isWorm = false;
    
    /// @brief Has decryptor available
    bool hasDecryptor = false;
};

/**
 * @brief Detection configuration
 */
struct RansomwareDetectorConfiguration {
    /// @brief Enable entropy analysis
    bool enableEntropyAnalysis = true;
    
    /// @brief Enable rate monitoring
    bool enableRateMonitoring = true;
    
    /// @brief Enable honeypot integration
    bool enableHoneypotIntegration = true;
    
    /// @brief Enable JIT backups
    bool enableJITBackups = true;
    
    /// @brief Enable automatic blocking
    bool enableAutoBlock = true;
    
    /// @brief Enable process termination
    bool enableProcessKill = true;
    
    /// @brief Entropy threshold
    double entropyThreshold = RansomwareConstants::ENTROPY_THRESHOLD;
    
    /// @brief Maximum writes per second
    uint32_t maxWritesPerSecond = RansomwareConstants::MAX_WRITES_PER_SECOND;
    
    /// @brief Maximum renames per second
    uint32_t maxRenamesPerSecond = RansomwareConstants::MAX_RENAMES_PER_SECOND;
    
    /// @brief Rate window (seconds)
    uint32_t rateWindowSecs = RansomwareConstants::RATE_WINDOW_SECS;
    
    /// @brief Minimum confidence for blocking
    double minBlockConfidence = RansomwareConstants::MIN_BLOCK_CONFIDENCE;
    
    /// @brief Excluded process names
    std::vector<std::wstring> excludedProcesses;
    
    /// @brief Excluded directories
    std::vector<std::wstring> excludedDirectories;
    
    /// @brief Protected directories (higher sensitivity)
    std::vector<std::wstring> protectedDirectories;
    
    /// @brief Verbose logging
    bool verboseLogging = false;
    
    /**
     * @brief Validate configuration
     */
    [[nodiscard]] bool IsValid() const noexcept;
};

/**
 * @brief Detection statistics
 */
struct DetectionStatistics {
    /// @brief Total operations analyzed
    std::atomic<uint64_t> totalOperations{0};
    
    /// @brief Operations blocked
    std::atomic<uint64_t> operationsBlocked{0};
    
    /// @brief Processes terminated
    std::atomic<uint64_t> processesTerminated{0};
    
    /// @brief Honeypot triggers
    std::atomic<uint64_t> honeypotTriggers{0};
    
    /// @brief High entropy writes
    std::atomic<uint64_t> highEntropyWrites{0};
    
    /// @brief Files backed up
    std::atomic<uint64_t> filesBackedUp{0};
    
    /// @brief Files restored
    std::atomic<uint64_t> filesRestored{0};
    
    /// @brief False positive reports
    std::atomic<uint64_t> falsePositives{0};
    
    /// @brief Detections by family
    std::array<std::atomic<uint64_t>, 32> detectionsByFamily{};
    
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

/// @brief Copyable, non-atomic snapshot for public API — no atomic fields leaked.
struct DetectionStatisticsSnapshot {
    uint64_t totalOperations{0};
    uint64_t operationsBlocked{0};
    uint64_t processesTerminated{0};
    uint64_t honeypotTriggers{0};
    uint64_t highEntropyWrites{0};
    uint64_t filesBackedUp{0};
    uint64_t filesRestored{0};
    uint64_t falsePositives{0};
    std::array<uint64_t, 32> detectionsByFamily{};
    int64_t  uptimeSeconds{0};
    [[nodiscard]] std::string ToJson() const;
};

/// @brief Detection callback
using DetectionCallback = std::function<void(const DetectionEvent&)>;

/// @brief Process blocked callback
using BlockCallback = std::function<void(uint32_t pid, const std::wstring& reason)>;

/// @brief Pre-write callback (can modify action)
using PreWriteCallback = std::function<DetectionAction(
    uint32_t pid, const std::wstring& path, std::span<const uint8_t> data)>;

// ============================================================================
// EMERGENCY RESPONSE CALLBACKS (wired by application startup code)
// ============================================================================

/// @brief Emergency backup all tracked files for a process
using EmergencyBackupCallback = std::function<bool(uint32_t pid)>;

/// @brief Create emergency volume snapshot on all drives
using EmergencySnapshotCallback = std::function<bool()>;

/// @brief Enter kernel-enforced lockdown (block all non-agent writes)
using LockdownCallback = std::function<void()>;

/// @brief Trigger decryptor recovery workflow for a ransomware family
using RecoveryCallback = std::function<void(uint32_t pid, RansomwareFamily family)>;

/// @brief Sub-detector indicator — feeds into the orchestrator score
using SubDetectorIndicatorCallback = std::function<void(
    uint32_t pid, double score, std::wstring_view detail)>;

// ============================================================================
// RANSOMWARE DETECTOR CLASS
// ============================================================================

/**
 * @class RansomwareDetector
 * @brief Enterprise-grade behavioral ransomware detection engine
 *
 * Provides real-time ransomware detection using multiple detection techniques
 * including entropy analysis, behavioral patterns, and honeypot monitoring.
 *
 * THREAD SAFETY: All public methods are thread-safe.
 *
 * USAGE:
 * @code
 *     auto& detector = RansomwareDetector::Instance();
 *     detector.Initialize();
 *     
 *     // Analyze before allowing write
 *     if (detector.AnalyzeWrite(pid, buffer, path)) {
 *         // Block the operation!
 *     }
 * @endcode
 */
class RansomwareDetector final {
public:
    // ========================================================================
    // SINGLETON ACCESS
    // ========================================================================
    
    /**
     * @brief Get singleton instance
     */
    [[nodiscard]] static RansomwareDetector& Instance() noexcept;
    
    /**
     * @brief Check if instance exists
     */
    [[nodiscard]] static bool HasInstance() noexcept;
    
    // Non-copyable, non-movable
    RansomwareDetector(const RansomwareDetector&) = delete;
    RansomwareDetector& operator=(const RansomwareDetector&) = delete;
    RansomwareDetector(RansomwareDetector&&) = delete;
    RansomwareDetector& operator=(RansomwareDetector&&) = delete;

    // ========================================================================
    // LIFECYCLE MANAGEMENT
    // ========================================================================
    
    /**
     * @brief Initialize ransomware detector
     */
    [[nodiscard]] bool Initialize(const RansomwareDetectorConfiguration& config = {});
    
    /**
     * @brief Shutdown ransomware detector
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
    // WRITE ANALYSIS
    // ========================================================================
    
    /**
     * @brief Analyze a file write operation BEFORE it happens
     * @param pid Process ID
     * @param buffer Data being written
     * @param filePath Target file
     * @return True if operation should be BLOCKED
     */
    [[nodiscard]] bool AnalyzeWrite(uint32_t pid,
                                    const std::vector<uint8_t>& buffer,
                                    const std::wstring& filePath);
    
    /**
     * @brief Analyze write with span
     */
    [[nodiscard]] bool AnalyzeWrite(uint32_t pid,
                                    std::span<const uint8_t> buffer,
                                    std::wstring_view filePath);
    
    /**
     * @brief Analyze write and get detailed verdict
     */
    [[nodiscard]] DetectionEvent AnalyzeWriteEx(uint32_t pid,
                                                std::span<const uint8_t> buffer,
                                                std::wstring_view filePath);
    
    // ========================================================================
    // RENAME ANALYSIS
    // ========================================================================
    
    /**
     * @brief Analyze a file rename operation
     * @param pid Process ID
     * @param oldPath Original path
     * @param newPath New path
     * @return True if operation should be BLOCKED
     */
    [[nodiscard]] bool AnalyzeRename(uint32_t pid,
                                     const std::wstring& oldPath,
                                     const std::wstring& newPath);
    
    /**
     * @brief Analyze rename and get detailed verdict
     */
    [[nodiscard]] DetectionEvent AnalyzeRenameEx(uint32_t pid,
                                                 std::wstring_view oldPath,
                                                 std::wstring_view newPath);
    
    // ========================================================================
    // DELETE ANALYSIS
    // ========================================================================
    
    /**
     * @brief Analyze a file delete operation
     */
    [[nodiscard]] bool AnalyzeDelete(uint32_t pid, std::wstring_view filePath);
    
    /**
     * @brief Analyze delete and get detailed verdict
     */
    [[nodiscard]] DetectionEvent AnalyzeDeleteEx(uint32_t pid, std::wstring_view filePath);
    
    // ========================================================================
    // HONEYPOT INTEGRATION
    // ========================================================================
    
    /**
     * @brief Called when a Honeyfile is touched
     * Immediate BLOCK + KILL verdict
     */
    void OnHoneypotTouched(uint32_t pid, const std::wstring& filePath);
    
    /**
     * @brief Register honeypot file for monitoring
     */
    void RegisterHoneypot(std::wstring_view filePath);
    
    /**
     * @brief Unregister honeypot file
     */
    void UnregisterHoneypot(std::wstring_view filePath);
    
    /**
     * @brief Check if path is a honeypot
     */
    [[nodiscard]] bool IsHoneypot(std::wstring_view filePath) const;
    
    // ========================================================================
    // KERNEL EVENT HANDLERS
    // ========================================================================
    
    /**
     * @brief Process creation event from kernel driver
     * Routes to BackupProtector, ShadowCopyProtector, LockyDetector, WannaCryDetector
     */
    void OnProcessCreated(uint32_t pid, std::wstring_view imagePath,
                          std::wstring_view commandLine);

    /**
     * @brief Network event from kernel driver
     * Routes to WannaCryDetector (SMB/EternalBlue), LockyDetector (DGA/C2)
     */
    void OnNetworkEvent(uint32_t pid, std::string_view srcIP,
                        std::string_view dstIP, uint16_t dstPort,
                        std::span<const uint8_t> payload);

    /**
     * @brief Registry event from kernel driver
     * Routes to LockyDetector (persistence), WannaCryDetector (service install)
     */
    void OnRegistryEvent(uint32_t pid, std::wstring_view keyPath,
                         std::wstring_view valueName, uint32_t operation);

    /**
     * @brief Sub-detector indicator callback — fed from LockyDetector/WannaCryDetector
     * Accumulates into composite score; triggers response pipeline at threshold.
     */
    void OnSubDetectorIndicator(uint32_t pid, double score,
                                RansomwareFamily family,
                                std::wstring_view detail);

    // ========================================================================
    // PROCESS MANAGEMENT
    // ========================================================================
    
    /**
     * @brief Get IO statistics for process
     */
    [[nodiscard]] std::optional<IOStats> GetProcessStats(uint32_t pid) const;
    
    /**
     * @brief Get all tracked processes
     */
    [[nodiscard]] std::vector<uint32_t> GetTrackedProcesses() const;
    
    /**
     * @brief Get high-risk processes
     */
    [[nodiscard]] std::vector<uint32_t> GetHighRiskProcesses() const;
    
    /**
     * @brief Clear statistics for process
     */
    void ClearProcessStats(uint32_t pid);
    
    /**
     * @brief Whitelist process (exclude from detection)
     */
    void WhitelistProcess(uint32_t pid);
    
    /**
     * @brief Remove process from whitelist
     */
    void UnwhitelistProcess(uint32_t pid);
    
    /**
     * @brief Check if process is whitelisted
     */
    [[nodiscard]] bool IsProcessWhitelisted(uint32_t pid) const;
    
    // ========================================================================
    // ENTROPY ANALYSIS
    // ========================================================================
    
    /**
     * @brief Calculate entropy of buffer
     */
    [[nodiscard]] static double CalculateEntropy(std::span<const uint8_t> buffer);
    
    /**
     * @brief Full entropy analysis
     */
    [[nodiscard]] static EntropyResult AnalyzeEntropy(std::span<const uint8_t> buffer);
    
    /**
     * @brief Check if data appears encrypted
     */
    [[nodiscard]] static bool IsEncrypted(std::span<const uint8_t> buffer);
    
    // ========================================================================
    // FAMILY IDENTIFICATION
    // ========================================================================
    
    /**
     * @brief Identify ransomware family
     */
    [[nodiscard]] RansomwareFamily IdentifyFamily(uint32_t pid) const;
    
    /**
     * @brief Identify family from extension
     */
    [[nodiscard]] RansomwareFamily IdentifyFamilyFromExtension(
        std::wstring_view extension) const;
    
    /**
     * @brief Get family signature
     */
    [[nodiscard]] std::optional<FamilySignature> GetFamilySignature(
        RansomwareFamily family) const;
    
    /**
     * @brief Register custom family signature
     */
    void RegisterFamilySignature(const FamilySignature& signature);
    
    // ========================================================================
    // CALLBACKS
    // ========================================================================
    
    /**
     * @brief Set detection callback
     */
    void SetDetectionCallback(DetectionCallback callback);
    
    /**
     * @brief Set block callback
     */
    void SetBlockCallback(BlockCallback callback);
    
    /**
     * @brief Set pre-write callback
     */
    void SetPreWriteCallback(PreWriteCallback callback);
    
    /**
     * @brief Set emergency backup callback (wired by startup to FileBackupManager)
     */
    void SetEmergencyBackupCallback(EmergencyBackupCallback callback);

    /**
     * @brief Set emergency snapshot callback (wired by startup to VolumeSnapshotService)
     */
    void SetEmergencySnapshotCallback(EmergencySnapshotCallback callback);

    /**
     * @brief Set lockdown callback (wired by startup to ShadowCopyProtector)
     */
    void SetLockdownCallback(LockdownCallback callback);

    /**
     * @brief Set recovery callback (wired by startup to RansomwareDecryptor)
     */
    void SetRecoveryCallback(RecoveryCallback callback);

    // ========================================================================
    // CONTAINMENT MODE
    // ========================================================================

    /**
     * @brief Enter ransomware containment — emergency lockdown
     * Blocks all non-agent file writes via kernel driver IOCTL
     */
    void EnterContainmentMode();

    /**
     * @brief Exit containment mode
     */
    void ExitContainmentMode();

    /**
     * @brief Check if containment mode is active
     */
    [[nodiscard]] bool IsInContainmentMode() const noexcept;

    /**
     * @brief Mark process as recovery (decryptor I/O) — exempted from detection
     */
    void RegisterRecoveryProcess(uint32_t pid);

    /**
     * @brief Remove recovery process exemption
     */
    void UnregisterRecoveryProcess(uint32_t pid);

    /**
     * @brief Check if a process is a recovery process
     */
    [[nodiscard]] bool IsRecoveryProcess(uint32_t pid) const;

    // ========================================================================
    // STATISTICS
    // ========================================================================
    
    /**
     * @brief Get detection statistics
     */
    [[nodiscard]] DetectionStatisticsSnapshot GetStatistics() const;
    
    /**
     * @brief Reset statistics
     */
    void ResetStatistics();
    
    /**
     * @brief Get recent detections
     */
    [[nodiscard]] std::vector<DetectionEvent> GetRecentDetections(
        size_t maxCount = 100) const;
    
    // ========================================================================
    // UTILITY
    // ========================================================================
    
    /**
     * @brief Check if file type is typically high entropy
     */
    [[nodiscard]] bool IsCompressedType(std::wstring_view filePath) const;
    
    /**
     * @brief Check if path is in protected directory
     */
    [[nodiscard]] bool IsProtectedPath(std::wstring_view filePath) const;
    
    /**
     * @brief Report false positive
     */
    void ReportFalsePositive(uint64_t eventId, const std::string& reason);
    
    /**
     * @brief Self-test
     */
    [[nodiscard]] bool SelfTest();
    
    /**
     * @brief Get version string
     */
    [[nodiscard]] static std::string GetVersionString() noexcept;

    // ========================================================================
    // KERNEL BRIDGE
    // ========================================================================

    /// @brief Called from kernel process creation notify callback.
    void OnKernelProcessNotify(uint32_t processId, std::wstring_view imagePath,
                               std::wstring_view commandLine, bool isCreate);
    /// @brief Called from kernel image load notify callback.
    void OnKernelImageLoad(uint32_t processId, std::wstring_view imagePath,
                           uint64_t imageBase, size_t imageSize);
    /// @brief Request kernel to block a process via IPC.
    [[nodiscard]] bool RequestKernelProcessBlock(uint32_t processId,
                                                 const std::wstring& reason);

    // ========================================================================
    // CROSS-MODULE WIRING
    // ========================================================================

    /// @brief Report ransomware detection to AlertSystem for SOC visibility.
    void ReportThreatToAlertSystem(const DetectionEvent& event);
    /// @brief Report detection telemetry to TelemetryCollector.
    void ReportDetectionTelemetry(const DetectionEvent& event);

private:
    // ========================================================================
    // PRIVATE CONSTRUCTOR
    // ========================================================================
    
    RansomwareDetector();
    ~RansomwareDetector();
    
    // ========================================================================
    // PIMPL
    // ========================================================================
    
    std::unique_ptr<RansomwareDetectorImpl> m_impl;
    
    // ========================================================================
    // STATIC INSTANCE FLAG
    // ========================================================================
    
    static std::atomic<bool> s_instanceCreated;
};

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

/**
 * @brief Get verdict name
 */
[[nodiscard]] std::string_view GetVerdictName(DetectionVerdict verdict) noexcept;

/**
 * @brief Get action name
 */
[[nodiscard]] std::string_view GetActionName(DetectionAction action) noexcept;

/**
 * @brief Get technique name
 */
[[nodiscard]] std::string_view GetTechniqueName(DetectionTechnique technique) noexcept;

/**
 * @brief Get family name
 */
[[nodiscard]] std::string_view GetFamilyName(RansomwareFamily family) noexcept;

/**
 * @brief Get risk level name
 */
[[nodiscard]] std::string_view GetRiskLevelName(ProcessRiskLevel level) noexcept;

/**
 * @brief Get operation type name
 */
[[nodiscard]] std::string_view GetOperationTypeName(FileOperationType type) noexcept;

/**
 * @brief Format detection flags as string
 */
[[nodiscard]] std::string FormatDetectionFlags(uint16_t flags);

/**
 * @brief Calculate confidence from multiple factors
 */
[[nodiscard]] double CalculateConfidence(
    double entropy, uint32_t writeRate, uint32_t renameRate,
    bool honeypotTriggered, bool knownFamily);

}  // namespace Ransomware
}  // namespace ShadowStrike

// ============================================================================
// MACROS
// ============================================================================

/**
 * @brief Analyze write operation
 */
#define SS_RANSOM_ANALYZE_WRITE(pid, buffer, path) \
    ::ShadowStrike::Ransomware::RansomwareDetector::Instance().AnalyzeWrite((pid), (buffer), (path))

/**
 * @brief Analyze rename operation
 */
#define SS_RANSOM_ANALYZE_RENAME(pid, old_path, new_path) \
    ::ShadowStrike::Ransomware::RansomwareDetector::Instance().AnalyzeRename((pid), (old_path), (new_path))
