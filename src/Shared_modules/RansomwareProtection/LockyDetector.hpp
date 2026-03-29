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
 * ShadowStrike Ransomware Detection - LOCKY FAMILY DETECTOR
 * ============================================================================
 *
 * @file LockyDetector.hpp
 * @brief Enterprise-grade specific detection module for Locky ransomware
 *        family variants including Zepto, Odin, Thor, Aesir, and others.
 *
 * Locky is a prolific ransomware family known for:
 * - Rapid file renaming to .locky, .zepto, .odin, .thor, .aesir extensions
 * - VSS destruction via WMIC
 * - Unique C2 communication patterns
 * - DGA (Domain Generation Algorithm) for C2
 * - Specific ransom note formats
 *
 * DETECTION CAPABILITIES:
 * =======================
 *
 * 1. EXTENSION MONITORING
 *    - .locky (original)
 *    - .zepto
 *    - .odin
 *    - .thor
 *    - .aesir
 *    - .zzzzz
 *    - .osiris
 *    - .diablo6
 *    - .lukitus
 *
 * 2. BEHAVIORAL PATTERNS
 *    - Rapid bulk renaming
 *    - RSA-2048 + AES-128 encryption pattern
 *    - Unique file header modifications
 *    - Specific directory traversal patterns
 *
 * 3. C2 DETECTION
 *    - Known Locky DGA patterns
 *    - .onion communication
 *    - Specific HTTP patterns
 *    - Payment portal detection
 *
 * 4. ARTIFACT DETECTION
 *    - Ransom note: _Locky_recover_instructions.txt
 *    - HTML ransom notes
 *    - BMP wallpaper changes
 *    - Registry persistence
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
#include <optional>
#include <memory>
#include <functional>
#include <chrono>
#include <atomic>
#include <mutex>
#include <unordered_set>

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
#include "../Utils/ProcessUtils.hpp"
#include "../Utils/NetworkUtils.hpp"
#include "../PatternStore/PatternStore.hpp"
#include "../HashStore/HashStore.hpp"

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

namespace ShadowStrike::Ransomware {
    class LockyDetectorImpl;
}

namespace ShadowStrike {
namespace Ransomware {

// ============================================================================
// COMPILE-TIME CONSTANTS
// ============================================================================

namespace LockyConstants {
    inline constexpr uint32_t VERSION_MAJOR = 3;
    inline constexpr uint32_t VERSION_MINOR = 0;
    inline constexpr uint32_t VERSION_PATCH = 0;
    
    /// @brief Known Locky extensions
    inline constexpr const wchar_t* LOCKY_EXTENSIONS[] = {
        L".locky", L".zepto", L".odin", L".thor", L".aesir",
        L".zzzzz", L".osiris", L".diablo6", L".lukitus", L".ykcol"
    };
    
    /// @brief Ransom note patterns (all known Locky variants)
    inline constexpr const wchar_t* RANSOM_NOTE_PATTERNS[] = {
        L"_Locky_recover_instructions.txt",
        L"_HELP_instructions.html",
        L"_HOWDO_text.html",
        L"_HOWDO_text.bmp",
        L"_README_.html",
        L"_README_.txt",
        L"_README_.bmp",
        L"info.html",
        L"info.bmp",
        L"DesktopOSIRIS.htm",
        L"DesktopOSIRIS.bmp",
        L"OSIRIS.htm",
        L"OSIRIS.bmp",
        L"diablo6.htm",
        L"diablo6.bmp",
        L"lukitus.htm",
        L"lukitus.bmp"
    };

    // ====================================================================
    // BEHAVIORAL THRESHOLDS
    // ====================================================================

    /// @brief Default correlation window in seconds
    inline constexpr uint32_t DEFAULT_CORRELATION_WINDOW_SECS = 60;

    /// @brief Mass-rename threshold within correlation window
    inline constexpr uint32_t DEFAULT_MASS_RENAME_THRESHOLD = 10;

    /// @brief Mass-write threshold within correlation window
    inline constexpr uint32_t DEFAULT_MASS_WRITE_THRESHOLD = 25;

    /// @brief High-entropy threshold (Shannon)
    inline constexpr double HIGH_ENTROPY_THRESHOLD = 7.5;

    // ====================================================================
    // DETECTION SCORE WEIGHTS
    // ====================================================================

    inline constexpr double SCORE_KNOWN_HASH          = 100.0;
    inline constexpr double SCORE_LOCKY_EXT_RENAME    =  25.0;
    inline constexpr double SCORE_MASS_RENAME          =  20.0;
    inline constexpr double SCORE_HIGH_ENTROPY_WRITE   =  15.0;
    inline constexpr double SCORE_RANSOM_NOTE           =  30.0;
    inline constexpr double SCORE_VSS_DESTRUCTION       =  35.0;
    inline constexpr double SCORE_REGISTRY_PERSISTENCE  =  20.0;
    inline constexpr double SCORE_WALLPAPER_CHANGE      =  15.0;
    inline constexpr double SCORE_DGA_DOMAIN            =  25.0;
    inline constexpr double SCORE_GUID_MUTEX            =  15.0;
    inline constexpr double SCORE_DROPPER_BEHAVIOR      =  20.0;
    inline constexpr double SCORE_MEMORY_PATTERN        =  30.0;
    inline constexpr double SCORE_MULTI_DIR_ACTIVITY    =  15.0;
    inline constexpr double SCORE_HEX_RENAME_PATTERN    =  20.0;

    // ====================================================================
    // CONFIDENCE THRESHOLDS
    // ====================================================================

    inline constexpr double CONFIDENCE_LOW_THRESHOLD       = 20.0;
    inline constexpr double CONFIDENCE_MEDIUM_THRESHOLD    = 45.0;
    inline constexpr double CONFIDENCE_HIGH_THRESHOLD      = 70.0;
    inline constexpr double CONFIDENCE_CONFIRMED_THRESHOLD = 90.0;

    /// @brief Maximum tracked processes to prevent memory exhaustion
    inline constexpr size_t MAX_TRACKED_PROCESSES = 2048;

    /// @brief Stale process entry age in seconds
    inline constexpr uint32_t STALE_PROCESS_AGE_SECS = 600;
}

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
 * @brief Locky variant
 */
enum class LockyVariant : uint8_t {
    Unknown     = 0,
    Original    = 1,    ///< Original .locky
    Zepto       = 2,    ///< .zepto variant
    Odin        = 3,    ///< .odin variant
    Thor        = 4,    ///< .thor variant
    Aesir       = 5,    ///< .aesir variant
    Zzzzz       = 6,    ///< .zzzzz variant
    Osiris      = 7,    ///< .osiris variant
    Diablo6     = 8,    ///< .diablo6 variant
    Lukitus     = 9,    ///< .lukitus variant
    Ykcol       = 10    ///< .ykcol variant
};

/**
 * @brief Detection confidence
 */
enum class DetectionConfidence : uint8_t {
    None        = 0,
    Low         = 1,
    Medium      = 2,
    High        = 3,
    Confirmed   = 4
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
 * @brief Locky detection result
 */
struct LockyDetectionResult {
    /// @brief Is Locky detected
    bool detected = false;
    
    /// @brief Variant identified
    LockyVariant variant = LockyVariant::Unknown;
    
    /// @brief Confidence level
    DetectionConfidence confidence = DetectionConfidence::None;
    
    /// @brief Process ID
    uint32_t pid = 0;
    
    /// @brief Process name
    std::wstring processName;
    
    /// @brief Indicators found
    std::vector<std::string> indicators;
    
    /// @brief Extensions observed
    std::vector<std::wstring> extensionsObserved;
    
    /// @brief Ransom notes found
    std::vector<std::wstring> ransomNotesFound;
    
    /// @brief C2 domains contacted
    std::vector<std::string> c2Domains;
    
    /// @brief Files encrypted count
    uint32_t filesEncrypted = 0;
    
    /// @brief Accumulated behavioral score
    double score = 0.0;
    
    /// @brief Detection time
    SystemTimePoint detectionTime;
    
    /**
     * @brief Serialize to JSON
     */
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Locky detector configuration
 */
struct LockyDetectorConfiguration {
    /// @brief Enable detection
    bool enabled = true;
    
    /// @brief Monitor extensions
    bool monitorExtensions = true;
    
    /// @brief Monitor C2 domains
    bool monitorC2 = true;
    
    /// @brief Monitor ransom notes
    bool monitorRansomNotes = true;
    
    /// @brief Minimum confidence for alert
    DetectionConfidence minAlertConfidence = DetectionConfidence::Medium;
    
    /// @brief Auto-terminate on detection
    bool autoTerminate = true;
    
    /// @brief Correlation window for behavioral events (seconds)
    uint32_t correlationWindowSecs = LockyConstants::DEFAULT_CORRELATION_WINDOW_SECS;
    
    /// @brief Mass rename threshold (renames within correlation window)
    uint32_t massRenameThreshold = LockyConstants::DEFAULT_MASS_RENAME_THRESHOLD;
    
    /// @brief Mass write threshold (writes within correlation window)
    uint32_t massWriteThreshold = LockyConstants::DEFAULT_MASS_WRITE_THRESHOLD;
    
    /// @brief Score threshold for alerts
    double scoreAlertThreshold = LockyConstants::CONFIDENCE_MEDIUM_THRESHOLD;
    
    /// @brief Score threshold for auto-kill
    double scoreBlockThreshold = LockyConstants::CONFIDENCE_HIGH_THRESHOLD;
    
    /// @brief Whitelisted process names (case-insensitive)
    std::vector<std::wstring> whitelistedProcesses;
    
    /// @brief Verbose logging
    bool verboseLogging = false;
    
    /**
     * @brief Validate configuration
     */
    [[nodiscard]] bool IsValid() const noexcept;
};

/**
 * @brief Locky detection statistics
 */
struct LockyStatistics {
    /// @brief Detections
    std::atomic<uint64_t> totalDetections{0};
    
    /// @brief By variant
    std::array<std::atomic<uint64_t>, 12> byVariant{};
    
    /// @brief Processes terminated
    std::atomic<uint64_t> processesTerminated{0};
    
    /// @brief Start time
    TimePoint startTime = Clock::now();
    
    void Reset() noexcept;
    [[nodiscard]] std::string ToJson() const;
};

// ============================================================================
// CALLBACK TYPES
// ============================================================================

using LockyDetectionCallback = std::function<void(const LockyDetectionResult&)>;

// ============================================================================
// LOCKY DETECTOR CLASS
// ============================================================================

/**
 * @class LockyDetector
 * @brief Specialized detector for Locky ransomware family
 *
 * Provides targeted detection for all known Locky variants.
 *
 * THREAD SAFETY: All public methods are thread-safe.
 */
class LockyDetector final {
public:
    // ========================================================================
    // SINGLETON ACCESS
    // ========================================================================
    
    [[nodiscard]] static LockyDetector& Instance() noexcept;
    [[nodiscard]] static bool HasInstance() noexcept;
    
    LockyDetector(const LockyDetector&) = delete;
    LockyDetector& operator=(const LockyDetector&) = delete;
    LockyDetector(LockyDetector&&) = delete;
    LockyDetector& operator=(LockyDetector&&) = delete;

    // ========================================================================
    // LIFECYCLE MANAGEMENT
    // ========================================================================
    
    [[nodiscard]] bool Initialize(const LockyDetectorConfiguration& config = {});
    void Shutdown();
    [[nodiscard]] bool IsInitialized() const noexcept;
    [[nodiscard]] ModuleStatus GetStatus() const noexcept;
    
    // ========================================================================
    // DETECTION
    // ========================================================================
    
    /**
     * @brief Detect Locky in process
     */
    [[nodiscard]] bool Detect(uint32_t pid);
    
    /**
     * @brief Full detection with result
     */
    [[nodiscard]] LockyDetectionResult DetectEx(uint32_t pid);
    
    /**
     * @brief Check if extension is Locky
     */
    [[nodiscard]] bool IsLockyExtension(std::wstring_view extension) const;
    
    /**
     * @brief Identify variant from extension
     */
    [[nodiscard]] LockyVariant IdentifyVariant(std::wstring_view extension) const;
    
    /**
     * @brief Check if file is Locky ransom note
     */
    [[nodiscard]] bool IsLockyRansomNote(std::wstring_view filename) const;
    
    /**
     * @brief Check if domain is known Locky C2
     */
    [[nodiscard]] bool IsLockyC2Domain(std::string_view domain) const;
    
    /**
     * @brief Analyze file for Locky encryption
     */
    [[nodiscard]] bool AnalyzeEncryptedFile(std::wstring_view filePath);
    
    // ========================================================================
    // BEHAVIORAL EVENT HANDLERS
    // ========================================================================
    
    /**
     * @brief Process a file rename event (from kernel minifilter)
     * @param pid Process performing the rename
     * @param oldPath Original file path
     * @param newPath New file path (with potentially Locky extension)
     * @return Detection result if score exceeds alert threshold
     */
    [[nodiscard]] std::optional<LockyDetectionResult> OnFileRename(
        uint32_t pid, std::wstring_view oldPath, std::wstring_view newPath);
    
    /**
     * @brief Process a file write event
     * @param pid Process performing the write
     * @param filePath File being written
     * @param dataSize Bytes written
     * @param entropy Shannon entropy of written data (0-8)
     * @return Detection result if score exceeds alert threshold
     */
    [[nodiscard]] std::optional<LockyDetectionResult> OnFileWrite(
        uint32_t pid, std::wstring_view filePath,
        size_t dataSize, double entropy);
    
    /**
     * @brief Process a process creation event (dropper chain detection)
     * @param pid New process PID
     * @param parentPid Parent process PID
     * @param imagePath Executable path
     * @param commandLine Full command line
     * @return Detection result if score exceeds alert threshold
     */
    [[nodiscard]] std::optional<LockyDetectionResult> OnProcessCreate(
        uint32_t pid, uint32_t parentPid,
        std::wstring_view imagePath, std::wstring_view commandLine);
    
    /**
     * @brief Process a DNS query event (DGA detection)
     * @param pid Process making the query
     * @param domain Domain being queried
     * @return Detection result if score exceeds alert threshold
     */
    [[nodiscard]] std::optional<LockyDetectionResult> OnDnsQuery(
        uint32_t pid, std::string_view domain);
    
    /**
     * @brief Process a registry write event
     * @param pid Process writing registry
     * @param keyPath Full registry key path
     * @param valueName Value name being written
     * @param data Value data
     * @return Detection result if score exceeds alert threshold
     */
    [[nodiscard]] std::optional<LockyDetectionResult> OnRegistryWrite(
        uint32_t pid, std::wstring_view keyPath,
        std::wstring_view valueName, std::wstring_view data);
    
    /**
     * @brief Process a mutex creation event
     * @param pid Process creating the mutex
     * @param mutexName Mutex name
     * @return Detection result if score exceeds alert threshold
     */
    [[nodiscard]] std::optional<LockyDetectionResult> OnMutexCreate(
        uint32_t pid, std::wstring_view mutexName);
    
    /**
     * @brief Get accumulated score for a process
     */
    [[nodiscard]] double GetProcessScore(uint32_t pid) const;
    
    /**
     * @brief Build detection result from accumulated behavioral state
     */
    [[nodiscard]] LockyDetectionResult BuildResultFromBehavior(uint32_t pid) const;
    
    /**
     * @brief Purge stale process tracking entries
     */
    void PurgeStaleProcesses();
    
    // ========================================================================
    // PATTERN MANAGEMENT
    // ========================================================================
    
    /**
     * @brief Add known C2 domain
     */
    void AddKnownC2Domain(std::string_view domain);
    
    /**
     * @brief Add known malicious hash (SHA-256 hex lowercase)
     */
    void AddKnownHash(std::string_view sha256Hex);
    
    /**
     * @brief Add known extension
     */
    void AddKnownExtension(std::wstring_view extension);
    
    /**
     * @brief Update patterns from threat intel
     */
    void UpdatePatternsFromThreatIntel();
    
    // ========================================================================
    // CALLBACKS
    // ========================================================================
    
    void SetDetectionCallback(LockyDetectionCallback callback);
    
    // ========================================================================
    // STATISTICS
    // ========================================================================
    
    [[nodiscard]] LockyStatistics GetStatistics() const;
    void ResetStatistics();
    
    // ========================================================================
    // UTILITY
    // ========================================================================
    
    [[nodiscard]] bool SelfTest();
    [[nodiscard]] static std::string GetVersionString() noexcept;

private:
    LockyDetector();
    ~LockyDetector();
    
    std::unique_ptr<LockyDetectorImpl> m_impl;
    static std::atomic<bool> s_instanceCreated;
};

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

[[nodiscard]] std::string_view GetLockyVariantName(LockyVariant variant) noexcept;
[[nodiscard]] std::string_view GetDetectionConfidenceName(DetectionConfidence conf) noexcept;
[[nodiscard]] std::wstring_view GetLockyExtension(LockyVariant variant) noexcept;

}  // namespace Ransomware
}  // namespace ShadowStrike

// ============================================================================
// MACROS
// ============================================================================

#define SS_DETECT_LOCKY(pid) \
    ::ShadowStrike::Ransomware::LockyDetector::Instance().Detect(pid)

#define SS_IS_LOCKY_EXT(ext) \
    ::ShadowStrike::Ransomware::LockyDetector::Instance().IsLockyExtension(ext)
