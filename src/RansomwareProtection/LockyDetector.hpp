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
    
    /// @brief Ransom note patterns
    inline constexpr const wchar_t* RANSOM_NOTE_PATTERNS[] = {
        L"_Locky_recover_instructions.txt",
        L"_HELP_instructions.html",
        L"_HOWDO_text.html",
        L"info.html"
    };
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
    // PATTERN MANAGEMENT
    // ========================================================================
    
    /**
     * @brief Add known C2 domain
     */
    void AddKnownC2Domain(std::string_view domain);
    
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
