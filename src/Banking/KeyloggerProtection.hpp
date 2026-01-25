/**
 * ============================================================================
 * ShadowStrike Banking Protection - KEYLOGGER PROTECTION
 * ============================================================================
 *
 * @file KeyloggerProtection.hpp
 * @brief Enterprise-grade keylogger protection engine for securing user input
 *        against keystroke capture and credential theft attacks.
 *
 * This module provides comprehensive protection against software and hardware
 * keyloggers, clipboard monitors, screen scrapers, and other input-based
 * credential theft vectors used by banking trojans.
 *
 * PROTECTION CAPABILITIES:
 * ========================
 *
 * 1. KEYBOARD HOOK DETECTION
 *    - SetWindowsHookEx hooks
 *    - Raw input hooks
 *    - DirectInput hooks
 *    - Low-level keyboard hooks
 *    - Journal hooks
 *
 * 2. INPUT PROTECTION
 *    - Secure input mode for credentials
 *    - Keystroke encryption
 *    - Anti-screenshot for password fields
 *    - Virtual keyboard support
 *    - Input scrambling
 *
 * 3. CLIPBOARD PROTECTION
 *    - Clipboard monitor detection
 *    - Credential auto-clear
 *    - Copy/paste protection
 *    - Clipboard history blocking
 *
 * 4. API MONITORING
 *    - GetAsyncKeyState monitoring
 *    - GetKeyState monitoring
 *    - GetKeyboardState monitoring
 *    - ReadConsole monitoring
 *    - DirectInput APIs
 *
 * 5. BEHAVIORAL DETECTION
 *    - Suspicious keyboard access patterns
 *    - Input logging detection
 *    - Keylogger file patterns
 *    - Credential field access
 *
 * 6. HARDWARE PROTECTION
 *    - USB device monitoring
 *    - PS/2 filter detection
 *    - HID device tampering
 *    - Keyboard firmware analysis
 *
 * INTEGRATION:
 * ============
 * - Utils::ProcessUtils for process monitoring
 * - Utils::RegistryUtils for persistence detection
 * - HashStore for known keylogger matching
 * - ThreatIntel for IOC lookup
 *
 * @note Requires system-level privileges for full protection.
 * @note Some features require kernel driver for complete coverage.
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @date 2026
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 *
 * COMPLIANCE: PCI-DSS 4.0, SOC2, ISO 27001
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
#include <memory>
#include <functional>
#include <chrono>
#include <atomic>
#include <mutex>
#include <shared_mutex>
#include <span>
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
#include "../Utils/ProcessUtils.hpp"
#include "../Utils/MemoryUtils.hpp"
#include "../Utils/RegistryUtils.hpp"
#include "../HashStore/HashStore.hpp"
#include "../PatternStore/PatternStore.hpp"
#include "../ThreatIntel/ThreatIntelManager.hpp"
#include "../Whitelist/WhiteListStore.hpp"

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

namespace ShadowStrike::Banking {
    class KeyloggerProtectionImpl;
}

namespace ShadowStrike {
namespace Banking {

// ============================================================================
// COMPILE-TIME CONSTANTS
// ============================================================================

namespace KeyloggerConstants {

    // ========================================================================
    // VERSION
    // ========================================================================
    
    inline constexpr uint32_t VERSION_MAJOR = 3;
    inline constexpr uint32_t VERSION_MINOR = 0;
    inline constexpr uint32_t VERSION_PATCH = 0;

    // ========================================================================
    // LIMITS
    // ========================================================================
    
    /// @brief Maximum hooks to track
    inline constexpr size_t MAX_TRACKED_HOOKS = 256;
    
    /// @brief Maximum processes to monitor
    inline constexpr size_t MAX_MONITORED_PROCESSES = 512;
    
    /// @brief Maximum protected windows
    inline constexpr size_t MAX_PROTECTED_WINDOWS = 128;
    
    /// @brief Input buffer size
    inline constexpr size_t INPUT_BUFFER_SIZE = 4096;
    
    /// @brief Clipboard auto-clear timeout (seconds)
    inline constexpr uint32_t CLIPBOARD_AUTO_CLEAR_SECS = 30;

    // ========================================================================
    // TIMING
    // ========================================================================
    
    /// @brief Hook scan interval (milliseconds)
    inline constexpr uint32_t HOOK_SCAN_INTERVAL_MS = 500;
    
    /// @brief Process monitor interval (milliseconds)
    inline constexpr uint32_t PROCESS_MONITOR_INTERVAL_MS = 1000;
    
    /// @brief Behavioral analysis window (seconds)
    inline constexpr uint32_t BEHAVIORAL_WINDOW_SECS = 30;

    // ========================================================================
    // THRESHOLDS
    // ========================================================================
    
    /// @brief Suspicious keystroke rate (per second)
    inline constexpr uint32_t SUSPICIOUS_KEYSTROKE_RATE = 100;
    
    /// @brief API call threshold for detection
    inline constexpr uint32_t API_CALL_THRESHOLD = 1000;
    
    /// @brief Confidence threshold
    inline constexpr double CONFIDENCE_THRESHOLD = 0.7;

}  // namespace KeyloggerConstants

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
 * @brief Keylogger type
 */
enum class KeyloggerType : uint8_t {
    Unknown             = 0,
    SoftwareHook        = 1,    ///< Windows hook-based
    RawInput            = 2,    ///< Raw input based
    DirectInput         = 3,    ///< DirectInput based
    APIPolling          = 4,    ///< GetAsyncKeyState polling
    KernelDriver        = 5,    ///< Kernel-level driver
    FormGrabber         = 6,    ///< Form field grabbing
    Hardware            = 7,    ///< Hardware keylogger
    ScreenCapture       = 8,    ///< Screenshot-based
    Acoustic            = 9     ///< Acoustic analysis (rare)
};

/**
 * @brief Hook type
 */
enum class KeyboardHookType : uint8_t {
    Unknown             = 0,
    WH_KEYBOARD         = 1,    ///< Standard keyboard hook
    WH_KEYBOARD_LL      = 2,    ///< Low-level keyboard hook
    WH_JOURNALRECORD    = 3,    ///< Journal record hook
    WH_GETMESSAGE       = 4,    ///< GetMessage hook
    RawInputDevice      = 5,    ///< Raw input registered
    DirectInputHook     = 6     ///< DirectInput hook
};

/**
 * @brief Protection mode
 */
enum class ProtectionMode : uint8_t {
    Disabled            = 0,
    Monitor             = 1,    ///< Monitor only
    Protect             = 2,    ///< Active protection
    Aggressive          = 3     ///< Maximum protection
};

/**
 * @brief Threat severity
 */
enum class ThreatSeverity : uint8_t {
    None        = 0,
    Low         = 1,
    Medium      = 2,
    High        = 3,
    Critical    = 4
};

/**
 * @brief Input field type
 */
enum class InputFieldType : uint8_t {
    Unknown     = 0,
    Password    = 1,
    PIN         = 2,
    CreditCard  = 3,
    SSN         = 4,
    CVV         = 5,
    Username    = 6,
    Email       = 7,
    OTP         = 8,
    Generic     = 9
};

/**
 * @brief Detection action
 */
enum class DetectionAction : uint8_t {
    None            = 0,
    Alert           = 1,
    Block           = 2,
    Terminate       = 3,
    Quarantine      = 4
};

/**
 * @brief Module status
 */
enum class ModuleStatus : uint8_t {
    Uninitialized   = 0,
    Initializing    = 1,
    Running         = 2,
    Paused          = 3,
    Stopping        = 4,
    Stopped         = 5,
    Error           = 6
};

// ============================================================================
// STRUCTURES
// ============================================================================

/**
 * @brief Keyboard hook info
 */
struct KeyboardHookInfo {
    /// @brief Hook handle
    uint64_t hookHandle = 0;
    
    /// @brief Hook type
    KeyboardHookType hookType = KeyboardHookType::Unknown;
    
    /// @brief Process ID
    uint32_t processId = 0;
    
    /// @brief Thread ID
    uint32_t threadId = 0;
    
    /// @brief Process name
    std::wstring processName;
    
    /// @brief Process path
    std::wstring processPath;
    
    /// @brief Module name
    std::wstring moduleName;
    
    /// @brief Hook procedure address
    uint64_t hookProc = 0;
    
    /// @brief Is global hook
    bool isGlobal = false;
    
    /// @brief Is suspicious
    bool isSuspicious = false;
    
    /// @brief Detection time
    SystemTimePoint detectionTime;
    
    /// @brief Confidence score
    double confidence = 0.0;
    
    /**
     * @brief Serialize to JSON
     */
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Suspicious API call info
 */
struct SuspiciousAPICall {
    /// @brief API name
    std::string apiName;
    
    /// @brief Process ID
    uint32_t processId = 0;
    
    /// @brief Process name
    std::wstring processName;
    
    /// @brief Call count (in window)
    uint64_t callCount = 0;
    
    /// @brief Call rate per second
    double callRate = 0.0;
    
    /// @brief Target window handle
    uint64_t targetWindow = 0;
    
    /// @brief Target window title
    std::wstring targetWindowTitle;
    
    /// @brief Is targeting sensitive field
    bool isTargetingSensitive = false;
    
    /// @brief Detection time
    SystemTimePoint detectionTime;
    
    /**
     * @brief Serialize to JSON
     */
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Clipboard threat info
 */
struct ClipboardThreatInfo {
    /// @brief Process ID accessing clipboard
    uint32_t processId = 0;
    
    /// @brief Process name
    std::wstring processName;
    
    /// @brief Access type (read/write)
    std::string accessType;
    
    /// @brief Data type accessed
    std::string dataType;
    
    /// @brief Contains sensitive data
    bool containsSensitive = false;
    
    /// @brief Detection time
    SystemTimePoint detectionTime;
    
    /**
     * @brief Serialize to JSON
     */
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Protected window info
 */
struct ProtectedWindowInfo {
    /// @brief Window handle
    uint64_t windowHandle = 0;
    
    /// @brief Window title
    std::wstring windowTitle;
    
    /// @brief Window class
    std::wstring windowClass;
    
    /// @brief Process ID
    uint32_t processId = 0;
    
    /// @brief Process name
    std::wstring processName;
    
    /// @brief Field type being protected
    InputFieldType fieldType = InputFieldType::Unknown;
    
    /// @brief Is currently focused
    bool isFocused = false;
    
    /// @brief Protection enabled
    bool protectionEnabled = true;
    
    /**
     * @brief Serialize to JSON
     */
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Detection event
 */
struct KeyloggerDetectionEvent {
    /// @brief Event ID
    std::string eventId;
    
    /// @brief Keylogger type
    KeyloggerType keyloggerType = KeyloggerType::Unknown;
    
    /// @brief Severity
    ThreatSeverity severity = ThreatSeverity::None;
    
    /// @brief Threat score (0-100)
    double threatScore = 0.0;
    
    /// @brief Confidence (0-1)
    double confidence = 0.0;
    
    /// @brief Process ID
    uint32_t processId = 0;
    
    /// @brief Process name
    std::wstring processName;
    
    /// @brief Process path
    std::wstring processPath;
    
    /// @brief File hash
    Hash256 fileHash{};
    
    /// @brief Description
    std::string description;
    
    /// @brief Detected hooks
    std::vector<KeyboardHookInfo> detectedHooks;
    
    /// @brief Suspicious API calls
    std::vector<SuspiciousAPICall> suspiciousAPIs;
    
    /// @brief Action taken
    DetectionAction actionTaken = DetectionAction::None;
    
    /// @brief Detection time
    SystemTimePoint detectionTime;
    
    /// @brief Is whitelisted
    bool isWhitelisted = false;
    
    /**
     * @brief Serialize to JSON
     */
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Protection statistics
 */
struct KeyloggerProtectionStatistics {
    /// @brief Total scans performed
    std::atomic<uint64_t> totalScans{0};
    
    /// @brief Threats detected
    std::atomic<uint64_t> threatsDetected{0};
    
    /// @brief Hooks blocked
    std::atomic<uint64_t> hooksBlocked{0};
    
    /// @brief API calls intercepted
    std::atomic<uint64_t> apiCallsIntercepted{0};
    
    /// @brief Clipboard accesses blocked
    std::atomic<uint64_t> clipboardBlocked{0};
    
    /// @brief Protected keystrokes
    std::atomic<uint64_t> protectedKeystrokes{0};
    
    /// @brief False positives reported
    std::atomic<uint64_t> falsePositives{0};
    
    /// @brief Start time
    TimePoint startTime = Clock::now();
    
    /// @brief Last detection time
    SystemTimePoint lastDetectionTime;
    
    /**
     * @brief Reset statistics
     */
    void Reset() noexcept;
    
    /**
     * @brief Serialize to JSON
     */
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Configuration
 */
struct KeyloggerProtectionConfiguration {
    /// @brief Protection mode
    ProtectionMode protectionMode = ProtectionMode::Protect;
    
    /// @brief Enable hook detection
    bool enableHookDetection = true;
    
    /// @brief Enable API monitoring
    bool enableAPIMonitoring = true;
    
    /// @brief Enable clipboard protection
    bool enableClipboardProtection = true;
    
    /// @brief Enable input encryption
    bool enableInputEncryption = true;
    
    /// @brief Enable screenshot protection
    bool enableScreenshotProtection = true;
    
    /// @brief Enable virtual keyboard
    bool enableVirtualKeyboard = true;
    
    /// @brief Auto-clear clipboard
    bool autoClipboardClear = true;
    
    /// @brief Clipboard clear timeout (seconds)
    uint32_t clipboardClearTimeout = KeyloggerConstants::CLIPBOARD_AUTO_CLEAR_SECS;
    
    /// @brief Block global hooks
    bool blockGlobalHooks = true;
    
    /// @brief Terminate detected keyloggers
    bool terminateKeyloggers = false;
    
    /// @brief Protect all password fields
    bool protectAllPasswordFields = true;
    
    /// @brief Whitelisted processes
    std::vector<std::wstring> whitelistedProcesses;
    
    /// @brief Verbose logging
    bool verboseLogging = false;
    
    /**
     * @brief Validate configuration
     */
    [[nodiscard]] bool IsValid() const noexcept;
};

// ============================================================================
// CALLBACK TYPES
// ============================================================================

/// @brief Detection callback
using DetectionCallback = std::function<void(const KeyloggerDetectionEvent&)>;

/// @brief Error callback
using ErrorCallback = std::function<void(const std::string& message, int code)>;

/// @brief Protected input callback
using ProtectedInputCallback = std::function<void(const std::wstring& input)>;

// ============================================================================
// KEYLOGGER PROTECTION CLASS
// ============================================================================

/**
 * @class KeyloggerProtection
 * @brief Enterprise-grade keylogger protection engine
 *
 * Provides comprehensive protection against keystroke capture attacks
 * including hook-based keyloggers, API polling, and hardware keyloggers.
 *
 * THREAD SAFETY: All public methods are thread-safe.
 *
 * USAGE:
 * @code
 *     auto& protection = KeyloggerProtection::Instance();
 *     protection.Initialize(config);
 *     
 *     // Enable protection for sensitive input
 *     protection.EnableSecureInputMode(windowHandle);
 * @endcode
 */
class KeyloggerProtection final {
public:
    // ========================================================================
    // SINGLETON ACCESS
    // ========================================================================
    
    /**
     * @brief Get singleton instance
     */
    [[nodiscard]] static KeyloggerProtection& Instance() noexcept;
    
    /**
     * @brief Check if instance exists
     */
    [[nodiscard]] static bool HasInstance() noexcept;
    
    // Non-copyable, non-movable
    KeyloggerProtection(const KeyloggerProtection&) = delete;
    KeyloggerProtection& operator=(const KeyloggerProtection&) = delete;
    KeyloggerProtection(KeyloggerProtection&&) = delete;
    KeyloggerProtection& operator=(KeyloggerProtection&&) = delete;

    // ========================================================================
    // LIFECYCLE MANAGEMENT
    // ========================================================================
    
    /**
     * @brief Initialize protection
     */
    [[nodiscard]] bool Initialize(const KeyloggerProtectionConfiguration& config = {});
    
    /**
     * @brief Shutdown protection
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
    
    /**
     * @brief Check if running
     */
    [[nodiscard]] bool IsRunning() const noexcept;
    
    // ========================================================================
    // CONTROL
    // ========================================================================
    
    /**
     * @brief Start protection
     */
    [[nodiscard]] bool Start();
    
    /**
     * @brief Stop protection
     */
    [[nodiscard]] bool Stop();
    
    /**
     * @brief Pause protection
     */
    void Pause();
    
    /**
     * @brief Resume protection
     */
    void Resume();
    
    // ========================================================================
    // CONFIGURATION
    // ========================================================================
    
    /**
     * @brief Update configuration
     */
    [[nodiscard]] bool UpdateConfiguration(const KeyloggerProtectionConfiguration& config);
    
    /**
     * @brief Get current configuration
     */
    [[nodiscard]] KeyloggerProtectionConfiguration GetConfiguration() const;
    
    /**
     * @brief Set protection mode
     */
    void SetProtectionMode(ProtectionMode mode);
    
    /**
     * @brief Get protection mode
     */
    [[nodiscard]] ProtectionMode GetProtectionMode() const noexcept;
    
    // ========================================================================
    // HOOK DETECTION
    // ========================================================================
    
    /**
     * @brief Scan for keyboard hooks
     */
    [[nodiscard]] std::vector<KeyboardHookInfo> ScanKeyboardHooks();
    
    /**
     * @brief Scan hooks in specific process
     */
    [[nodiscard]] std::vector<KeyboardHookInfo> ScanProcessHooks(uint32_t processId);
    
    /**
     * @brief Check if hook is legitimate
     */
    [[nodiscard]] bool IsLegitimateHook(const KeyboardHookInfo& hook) const;
    
    /**
     * @brief Block hook
     */
    [[nodiscard]] bool BlockHook(const KeyboardHookInfo& hook);
    
    /**
     * @brief Unhook all malicious hooks
     */
    [[nodiscard]] size_t UnhookMaliciousHooks();
    
    // ========================================================================
    // SECURE INPUT
    // ========================================================================
    
    /**
     * @brief Enable secure input mode
     */
    [[nodiscard]] bool EnableSecureInputMode(uint64_t windowHandle);
    
    /**
     * @brief Disable secure input mode
     */
    void DisableSecureInputMode(uint64_t windowHandle);
    
    /**
     * @brief Check if secure input active
     */
    [[nodiscard]] bool IsSecureInputActive() const noexcept;
    
    /**
     * @brief Get protected windows
     */
    [[nodiscard]] std::vector<ProtectedWindowInfo> GetProtectedWindows() const;
    
    /**
     * @brief Auto-detect and protect password fields
     */
    void AutoProtectPasswordFields();
    
    // ========================================================================
    // CLIPBOARD PROTECTION
    // ========================================================================
    
    /**
     * @brief Enable clipboard protection
     */
    void EnableClipboardProtection();
    
    /**
     * @brief Disable clipboard protection
     */
    void DisableClipboardProtection();
    
    /**
     * @brief Check clipboard protection status
     */
    [[nodiscard]] bool IsClipboardProtectionEnabled() const noexcept;
    
    /**
     * @brief Clear clipboard
     */
    void ClearClipboard();
    
    /**
     * @brief Get clipboard access events
     */
    [[nodiscard]] std::vector<ClipboardThreatInfo> GetClipboardAccessEvents() const;
    
    // ========================================================================
    // VIRTUAL KEYBOARD
    // ========================================================================
    
    /**
     * @brief Show virtual keyboard
     */
    [[nodiscard]] bool ShowVirtualKeyboard();
    
    /**
     * @brief Hide virtual keyboard
     */
    void HideVirtualKeyboard();
    
    /**
     * @brief Check if virtual keyboard visible
     */
    [[nodiscard]] bool IsVirtualKeyboardVisible() const noexcept;
    
    // ========================================================================
    // KEYLOGGER DETECTION
    // ========================================================================
    
    /**
     * @brief Detect keyloggers
     */
    [[nodiscard]] std::vector<KeyloggerDetectionEvent> DetectKeyloggers();
    
    /**
     * @brief Scan specific process for keylogging
     */
    [[nodiscard]] KeyloggerDetectionEvent ScanProcess(uint32_t processId);
    
    /**
     * @brief Monitor API calls
     */
    [[nodiscard]] std::vector<SuspiciousAPICall> MonitorSuspiciousAPICalls();
    
    /**
     * @brief Check for GetAsyncKeyState abuse
     */
    [[nodiscard]] bool DetectGetAsyncKeyStateAbuse(uint32_t processId);
    
    // ========================================================================
    // REMEDIATION
    // ========================================================================
    
    /**
     * @brief Terminate keylogger process
     */
    [[nodiscard]] bool TerminateKeylogger(uint32_t processId);
    
    /**
     * @brief Quarantine keylogger
     */
    [[nodiscard]] bool QuarantineKeylogger(uint32_t processId);
    
    /**
     * @brief Remove persistence
     */
    [[nodiscard]] bool RemovePersistence(uint32_t processId);
    
    // ========================================================================
    // WHITELIST
    // ========================================================================
    
    /**
     * @brief Check if process is whitelisted
     */
    [[nodiscard]] bool IsWhitelisted(uint32_t processId) const;
    
    /**
     * @brief Add to whitelist
     */
    void AddToWhitelist(uint32_t processId, const std::string& reason);
    
    /**
     * @brief Add path to whitelist
     */
    void AddPathToWhitelist(const std::filesystem::path& path, const std::string& reason);
    
    /**
     * @brief Remove from whitelist
     */
    void RemoveFromWhitelist(uint32_t processId);
    
    // ========================================================================
    // CALLBACKS
    // ========================================================================
    
    /**
     * @brief Register detection callback
     */
    void RegisterDetectionCallback(DetectionCallback callback);
    
    /**
     * @brief Register error callback
     */
    void RegisterErrorCallback(ErrorCallback callback);
    
    /**
     * @brief Unregister callbacks
     */
    void UnregisterCallbacks();
    
    // ========================================================================
    // STATISTICS
    // ========================================================================
    
    /**
     * @brief Get statistics
     */
    [[nodiscard]] KeyloggerProtectionStatistics GetStatistics() const;
    
    /**
     * @brief Reset statistics
     */
    void ResetStatistics();
    
    /**
     * @brief Get recent detections
     */
    [[nodiscard]] std::vector<KeyloggerDetectionEvent> GetRecentDetections(
        size_t maxCount = 100) const;
    
    // ========================================================================
    // UTILITY
    // ========================================================================
    
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
    
    KeyloggerProtection();
    ~KeyloggerProtection();
    
    // ========================================================================
    // PIMPL
    // ========================================================================
    
    std::unique_ptr<KeyloggerProtectionImpl> m_impl;
    
    // ========================================================================
    // STATIC INSTANCE FLAG
    // ========================================================================
    
    static std::atomic<bool> s_instanceCreated;
};

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

/**
 * @brief Get keylogger type name
 */
[[nodiscard]] std::string_view GetKeyloggerTypeName(KeyloggerType type) noexcept;

/**
 * @brief Get hook type name
 */
[[nodiscard]] std::string_view GetKeyboardHookTypeName(KeyboardHookType type) noexcept;

/**
 * @brief Get protection mode name
 */
[[nodiscard]] std::string_view GetProtectionModeName(ProtectionMode mode) noexcept;

/**
 * @brief Get input field type name
 */
[[nodiscard]] std::string_view GetInputFieldTypeName(InputFieldType type) noexcept;

/**
 * @brief Detect sensitive input field
 */
[[nodiscard]] InputFieldType DetectInputFieldType(uint64_t windowHandle);

/**
 * @brief Check if window is password field
 */
[[nodiscard]] bool IsPasswordField(uint64_t windowHandle);

}  // namespace Banking
}  // namespace ShadowStrike

// ============================================================================
// MACROS
// ============================================================================

/**
 * @brief Enable secure input mode for window
 */
#define SS_ENABLE_SECURE_INPUT(hwnd) \
    ::ShadowStrike::Banking::KeyloggerProtection::Instance().EnableSecureInputMode(hwnd)

/**
 * @brief Scan for keyloggers
 */
#define SS_SCAN_KEYLOGGERS() \
    ::ShadowStrike::Banking::KeyloggerProtection::Instance().DetectKeyloggers()
