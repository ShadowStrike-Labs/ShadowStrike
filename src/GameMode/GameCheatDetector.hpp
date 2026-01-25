/**
 * ============================================================================
 * ShadowStrike NGAV - GAME CHEAT DETECTOR MODULE
 * ============================================================================
 *
 * @file GameCheatDetector.hpp
 * @brief Enterprise-grade cheat/trainer detection to protect users from
 *        malware disguised as game cheats and memory manipulation tools.
 *
 * This is NOT a full anti-cheat system (like EAC/BattlEye). Its purpose is
 * to protect users from malicious software that poses as game cheats, which
 * are frequently used as malware delivery vectors.
 *
 * DETECTION CAPABILITIES:
 * =======================
 *
 * 1. KNOWN CHEAT TOOLS
 *    - Cheat Engine
 *    - ArtMoney
 *    - Game trainers
 *    - Memory editors
 *    - Speed hacks
 *    - Wallhacks/ESP loaders
 *
 * 2. MEMORY MANIPULATION
 *    - WriteProcessMemory detection
 *    - VirtualAllocEx monitoring
 *    - Code injection detection
 *    - DLL injection tracking
 *    - Handle manipulation
 *
 * 3. MALWARE-CHEAT HYBRIDS
 *    - Trojanized cheats
 *    - RAT-enabled trainers
 *    - Cryptocurrency miners
 *    - Password stealers
 *    - Backdoor loaders
 *
 * 4. BEHAVIORAL ANALYSIS
 *    - Process hollowing
 *    - Debug API abuse
 *    - Anti-VM/sandbox evasion
 *    - Rootkit indicators
 *    - Persistence mechanisms
 *
 * 5. SIGNATURE MATCHING
 *    - Known cheat signatures
 *    - Packer detection
 *    - Obfuscation patterns
 *    - Network indicators
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
#include "../HashStore/HashStore.hpp"
#include "../SignatureStore/SignatureStore.hpp"

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

namespace ShadowStrike::GameMode {
    class GameCheatDetectorImpl;
}

namespace ShadowStrike {
namespace GameMode {

// ============================================================================
// COMPILE-TIME CONSTANTS
// ============================================================================

namespace CheatDetectorConstants {

    inline constexpr uint32_t VERSION_MAJOR = 3;
    inline constexpr uint32_t VERSION_MINOR = 0;
    inline constexpr uint32_t VERSION_PATCH = 0;

    /// @brief Maximum memory scan size (MB)
    inline constexpr size_t MAX_MEMORY_SCAN_MB = 256;
    
    /// @brief Signature database path
    inline constexpr const wchar_t* SIGNATURE_DB_PATH = L"Data\\cheats.sig";
    
    /// @brief Scan timeout (ms)
    inline constexpr uint32_t SCAN_TIMEOUT_MS = 30000;

}  // namespace CheatDetectorConstants

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
 * @brief Cheat type
 */
enum class CheatType : uint8_t {
    Unknown             = 0,
    MemoryEditor        = 1,    ///< Cheat Engine, ArtMoney
    Trainer             = 2,    ///< Game trainers
    SpeedHack           = 3,    ///< Speed manipulation
    Wallhack            = 4,    ///< ESP/Wallhacks
    AimAssist           = 5,    ///< Aimbots
    Injector            = 6,    ///< DLL injectors
    DebuggerBased       = 7,    ///< Debugger-based cheats
    KernelBased         = 8,    ///< Kernel-level cheats
    NetworkBased        = 9,    ///< Packet manipulation
    ScriptBased         = 10    ///< Lua/AutoHotkey scripts
};

/**
 * @brief Threat category
 */
enum class ThreatCategory : uint8_t {
    Clean               = 0,
    PotentiallyUnwanted = 1,    ///< Cheat tool (user chose)
    Suspicious          = 2,    ///< Suspicious behavior
    Malicious           = 3,    ///< Known malware
    Critical            = 4     ///< RAT/Rootkit
};

/**
 * @brief Detection method
 */
enum class CheatDetectionMethod : uint8_t {
    Signature           = 0,
    Hash                = 1,
    ProcessName         = 2,
    WindowClass         = 3,
    MemoryPattern       = 4,
    Behavioral          = 5,
    APIHooking          = 6,
    HandleManipulation  = 7,
    Heuristic           = 8
};

/**
 * @brief Action recommendation
 */
enum class RecommendedAction : uint8_t {
    Allow               = 0,    ///< Allow (user's choice)
    Warn                = 1,    ///< Warn user
    Block               = 2,    ///< Block execution
    Quarantine          = 3,    ///< Quarantine file
    Terminate           = 4     ///< Terminate process
};

/**
 * @brief Module status
 */
enum class CheatDetectorStatus : uint8_t {
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
 * @brief Memory manipulation event
 */
struct MemoryManipulationEvent {
    /// @brief Source process ID
    uint32_t sourceProcessId = 0;
    
    /// @brief Source process name
    std::wstring sourceProcessName;
    
    /// @brief Target process ID
    uint32_t targetProcessId = 0;
    
    /// @brief Target process name
    std::wstring targetProcessName;
    
    /// @brief API called
    std::string apiCalled;
    
    /// @brief Target address
    uint64_t targetAddress = 0;
    
    /// @brief Size
    size_t size = 0;
    
    /// @brief Protection flags
    uint32_t protection = 0;
    
    /// @brief Timestamp
    SystemTimePoint timestamp;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Cheat detection result
 */
struct CheatDetectionResult {
    /// @brief Detection ID
    std::string detectionId;
    
    /// @brief Process ID
    uint32_t processId = 0;
    
    /// @brief Process name
    std::wstring processName;
    
    /// @brief File path
    std::wstring filePath;
    
    /// @brief Cheat type
    CheatType cheatType = CheatType::Unknown;
    
    /// @brief Threat category
    ThreatCategory threatCategory = ThreatCategory::Clean;
    
    /// @brief Detection name
    std::string detectionName;
    
    /// @brief Detection method
    CheatDetectionMethod detectionMethod = CheatDetectionMethod::Signature;
    
    /// @brief Confidence (0-100)
    uint8_t confidence = 0;
    
    /// @brief File hash (SHA256)
    std::string fileHash;
    
    /// @brief Recommended action
    RecommendedAction recommendedAction = RecommendedAction::Allow;
    
    /// @brief Additional indicators
    std::vector<std::string> indicators;
    
    /// @brief Timestamp
    SystemTimePoint timestamp;
    
    /// @brief Is known malware
    bool isKnownMalware = false;
    
    /// @brief Has persistence
    bool hasPersistence = false;
    
    /// @brief Has network activity
    bool hasNetworkActivity = false;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Known cheat tool
 */
struct KnownCheatTool {
    /// @brief Tool ID
    uint64_t toolId = 0;
    
    /// @brief Name
    std::string name;
    
    /// @brief Process names
    std::vector<std::wstring> processNames;
    
    /// @brief Window classes
    std::vector<std::string> windowClasses;
    
    /// @brief Window titles
    std::vector<std::string> windowTitles;
    
    /// @brief Cheat type
    CheatType cheatType = CheatType::Unknown;
    
    /// @brief Default threat category
    ThreatCategory defaultCategory = ThreatCategory::PotentiallyUnwanted;
    
    /// @brief Known hashes
    std::vector<std::string> knownHashes;
    
    /// @brief Description
    std::string description;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Scan result
 */
struct CheatScanResult {
    /// @brief Scan ID
    std::string scanId;
    
    /// @brief Game process ID
    uint32_t gameProcessId = 0;
    
    /// @brief Game process name
    std::wstring gameProcessName;
    
    /// @brief Scan start time
    SystemTimePoint startTime;
    
    /// @brief Scan end time
    SystemTimePoint endTime;
    
    /// @brief Duration (ms)
    uint32_t durationMs = 0;
    
    /// @brief Processes scanned
    uint32_t processesScanned = 0;
    
    /// @brief Memory regions scanned
    uint32_t memoryRegionsScanned = 0;
    
    /// @brief Detections
    std::vector<CheatDetectionResult> detections;
    
    /// @brief Is clean
    [[nodiscard]] bool IsClean() const noexcept { return detections.empty(); }
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Statistics
 */
struct CheatDetectorStatistics {
    std::atomic<uint64_t> totalScans{0};
    std::atomic<uint64_t> detectionsTotal{0};
    std::atomic<uint64_t> detectionsMalicious{0};
    std::atomic<uint64_t> detectionsSuspicious{0};
    std::atomic<uint64_t> detectionsPUP{0};
    std::atomic<uint64_t> memoryManipulations{0};
    std::atomic<uint64_t> processesScanned{0};
    std::atomic<uint64_t> falsePositives{0};
    std::array<std::atomic<uint64_t>, 16> byCheatType{};
    TimePoint startTime = Clock::now();
    
    void Reset() noexcept;
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Configuration
 */
struct CheatDetectorConfiguration {
    /// @brief Enable detection
    bool enabled = true;
    
    /// @brief Enable memory scan
    bool enableMemoryScan = true;
    
    /// @brief Enable process monitoring
    bool enableProcessMonitoring = true;
    
    /// @brief Enable API monitoring
    bool enableAPIMonitoring = true;
    
    /// @brief Auto-block known malware
    bool autoBlockMalware = true;
    
    /// @brief Warn on PUP
    bool warnOnPUP = true;
    
    /// @brief Memory scan limit (MB)
    size_t memoryScanLimitMB = CheatDetectorConstants::MAX_MEMORY_SCAN_MB;
    
    /// @brief Scan timeout (ms)
    uint32_t scanTimeoutMs = CheatDetectorConstants::SCAN_TIMEOUT_MS;
    
    /// @brief Whitelist (file hashes)
    std::set<std::string> whitelist;
    
    [[nodiscard]] bool IsValid() const noexcept;
};

// ============================================================================
// CALLBACK TYPES
// ============================================================================

using DetectionCallback = std::function<void(const CheatDetectionResult&)>;
using MemoryEventCallback = std::function<void(const MemoryManipulationEvent&)>;
using ScanCompleteCallback = std::function<void(const CheatScanResult&)>;
using ErrorCallback = std::function<void(const std::string& message, int code)>;

// ============================================================================
// GAME CHEAT DETECTOR CLASS
// ============================================================================

/**
 * @class GameCheatDetector
 * @brief Enterprise cheat/malware detection
 */
class GameCheatDetector final {
public:
    [[nodiscard]] static GameCheatDetector& Instance() noexcept;
    [[nodiscard]] static bool HasInstance() noexcept;
    
    GameCheatDetector(const GameCheatDetector&) = delete;
    GameCheatDetector& operator=(const GameCheatDetector&) = delete;
    GameCheatDetector(GameCheatDetector&&) = delete;
    GameCheatDetector& operator=(GameCheatDetector&&) = delete;

    // ========================================================================
    // LIFECYCLE
    // ========================================================================
    
    [[nodiscard]] bool Initialize(const CheatDetectorConfiguration& config = {});
    void Shutdown();
    [[nodiscard]] bool IsInitialized() const noexcept;
    [[nodiscard]] CheatDetectorStatus GetStatus() const noexcept;
    
    [[nodiscard]] bool UpdateConfiguration(const CheatDetectorConfiguration& config);
    [[nodiscard]] CheatDetectorConfiguration GetConfiguration() const;

    // ========================================================================
    // SCANNING
    // ========================================================================
    
    /// @brief Scan for cheats affecting a game process
    [[nodiscard]] CheatScanResult ScanForCheats(uint32_t gamePid);
    
    /// @brief Quick scan (process-level only)
    [[nodiscard]] CheatScanResult QuickScan(uint32_t gamePid);
    
    /// @brief Deep scan (includes memory)
    [[nodiscard]] CheatScanResult DeepScan(uint32_t gamePid);
    
    /// @brief Scan specific process
    [[nodiscard]] std::optional<CheatDetectionResult> ScanProcess(uint32_t pid);
    
    /// @brief Scan file
    [[nodiscard]] std::optional<CheatDetectionResult> ScanFile(const std::wstring& filePath);

    // ========================================================================
    // REAL-TIME MONITORING
    // ========================================================================
    
    /// @brief Start monitoring game process
    [[nodiscard]] bool StartMonitoring(uint32_t gamePid);
    
    /// @brief Stop monitoring
    void StopMonitoring(uint32_t gamePid);
    
    /// @brief Stop all monitoring
    void StopAllMonitoring();
    
    /// @brief Get monitored processes
    [[nodiscard]] std::vector<uint32_t> GetMonitoredProcesses() const;

    // ========================================================================
    // DETECTION MANAGEMENT
    // ========================================================================
    
    /// @brief Get recent detections
    [[nodiscard]] std::vector<CheatDetectionResult> GetRecentDetections(size_t limit = 100) const;
    
    /// @brief Get detection by ID
    [[nodiscard]] std::optional<CheatDetectionResult> GetDetection(const std::string& detectionId) const;
    
    /// @brief Mark as false positive
    [[nodiscard]] bool MarkAsFalsePositive(const std::string& detectionId);
    
    /// @brief Add to whitelist
    [[nodiscard]] bool AddToWhitelist(const std::string& fileHash);
    
    /// @brief Remove from whitelist
    [[nodiscard]] bool RemoveFromWhitelist(const std::string& fileHash);

    // ========================================================================
    // TOOL DATABASE
    // ========================================================================
    
    /// @brief Get known cheat tools
    [[nodiscard]] std::vector<KnownCheatTool> GetKnownCheatTools() const;
    
    /// @brief Search cheat tools
    [[nodiscard]] std::vector<KnownCheatTool> SearchCheatTools(const std::string& query) const;
    
    /// @brief Is known cheat process
    [[nodiscard]] bool IsKnownCheatProcess(const std::wstring& processName) const;

    // ========================================================================
    // CALLBACKS
    // ========================================================================
    
    void RegisterDetectionCallback(DetectionCallback callback);
    void RegisterMemoryEventCallback(MemoryEventCallback callback);
    void RegisterScanCompleteCallback(ScanCompleteCallback callback);
    void RegisterErrorCallback(ErrorCallback callback);
    void UnregisterCallbacks();

    // ========================================================================
    // STATISTICS
    // ========================================================================
    
    [[nodiscard]] CheatDetectorStatistics GetStatistics() const;
    void ResetStatistics();
    
    [[nodiscard]] bool SelfTest();
    [[nodiscard]] static std::string GetVersionString() noexcept;

private:
    GameCheatDetector();
    ~GameCheatDetector();
    
    std::unique_ptr<GameCheatDetectorImpl> m_impl;
    static std::atomic<bool> s_instanceCreated;
};

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

[[nodiscard]] std::string_view GetCheatTypeName(CheatType type) noexcept;
[[nodiscard]] std::string_view GetThreatCategoryName(ThreatCategory category) noexcept;
[[nodiscard]] std::string_view GetDetectionMethodName(CheatDetectionMethod method) noexcept;
[[nodiscard]] std::string_view GetRecommendedActionName(RecommendedAction action) noexcept;

/// @brief Check if process has debug privileges
[[nodiscard]] bool HasDebugPrivileges(uint32_t pid);

/// @brief Detect memory manipulation APIs
[[nodiscard]] bool IsMemoryManipulationAPI(const std::string& apiName);

}  // namespace GameMode
}  // namespace ShadowStrike

// ============================================================================
// MACROS
// ============================================================================

#define SS_SCAN_FOR_CHEATS(gamePid) \
    ::ShadowStrike::GameMode::GameCheatDetector::Instance().ScanForCheats(gamePid)

#define SS_IS_CHEAT_PROCESS(processName) \
    ::ShadowStrike::GameMode::GameCheatDetector::Instance().IsKnownCheatProcess(processName)
