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
 * ShadowStrike Core Process - ATOM BOMBING DETECTOR (The Chemist)
 * ============================================================================
 *
 * @file AtomBombingDetector.hpp
 * @brief Enterprise-grade detection of AtomBombing code injection attacks.
 *
 * AtomBombing is a sophisticated code injection technique discovered by enSilo
 * in 2016 that abuses the Windows Global Atom Table to inject and execute
 * malicious code. Unlike traditional injection techniques, AtomBombing doesn't
 * require WriteProcessMemory, making it harder to detect.
 *
 * ============================================================================
 * ATTACK MECHANISM
 * ============================================================================
 *
 * The attack works by:
 * 1. Attacker writes shellcode/payload to the Global Atom Table using
 *    GlobalAddAtom() - atoms are system-wide and accessible by all processes
 * 2. Uses QueueUserAPC() to queue an APC to a target thread that calls
 *    GlobalGetAtomName() to read the shellcode into the target's memory
 * 3. Uses ROP gadgets or additional APCs to execute the retrieved code
 *
 * Variations include:
 * - Using NtQueueApcThread/NtQueueApcThreadEx for kernel-level APC
 * - Using WriteProcessMemory alternative via atom table
 * - Combining with other techniques for full code execution
 *
 * ============================================================================
 * DETECTION VECTORS
 * ============================================================================
 *
 * | Detection Method          | Description                               |
 * |---------------------------|-------------------------------------------|
 * | Atom Table Monitoring     | Track suspicious atom additions           |
 * | APC Queue Monitoring      | Detect APCs targeting atom functions      |
 * | Pattern Recognition       | Shellcode patterns in atom data           |
 * | Cross-Process Correlation | APC from external process                 |
 * | Entropy Analysis          | High entropy atom content                 |
 * | Size Analysis             | Unusually large atom data                 |
 * | Behavioral Analysis       | Atom + APC + Code execution sequence      |
 *
 * ============================================================================
 * MITRE ATT&CK COVERAGE
 * ============================================================================
 *
 * | Technique ID | Technique Name              | Detection Method              |
 * |--------------|-----------------------------|-------------------------------|
 * | T1055.009    | Proc Injection: AtomBombing | Core detection                |
 * | T1055        | Process Injection           | APC monitoring                |
 * | T1106        | Native API                  | NtQueueApcThread detection    |
 * | T1218        | System Binary Proxy         | ntdll.dll gadget detection    |
 *
 * @author ShadowStrike Security Team
 * @version 4.0.0
 * @copyright 2026 ShadowStrike Security Suite
 */

#pragma once

// ============================================================================
// INCLUDES
// ============================================================================

// Internal infrastructure
#include "ProcessMonitor.hpp"
#include "../../Utils/ProcessUtils.hpp"
#include "../../Utils/ErrorUtils.hpp"
#include "../../PatternStore/PatternStore.hpp"
#include "../../ThreatIntel/ThreatIntelManager.hpp"

// Standard library
#include <string>
#include <string_view>
#include <vector>
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
#include <span>
#include <array>
#include <cstdint>

namespace ShadowStrike {
namespace Core {
namespace Process {

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

class AtomBombingDetectorImpl;

// ============================================================================
// CONSTANTS
// ============================================================================

namespace AtomBombingConstants {

    // Version information
    constexpr uint32_t VERSION_MAJOR = 4;
    constexpr uint32_t VERSION_MINOR = 0;
    constexpr uint32_t VERSION_PATCH = 0;

    // Atom table limits (Windows limits)
    constexpr uint16_t MIN_GLOBAL_ATOM = 0xC000;
    constexpr uint16_t MAX_GLOBAL_ATOM = 0xFFFF;
    constexpr size_t MAX_ATOM_NAME_LENGTH = 255;
    constexpr size_t MAX_ATOMS_TO_MONITOR = 16384;

    // Detection thresholds
    constexpr double HIGH_ENTROPY_THRESHOLD = 6.5;
    constexpr size_t SUSPICIOUS_ATOM_SIZE_THRESHOLD = 64;
    constexpr size_t SHELLCODE_MIN_SIZE = 16;
    constexpr size_t SHELLCODE_TYPICAL_MIN = 50;
    constexpr uint32_t APC_CORRELATION_WINDOW_MS = 5000;

    // Monitoring limits
    constexpr size_t MAX_APC_EVENTS = 8192;
    constexpr size_t MAX_ATOM_EVENTS = 8192;
    constexpr uint32_t SCAN_TIMEOUT_MS = 30000;

    // Known suspicious atom patterns (simplified)
    constexpr size_t MAX_PATTERNS = 64;

    // Windows API function hashes (for ROP detection)
    constexpr uint32_t HASH_GlobalGetAtomNameA = 0x2C5B8D4A;
    constexpr uint32_t HASH_GlobalGetAtomNameW = 0x3E7C9F5B;
    constexpr uint32_t HASH_NtQueueApcThread = 0x4D8E0A6C;
    constexpr uint32_t HASH_NtQueueApcThreadEx = 0x5E9F1B7D;

} // namespace AtomBombingConstants

// ============================================================================
// ENUMERATIONS
// ============================================================================

/**
 * @enum AtomType
 * @brief Types of atoms in Windows.
 */
enum class AtomType : uint8_t {
    Unknown = 0,
    GlobalAtom = 1,               ///< System-wide atom (GlobalAddAtom)
    LocalAtom = 2,                ///< Process-local atom (AddAtom)
    IntegerAtom = 3,              ///< Integer atom (MAKEINTATOM)
    RegisteredClass = 4           ///< Window class atom (RegisterClass)
};

/**
 * @enum AtomSuspicion
 * @brief Suspicion level for an atom.
 */
enum class AtomSuspicion : uint8_t {
    Normal = 0,
    LowRisk = 1,              ///< Minor anomaly
    MediumRisk = 2,           ///< Multiple indicators
    HighRisk = 3,             ///< Strong indicators
    Critical = 4              ///< Definitive shellcode/attack
};

/**
 * @enum APCType
 * @brief Types of APCs monitored.
 */
enum class APCType : uint8_t {
    Unknown = 0,
    UserMode = 1,                 ///< Standard user-mode APC
    KernelMode = 2,               ///< Kernel-mode APC
    NtQueueApcThread = 3,         ///< Direct NT API call
    NtQueueApcThreadEx = 4,       ///< Extended NT API call
    QueueUserAPC = 5,             ///< Win32 API
    Special = 6                   ///< Special APC
};

/**
 * @enum APCTargetType
 * @brief What function the APC is targeting.
 */
enum class APCTargetType : uint8_t {
    Unknown = 0,
    GlobalGetAtomNameA = 1,
    GlobalGetAtomNameW = 2,
    GlobalGetAtomName = 3,        ///< Unspecified variant
    NtdllGadget = 4,              ///< ROP gadget in ntdll
    ShellcodeEntry = 5,           ///< Direct shellcode execution
    LoadLibrary = 6,              ///< LoadLibrary injection
    OtherSuspicious = 7
};

/**
 * @enum DetectionConfidence
 * @brief Confidence level of detection.
 */
enum class DetectionConfidence : uint8_t {
    None = 0,
    Low = 1,              ///< Single indicator
    Medium = 2,           ///< Multiple indicators
    High = 3,             ///< Strong correlation
    Confirmed = 4         ///< Attack chain confirmed
};

/**
 * @enum MonitoringMode
 * @brief Real-time monitoring mode.
 */
enum class MonitoringMode : uint8_t {
    Disabled = 0,
    PassiveOnly = 1,          ///< Monitor and alert
    Active = 2,               ///< Can block suspicious APCs
    Aggressive = 3            ///< Block all cross-process APCs to atom functions
};

// ============================================================================
// DATA STRUCTURES
// ============================================================================

/**
 * @struct AtomInfo
 * @brief Information about an atom in the Global Atom Table.
 */
struct AtomInfo {
    uint16_t atomValue = 0;                   ///< Atom identifier
    AtomType type = AtomType::Unknown;
    std::wstring atomName;                    ///< Atom string content
    std::vector<uint8_t> rawContent;          ///< Raw bytes
    size_t contentLength = 0;
    
    // Creation context
    uint32_t creatorPid = 0;                  ///< Process that created atom
    std::wstring creatorProcessName;
    std::chrono::system_clock::time_point createTime;
    
    // Analysis
    double entropy = 0.0;
    bool hasHighEntropy = false;
    bool hasShellcodePatterns = false;
    bool hasNullBytes = false;
    bool hasSuspiciousStrings = false;
    
    // Detection
    AtomSuspicion suspicionLevel = AtomSuspicion::Normal;
    std::vector<std::wstring> suspicionReasons;
    
    // For monitoring
    bool isMonitored = false;
    uint32_t accessCount = 0;
    std::vector<uint32_t> accessingPids;
};

/**
 * @struct APCEvent
 * @brief Information about an APC being queued.
 */
struct APCEvent {
    uint64_t eventId = 0;
    std::chrono::system_clock::time_point timestamp;
    
    // Source process (queuing the APC)
    uint32_t sourcePid = 0;
    std::wstring sourceProcessName;
    std::wstring sourceProcessPath;
    uint32_t sourceTid = 0;
    
    // Target process/thread
    uint32_t targetPid = 0;
    std::wstring targetProcessName;
    std::wstring targetProcessPath;
    uint32_t targetTid = 0;
    
    // APC details
    APCType apcType = APCType::Unknown;
    uintptr_t apcRoutine = 0;                 ///< APC function address
    uintptr_t apcArgument1 = 0;
    uintptr_t apcArgument2 = 0;
    uintptr_t apcArgument3 = 0;
    
    // Analysis
    APCTargetType targetType = APCTargetType::Unknown;
    std::wstring moduleName;                  ///< Module containing APC routine
    std::wstring symbolName;                  ///< Symbol name if available
    bool isCrossProcess = false;
    bool targetsSelf = false;
    bool targetsAtomFunction = false;
    
    // Risk assessment
    bool isSuspicious = false;
    std::vector<std::wstring> suspicionReasons;
    uint32_t riskScore = 0;
};

/**
 * @struct AtomBombingAttack
 * @brief Detected AtomBombing attack.
 */
struct alignas(64) AtomBombingAttack {
    uint64_t attackId = 0;
    std::chrono::system_clock::time_point detectionTime;
    
    // Attack participants
    uint32_t attackerPid = 0;
    std::wstring attackerProcessName;
    std::wstring attackerProcessPath;
    
    uint32_t victimPid = 0;
    std::wstring victimProcessName;
    std::wstring victimProcessPath;
    uint32_t victimTid = 0;
    
    // Attack components
    AtomInfo maliciousAtom;
    std::vector<APCEvent> relatedApcs;
    
    // Attack chain analysis
    bool atomWriteDetected = false;
    bool apcQueueDetected = false;
    bool atomRetrievalDetected = false;
    bool codeExecutionDetected = false;
    
    // Payload analysis
    bool payloadExtracted = false;
    std::vector<uint8_t> payload;
    std::array<uint8_t, 32> payloadHash{};
    std::wstring payloadDescription;
    
    // Detection confidence
    DetectionConfidence confidence = DetectionConfidence::None;
    std::vector<std::wstring> detectionReasons;
    
    // Risk assessment
    uint32_t riskScore = 0;                   ///< 0-100
    
    // Response
    bool wasBlocked = false;
    bool attackerTerminated = false;
    std::wstring mitigationAction;
    
    // Threat intelligence
    bool correlatedWithThreat = false;
    std::wstring threatName;
    std::string mitreAttackId;
};

/**
 * @struct ScanResult
 * @brief Result of scanning for AtomBombing.
 */
struct ScanResult {
    std::chrono::system_clock::time_point scanTime;
    
    // Scope
    bool systemWideScan = false;
    uint32_t targetPid = 0;                   ///< If not system-wide
    
    // Atom table analysis
    uint32_t totalAtomsAnalyzed = 0;
    uint32_t suspiciousAtomsFound = 0;
    std::vector<AtomInfo> suspiciousAtoms;
    
    // APC analysis
    uint32_t apcsAnalyzed = 0;
    uint32_t suspiciousApcsFound = 0;
    std::vector<APCEvent> suspiciousApcs;
    
    // Attacks detected
    std::vector<AtomBombingAttack> detectedAttacks;
    
    // Overall
    bool attackDetected = false;
    DetectionConfidence highestConfidence = DetectionConfidence::None;
    uint32_t highestRiskScore = 0;
    
    // Metadata
    uint32_t scanDurationMs = 0;
    bool scanComplete = false;
    std::wstring scanError;
};

/**
 * @struct AtomBombingConfig
 * @brief Configuration for the detector.
 */
struct AtomBombingConfig {
    // Monitoring mode
    MonitoringMode mode = MonitoringMode::Active;
    bool enableRealTimeMonitoring = true;
    bool enableOnDemandScanning = true;
    
    // Detection features
    bool monitorAtomTable = true;
    bool monitorAPCs = true;
    bool correlateAtomAndAPC = true;
    bool detectShellcodePatterns = true;
    bool analyzeEntropy = true;
    bool extractPayloads = true;
    
    // Sensitivity
    DetectionConfidence alertThreshold = DetectionConfidence::Medium;
    double entropyThreshold = AtomBombingConstants::HIGH_ENTROPY_THRESHOLD;
    size_t suspiciousAtomSizeThreshold = AtomBombingConstants::SUSPICIOUS_ATOM_SIZE_THRESHOLD;
    
    // Correlation
    uint32_t apcCorrelationWindowMs = AtomBombingConstants::APC_CORRELATION_WINDOW_MS;
    
    // Response
    bool enableAutoResponse = false;
    bool blockSuspiciousApcs = false;
    bool terminateAttacker = false;
    
    // Performance
    uint32_t scanTimeoutMs = AtomBombingConstants::SCAN_TIMEOUT_MS;
    size_t maxAtomsToAnalyze = AtomBombingConstants::MAX_ATOMS_TO_MONITOR;
    
    // Exclusions
    std::vector<std::wstring> excludedProcesses;
    std::vector<uint16_t> excludedAtoms;
    
    /**
     * @brief Create default configuration.
     */
    static AtomBombingConfig CreateDefault() noexcept;
    
    /**
     * @brief Create high-sensitivity configuration.
     */
    static AtomBombingConfig CreateHighSensitivity() noexcept;
    
    /**
     * @brief Create performance-optimized configuration.
     */
    static AtomBombingConfig CreatePerformance() noexcept;
};

/**
 * @struct AtomBombingStatistics
 * @brief Runtime statistics for the detector.
 */
struct alignas(64) AtomBombingStatistics {
    // Atom table monitoring
    std::atomic<uint64_t> atomsMonitored{0};
    std::atomic<uint64_t> atomCreations{0};
    std::atomic<uint64_t> atomDeletions{0};
    std::atomic<uint64_t> suspiciousAtomsDetected{0};
    std::atomic<uint64_t> highEntropyAtomsDetected{0};
    std::atomic<uint64_t> shellcodePatternsDetected{0};
    
    // APC monitoring
    std::atomic<uint64_t> apcsMonitored{0};
    std::atomic<uint64_t> crossProcessApcs{0};
    std::atomic<uint64_t> suspiciousApcsDetected{0};
    std::atomic<uint64_t> atomTargetingApcs{0};
    
    // Attack detection
    std::atomic<uint64_t> attacksDetected{0};
    std::atomic<uint64_t> attacksBlocked{0};
    std::atomic<uint64_t> lowConfidenceDetections{0};
    std::atomic<uint64_t> mediumConfidenceDetections{0};
    std::atomic<uint64_t> highConfidenceDetections{0};
    std::atomic<uint64_t> confirmedAttacks{0};
    
    // Payload extraction
    std::atomic<uint64_t> payloadsExtracted{0};
    std::atomic<uint64_t> extractionFailures{0};
    
    // Performance
    std::atomic<uint64_t> totalScanTimeMs{0};
    std::atomic<uint64_t> scansPerformed{0};
    
    // Errors
    std::atomic<uint64_t> scanErrors{0};
    std::atomic<uint64_t> accessDeniedErrors{0};
    
    /**
     * @brief Reset all statistics.
     */
    void Reset() noexcept;
    
    /**
     * @brief Get attack detection rate.
     */
    [[nodiscard]] double GetDetectionRate() const noexcept;
};

// ============================================================================
// CALLBACK DEFINITIONS
// ============================================================================

/**
 * @brief Callback when AtomBombing attack is detected.
 * @param attack Attack details
 */
using AttackDetectedCallback = std::function<void(
    const AtomBombingAttack& attack
)>;

/**
 * @brief Callback when suspicious atom is detected.
 * @param atom Atom information
 */
using SuspiciousAtomCallback = std::function<void(
    const AtomInfo& atom
)>;

/**
 * @brief Callback when suspicious APC is detected.
 * @param apc APC event information
 */
using SuspiciousAPCCallback = std::function<void(
    const APCEvent& apc
)>;

// ============================================================================
// ATOM BOMBING DETECTOR CLASS
// ============================================================================

/**
 * @class AtomBombingDetector
 * @brief Enterprise-grade AtomBombing attack detection engine.
 *
 * Thread-safety: All public methods are thread-safe.
 * Pattern: Singleton with PIMPL for ABI stability.
 *
 * Usage:
 * @code
 * auto& detector = AtomBombingDetector::Instance();
 * 
 * // Scan atom table
 * auto result = detector.ScanAtomTable();
 * for (const auto& attack : result.detectedAttacks) {
 *     std::wcout << L"Attack detected from PID " << attack.attackerPid << std::endl;
 * }
 * 
 * // Enable real-time monitoring
 * detector.RegisterAttackCallback([](const AtomBombingAttack& attack) {
 *     // Handle attack...
 * });
 * detector.StartMonitoring();
 * @endcode
 */
class AtomBombingDetector {
public:
    // ========================================================================
    // SINGLETON ACCESS
    // ========================================================================

    /**
     * @brief Get singleton instance.
     * @return Reference to the singleton instance.
     */
    [[nodiscard]] static AtomBombingDetector& Instance();

    /**
     * @brief Delete copy constructor.
     */
    AtomBombingDetector(const AtomBombingDetector&) = delete;

    /**
     * @brief Delete copy assignment.
     */
    AtomBombingDetector& operator=(const AtomBombingDetector&) = delete;

    // ========================================================================
    // LIFECYCLE MANAGEMENT
    // ========================================================================

    /**
     * @brief Initialize the detector.
     * @param config Configuration settings.
     * @return True if initialization succeeded.
     */
    [[nodiscard]] bool Initialize(
        const AtomBombingConfig& config = AtomBombingConfig::CreateDefault()
    );

    /**
     * @brief Shutdown the detector.
     */
    void Shutdown();

    /**
     * @brief Check if detector is initialized.
     * @return True if ready.
     */
    [[nodiscard]] bool IsInitialized() const noexcept;

    /**
     * @brief Update configuration.
     * @param config New configuration.
     * @return True if applied successfully.
     */
    bool UpdateConfig(const AtomBombingConfig& config);

    /**
     * @brief Get current configuration.
     * @return Current configuration.
     */
    [[nodiscard]] AtomBombingConfig GetConfig() const;

    // ========================================================================
    // ATOM TABLE SCANNING
    // ========================================================================

    /**
     * @brief Scan the Global Atom Table for suspicious entries.
     * @return Scan result.
     */
    [[nodiscard]] ScanResult ScanAtomTable();

    /**
     * @brief Analyze a specific atom.
     * @param atomValue Atom identifier.
     * @return Atom information.
     */
    [[nodiscard]] AtomInfo AnalyzeAtom(uint16_t atomValue);

    /**
     * @brief Get all atoms in the Global Atom Table.
     * @return Vector of atom information.
     */
    [[nodiscard]] std::vector<AtomInfo> EnumerateAtoms();

    /**
     * @brief Find atoms with suspicious characteristics.
     * @return Vector of suspicious atoms.
     */
    [[nodiscard]] std::vector<AtomInfo> FindSuspiciousAtoms();

    /**
     * @brief Check if an atom contains shellcode patterns.
     * @param atomValue Atom identifier.
     * @return True if shellcode patterns detected.
     */
    [[nodiscard]] bool ContainsShellcode(uint16_t atomValue);

    /**
     * @brief Get entropy of atom content.
     * @param atomValue Atom identifier.
     * @return Entropy value (0-8).
     */
    [[nodiscard]] double GetAtomEntropy(uint16_t atomValue);

    // ========================================================================
    // APC MONITORING
    // ========================================================================

    /**
     * @brief Check an APC for AtomBombing indicators.
     * @param targetPid Target process ID.
     * @param apcRoutine APC routine address.
     * @return True if APC targets atom-related functions.
     */
    [[nodiscard]] bool CheckAPC(uint32_t targetPid, uintptr_t apcRoutine);

    /**
     * @brief Analyze an APC event.
     * @param sourcePid Source process ID.
     * @param targetPid Target process ID.
     * @param targetTid Target thread ID.
     * @param apcRoutine APC routine address.
     * @return APC event analysis.
     */
    [[nodiscard]] APCEvent AnalyzeAPC(
        uint32_t sourcePid,
        uint32_t targetPid,
        uint32_t targetTid,
        uintptr_t apcRoutine
    );

    /**
     * @brief Get recent suspicious APCs.
     * @return Vector of suspicious APC events.
     */
    [[nodiscard]] std::vector<APCEvent> GetSuspiciousAPCs() const;

    /**
     * @brief Check if APC targets GlobalGetAtomName.
     * @param apcRoutine APC routine address.
     * @param pid Target process ID.
     * @return True if targets atom retrieval.
     */
    [[nodiscard]] bool TargetsAtomRetrieval(uintptr_t apcRoutine, uint32_t pid);

    // ========================================================================
    // ATTACK CORRELATION
    // ========================================================================

    /**
     * @brief Correlate atom and APC events to detect attacks.
     * @return Detected attacks.
     */
    [[nodiscard]] std::vector<AtomBombingAttack> CorrelateEvents();

    /**
     * @brief Check if a complete attack chain exists.
     * @param victimPid Potential victim process ID.
     * @return Attack information if chain detected.
     */
    [[nodiscard]] std::optional<AtomBombingAttack> DetectAttackChain(
        uint32_t victimPid
    );

    /**
     * @brief Scan a specific process for AtomBombing.
     * @param pid Process ID.
     * @return Scan result.
     */
    [[nodiscard]] ScanResult ScanProcess(uint32_t pid);

    // ========================================================================
    // REAL-TIME MONITORING
    // ========================================================================

    /**
     * @brief Start real-time monitoring.
     * @return True if monitoring started.
     */
    bool StartMonitoring();

    /**
     * @brief Stop real-time monitoring.
     */
    void StopMonitoring();

    /**
     * @brief Check if monitoring is active.
     * @return True if monitoring.
     */
    [[nodiscard]] bool IsMonitoring() const noexcept;

    /**
     * @brief Set monitoring mode.
     * @param mode New monitoring mode.
     */
    void SetMonitoringMode(MonitoringMode mode);

    /**
     * @brief Get current monitoring mode.
     * @return Current mode.
     */
    [[nodiscard]] MonitoringMode GetMonitoringMode() const noexcept;

    // ========================================================================
    // EVENT HANDLERS (from kernel/ETW)
    // ========================================================================

    /**
     * @brief Notify of atom creation.
     * @param atomValue Atom identifier.
     * @param creatorPid Creator process ID.
     * @param atomName Atom content.
     */
    void OnAtomCreate(
        uint16_t atomValue,
        uint32_t creatorPid,
        const std::wstring& atomName
    );

    /**
     * @brief Notify of atom deletion.
     * @param atomValue Atom identifier.
     * @param deleterPid Deleting process ID.
     */
    void OnAtomDelete(uint16_t atomValue, uint32_t deleterPid);

    /**
     * @brief Notify of APC queue.
     * @param sourcePid Source process ID.
     * @param targetPid Target process ID.
     * @param targetTid Target thread ID.
     * @param apcRoutine APC routine address.
     * @param arg1 Argument 1.
     * @param arg2 Argument 2.
     * @param arg3 Argument 3.
     */
    void OnAPCQueue(
        uint32_t sourcePid,
        uint32_t targetPid,
        uint32_t targetTid,
        uintptr_t apcRoutine,
        uintptr_t arg1,
        uintptr_t arg2,
        uintptr_t arg3
    );

    // ========================================================================
    // RESPONSE ACTIONS
    // ========================================================================

    /**
     * @brief Block a suspicious APC.
     * @param apc APC event to block.
     * @return True if blocked successfully.
     */
    bool BlockAPC(const APCEvent& apc);

    /**
     * @brief Remove a malicious atom.
     * @param atomValue Atom to remove.
     * @return True if removed successfully.
     */
    bool RemoveMaliciousAtom(uint16_t atomValue);

    /**
     * @brief Terminate attacker process.
     * @param attack Attack to respond to.
     * @return True if terminated.
     */
    bool TerminateAttacker(const AtomBombingAttack& attack);

    // ========================================================================
    // CALLBACK REGISTRATION
    // ========================================================================

    /**
     * @brief Register callback for attack detection.
     * @param callback Attack callback.
     * @return Callback ID.
     */
    uint64_t RegisterAttackCallback(AttackDetectedCallback callback);

    /**
     * @brief Register callback for suspicious atoms.
     * @param callback Atom callback.
     * @return Callback ID.
     */
    uint64_t RegisterAtomCallback(SuspiciousAtomCallback callback);

    /**
     * @brief Register callback for suspicious APCs.
     * @param callback APC callback.
     * @return Callback ID.
     */
    uint64_t RegisterAPCCallback(SuspiciousAPCCallback callback);

    /**
     * @brief Unregister a callback.
     * @param callbackId Callback ID.
     */
    void UnregisterCallback(uint64_t callbackId);

    // ========================================================================
    // STATISTICS
    // ========================================================================

    /**
     * @brief Get detector statistics.
     * @return Current statistics.
     */
    [[nodiscard]] AtomBombingStatistics GetStatistics() const;

    /**
     * @brief Reset statistics.
     */
    void ResetStatistics();

    /**
     * @brief Get version string.
     * @return Version.
     */
    [[nodiscard]] static std::wstring GetVersion() noexcept;

    // ========================================================================
    // UTILITY
    // ========================================================================

    /**
     * @brief Check if atom value is in global range.
     * @param atomValue Atom identifier.
     * @return True if global atom.
     */
    [[nodiscard]] static bool IsGlobalAtom(uint16_t atomValue) noexcept;

    /**
     * @brief Get atom content as string.
     * @param atomValue Atom identifier.
     * @return Atom content.
     */
    [[nodiscard]] std::wstring GetAtomName(uint16_t atomValue) const;

    /**
     * @brief Convert confidence to string.
     * @param confidence Confidence level.
     * @return String representation.
     */
    [[nodiscard]] static std::wstring ConfidenceToString(
        DetectionConfidence confidence
    ) noexcept;

private:
    // ========================================================================
    // PRIVATE CONSTRUCTOR (SINGLETON)
    // ========================================================================

    AtomBombingDetector();
    ~AtomBombingDetector();

    // ========================================================================
    // IMPLEMENTATION
    // ========================================================================

    std::unique_ptr<AtomBombingDetectorImpl> m_impl;
};

} // namespace Process
} // namespace Core
} // namespace ShadowStrike
