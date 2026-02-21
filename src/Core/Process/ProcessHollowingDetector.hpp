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
 * ShadowStrike Core Process - PROCESS HOLLOWING DETECTOR (The Ghostbuster)
 * ============================================================================
 *
 * @file ProcessHollowingDetector.hpp
 * @brief Enterprise-grade detection of Process Hollowing (RunPE) attacks.
 *
 * Process Hollowing is a sophisticated code injection technique where malware:
 * 1. Creates a legitimate process in SUSPENDED state
 * 2. Unmaps the original executable image
 * 3. Allocates new memory for malicious code
 * 4. Writes malicious payload
 * 5. Modifies thread context to point to payload
 * 6. Resumes execution
 *
 * This detector identifies hollowing through multiple detection vectors:
 * - Memory vs. Disk PE header comparison
 * - Entry point validation
 * - Section anomaly detection
 * - Creation pattern monitoring
 * - Memory protection analysis
 *
 * ============================================================================
 * ATTACK VARIANTS DETECTED
 * ============================================================================
 *
 * | Variant                   | Detection Method                            |
 * |---------------------------|---------------------------------------------|
 * | Classic Hollowing         | PE header mismatch disk vs memory           |
 * | Section Hollowing         | Individual section unmapping detection      |
 * | Transacted Hollowing      | TxF transaction monitoring                  |
 * | Process Doppelgänging     | Transacted file + section creation          |
 * | Process Herpaderping      | File modification post-mapping              |
 * | Process Ghosting          | Delete-pending file execution               |
 * | Process Reimaging         | Re-map with different image                 |
 * | Early Bird                | APC injection before entry point            |
 * | Thread Execution Hijack   | Context modification detection              |
 * | Module Stomping           | Legitimate DLL overwrite                    |
 * | Phantom DLL Hollowing     | Hidden module hollowing                     |
 *
 * ============================================================================
 * MITRE ATT&CK COVERAGE
 * ============================================================================
 *
 * | Technique ID | Technique Name              | Detection Method              |
 * |--------------|-----------------------------|-------------------------------|
 * | T1055.012    | Process Hollowing           | Core detection                |
 * | T1055.013    | Process Doppelgänging       | TxF monitoring                |
 * | T1055        | Process Injection           | Memory analysis               |
 * | T1106        | Native API                  | API sequence detection        |
 * | T1027        | Obfuscated Files            | Entropy analysis              |
 * | T1620        | Reflective Code Loading     | Unbacked memory detection     |
 *
 * ============================================================================
 * DETECTION ARCHITECTURE
 * ============================================================================
 *
 * ┌─────────────────────────────────────────────────────────────────────────┐
 * │                      ProcessHollowingDetector                           │
 * └───────────────────┬─────────────────────────────────────────────────────┘
 *                     │
 *     ┌───────────────┼───────────────┬───────────────────┐
 *     ▼               ▼               ▼                   ▼
 * ┌─────────┐   ┌─────────┐   ┌───────────┐   ┌──────────────┐
 * │ Memory  │   │  Disk   │   │ Creation  │   │   Thread     │
 * │ Analysis│   │ Analysis│   │ Monitor   │   │   Monitor    │
 * └─────────┘   └─────────┘   └───────────┘   └──────────────┘
 *     │               │               │                   │
 *     ▼               ▼               ▼                   ▼
 * ┌─────────────────────────────────────────────────────────────┐
 * │                    Correlation Engine                        │
 * │  (Combines signals for high-confidence hollowing detection)  │
 * └─────────────────────────────────────────────────────────────┘
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
#include "MemoryScanner.hpp"
#include "../../Utils/ProcessUtils.hpp"
#include "../../Utils/FileUtils.hpp"
#include "../../Utils/CryptoUtils.hpp"
#include "../../Utils/ErrorUtils.hpp"
#include "../../Utils/Logger.hpp"
#include "../../HashStore/HashStore.hpp"
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
#include <bitset>
#include <cstdint>

namespace ShadowStrike {
namespace Core {
namespace Process {

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

class ProcessHollowingDetectorImpl;

// ============================================================================
// CONSTANTS
// ============================================================================

namespace HollowingConstants {

    // Version information
    constexpr uint32_t VERSION_MAJOR = 4;
    constexpr uint32_t VERSION_MINOR = 0;
    constexpr uint32_t VERSION_PATCH = 0;

    // PE structure constants
    constexpr uint16_t DOS_MAGIC = 0x5A4D;                    ///< MZ
    constexpr uint32_t PE_SIGNATURE = 0x00004550;             ///< PE\0\0
    constexpr uint16_t IMAGE_FILE_MACHINE_I386 = 0x014C;
    constexpr uint16_t IMAGE_FILE_MACHINE_AMD64 = 0x8664;
    constexpr size_t DOS_HEADER_SIZE = 64;
    constexpr size_t PE_HEADER_MIN_SIZE = 24;
    constexpr size_t OPTIONAL_HEADER32_SIZE = 224;
    constexpr size_t OPTIONAL_HEADER64_SIZE = 240;
    constexpr uint32_t MAX_SECTIONS = 96;

    // Analysis limits
    constexpr size_t MAX_PE_HEADER_SIZE = 4096;
    constexpr size_t MAX_SECTION_HEADERS_SIZE = 4096;
    constexpr size_t MAX_COMPARISON_SIZE = 1024 * 1024;       ///< 1MB
    constexpr size_t SAMPLE_SIZE_PER_SECTION = 4096;
    constexpr uint32_t MAX_PROCESSES_TO_SCAN = 10000;
    constexpr uint32_t MAX_MODULES_PER_PROCESS = 2048;

    // Detection thresholds
    constexpr double ENTROPY_THRESHOLD_PACKED = 7.2;
    constexpr double ENTROPY_THRESHOLD_ENCRYPTED = 7.8;
    constexpr uint32_t MIN_SECTION_SIZE = 512;
    constexpr uint32_t CHECKSUM_MISMATCH_TOLERANCE = 0;       ///< Strict
    constexpr double SECTION_DIFF_THRESHOLD = 0.1;            ///< 10% difference
    constexpr uint32_t SUSPICIOUS_THREAD_COUNT = 1;           ///< New process single thread

    // Timing thresholds
    constexpr uint32_t MAX_CREATION_TO_RESUME_MS = 5000;      ///< Suspicious if > 5s
    constexpr uint32_t MIN_SUSPENDED_DURATION_MS = 100;       ///< Too quick = automation

    // Monitoring
    constexpr uint32_t SCAN_TIMEOUT_MS = 30000;
    constexpr uint32_t CREATION_MONITOR_WINDOW_MS = 10000;
    constexpr size_t CREATION_EVENT_QUEUE_SIZE = 4096;
    constexpr size_t SUSPECTED_PROCESS_CACHE_SIZE = 1024;

    // Section characteristics (PE flags)
    constexpr uint32_t IMAGE_SCN_CNT_CODE = 0x00000020;
    constexpr uint32_t IMAGE_SCN_CNT_INITIALIZED_DATA = 0x00000040;
    constexpr uint32_t IMAGE_SCN_CNT_UNINITIALIZED_DATA = 0x00000080;
    constexpr uint32_t IMAGE_SCN_MEM_EXECUTE = 0x20000000;
    constexpr uint32_t IMAGE_SCN_MEM_READ = 0x40000000;
    constexpr uint32_t IMAGE_SCN_MEM_WRITE = 0x80000000;

} // namespace HollowingConstants

// ============================================================================
// ENUMERATIONS
// ============================================================================

/**
 * @enum HollowingType
 * @brief Types of process hollowing attacks detected.
 */
enum class HollowingType : uint8_t {
    Unknown = 0,
    ClassicHollowing = 1,         ///< Traditional RunPE
    SectionHollowing = 2,         ///< Individual section replacement
    TransactedHollowing = 3,      ///< TxF-based hollowing
    ProcessDoppelganging = 4,     ///< Doppelgänging technique
    ProcessHerpaderping = 5,      ///< Herpaderping technique
    ProcessGhosting = 6,          ///< Delete-pending execution
    ProcessReimaging = 7,         ///< Image re-mapping
    EarlyBird = 8,                ///< APC before entry point
    ThreadHijack = 9,             ///< Thread context modification
    ModuleStomping = 10,          ///< Legitimate DLL overwrite
    PhantomDLLHollowing = 11,     ///< Hidden module hollowing
    PartialHollowing = 12,        ///< Partial image replacement
    HeaderModification = 13       ///< PE header tampering
};

/**
 * @enum HollowingConfidence
 * @brief Confidence level of hollowing detection.
 */
enum class HollowingConfidence : uint8_t {
    None = 0,
    Low = 1,              ///< Single indicator
    Medium = 2,           ///< Multiple weak indicators
    High = 3,             ///< Strong indicators
    Confirmed = 4         ///< Multiple strong indicators, very high confidence
};

/**
 * @enum DetectionMethod
 * @brief Method used to detect hollowing.
 */
enum class DetectionMethod : uint8_t {
    Unknown = 0,
    PEHeaderMismatch = 1,         ///< Headers differ disk vs memory
    EntryPointAnomaly = 2,        ///< Entry point in unexpected location
    SectionMismatch = 3,          ///< Section content differs
    SectionCharacteristics = 4,   ///< Section flags anomaly
    ImageBaseAnomaly = 5,         ///< ImageBase doesn't match
    ChecksumMismatch = 6,         ///< PE checksum invalid
    TimestampMismatch = 7,        ///< Timestamp differs
    SizeOfImageMismatch = 8,      ///< Size differs
    MemoryProtection = 9,         ///< Unexpected memory protection
    UnbackedExecMemory = 10,      ///< Executable memory without file backing
    ThreadContextAnomaly = 11,    ///< Thread start address suspicious
    CreationPatternAnomaly = 12,  ///< CREATE_SUSPENDED + modification pattern
    TransactionAnomaly = 13,      ///< TxF transaction detected
    DeletePendingFile = 14,       ///< File deleted while mapped
    EntropyAnomaly = 15,          ///< Section entropy anomaly
    ImportTableAnomaly = 16,      ///< Import table modified
    RelocationAnomaly = 17,       ///< Relocation table anomaly
    ExportTableAnomaly = 18,      ///< Export table modified
    DebugDirectoryAnomaly = 19,   ///< Debug info mismatch
    ResourceAnomaly = 20,         ///< Resources modified
    DigitalSignatureBroken = 21   ///< Signature invalid due to modification
};

/**
 * @enum ScanMode
 * @brief Mode for hollowing detection scans.
 */
enum class ScanMode : uint8_t {
    Quick = 0,            ///< PE header comparison only
    Standard = 1,         ///< Header + entry point + key sections
    Comprehensive = 2,    ///< Full image comparison
    Paranoid = 3          ///< Byte-by-byte comparison + behavioral
};

/**
 * @enum MonitorMode
 * @brief Real-time monitoring mode.
 */
enum class MonitorMode : uint8_t {
    Disabled = 0,
    PassiveOnly = 1,      ///< Monitor and alert only
    Active = 2,           ///< Monitor and can block
    Aggressive = 3        ///< Block suspicious patterns proactively
};

// ============================================================================
// DATA STRUCTURES
// ============================================================================

/**
 * @struct PESectionInfo
 * @brief Information about a PE section.
 */
struct PESectionInfo {
    std::array<char, 8> name{};               ///< Section name
    uint32_t virtualSize = 0;
    uint32_t virtualAddress = 0;              ///< RVA
    uint32_t sizeOfRawData = 0;
    uint32_t pointerToRawData = 0;
    uint32_t characteristics = 0;

    // Calculated values
    uintptr_t memoryAddress = 0;              ///< Absolute address in memory
    bool isExecutable = false;
    bool isWritable = false;
    bool isReadable = false;
    bool containsCode = false;
    bool containsData = false;

    // Analysis results
    double entropy = 0.0;
    bool hasAnomalousEntropy = false;
    std::array<uint8_t, 32> contentHash{};    ///< SHA256 of content
};

/**
 * @struct PEHeaderInfo
 * @brief Parsed PE header information.
 */
struct PEHeaderInfo {
    // DOS Header
    bool hasDosHeader = false;
    uint32_t peHeaderOffset = 0;

    // PE Header
    bool hasPeHeader = false;
    uint16_t machine = 0;
    uint16_t numberOfSections = 0;
    uint32_t timeDateStamp = 0;
    uint32_t characteristics = 0;

    // Optional Header
    bool is64Bit = false;
    uintptr_t imageBase = 0;
    uint32_t sectionAlignment = 0;
    uint32_t fileAlignment = 0;
    uint32_t sizeOfImage = 0;
    uint32_t sizeOfHeaders = 0;
    uint32_t checksum = 0;
    uintptr_t entryPoint = 0;                 ///< RVA
    uint16_t subsystem = 0;
    uint16_t dllCharacteristics = 0;

    // Data directories
    uint32_t numberOfDataDirectories = 0;
    uintptr_t importTableRVA = 0;
    uint32_t importTableSize = 0;
    uintptr_t exportTableRVA = 0;
    uint32_t exportTableSize = 0;
    uintptr_t relocationTableRVA = 0;
    uint32_t relocationTableSize = 0;
    uintptr_t debugDirectoryRVA = 0;
    uint32_t debugDirectorySize = 0;
    uintptr_t tlsDirectoryRVA = 0;
    uint32_t tlsDirectorySize = 0;

    // Sections
    std::vector<PESectionInfo> sections;

    // Validation
    bool isValid = false;
    std::wstring validationError;
};

/**
 * @struct HeaderComparison
 * @brief Result of comparing disk vs memory PE headers.
 */
struct HeaderComparison {
    bool headersMatch = true;
    bool imageBaseMatches = true;
    bool entryPointMatches = true;
    bool sizeOfImageMatches = true;
    bool checksumMatches = true;
    bool timestampMatches = true;
    bool sectionCountMatches = true;
    bool machineMatches = true;

    // Differences found
    uintptr_t diskImageBase = 0;
    uintptr_t memoryImageBase = 0;
    uintptr_t diskEntryPoint = 0;
    uintptr_t memoryEntryPoint = 0;
    uint32_t diskSizeOfImage = 0;
    uint32_t memorySizeOfImage = 0;
    uint32_t diskChecksum = 0;
    uint32_t memoryChecksum = 0;
    uint32_t diskTimestamp = 0;
    uint32_t memoryTimestamp = 0;
    uint16_t diskSectionCount = 0;
    uint16_t memorySectionCount = 0;

    // Per-section comparison
    struct SectionComparison {
        std::string name;
        bool exists = true;
        bool sizeMatches = true;
        bool characteristicsMatch = true;
        bool contentMatches = true;
        double contentSimilarity = 1.0;       ///< 0.0-1.0
    };
    std::vector<SectionComparison> sectionComparisons;

    // Overall assessment
    uint32_t mismatchCount = 0;
    double overallSimilarity = 1.0;
    std::vector<std::wstring> anomalies;
};

/**
 * @struct EntryPointAnalysis
 * @brief Analysis of process entry point.
 */
struct EntryPointAnalysis {
    uintptr_t entryPointRVA = 0;
    uintptr_t entryPointVA = 0;               ///< Virtual address
    std::wstring containingSection;
    bool isInCodeSection = false;
    bool isInExpectedRange = false;
    bool pointsToValidCode = false;

    // Entry point context
    std::array<uint8_t, 64> entryPointBytes{};
    bool hasValidPrologue = false;            ///< Standard function prologue
    bool hasShellcodePattern = false;

    // Thread analysis
    bool mainThreadAtEntryPoint = false;
    uintptr_t mainThreadRIP = 0;
    bool threadContextModified = false;

    // Anomalies
    bool isAnomalous = false;
    std::vector<std::wstring> anomalyReasons;
};

/**
 * @struct CreationPatternAnalysis
 * @brief Analysis of process creation pattern for hollowing indicators.
 */
struct CreationPatternAnalysis {
    uint32_t creatorPid = 0;
    std::wstring creatorPath;
    bool createdSuspended = false;
    std::chrono::system_clock::time_point createTime;
    std::chrono::system_clock::time_point firstResumeTime;
    uint32_t suspendedDurationMs = 0;

    // Memory modifications while suspended
    bool hadMemoryUnmap = false;
    bool hadMemoryAllocation = false;
    bool hadMemoryWrite = false;
    bool hadContextModification = false;
    bool hadSectionCreation = false;

    // API sequence observed
    std::vector<std::wstring> observedApiSequence;
    bool matchesHollowingPattern = false;

    // Transaction analysis (for doppelgänging)
    bool involvedTransaction = false;
    std::wstring transactionId;

    // File state analysis
    bool fileDeletePending = false;
    bool fileModifiedAfterMap = false;

    // Overall assessment
    bool isSuspiciousPattern = false;
    std::vector<std::wstring> suspiciousIndicators;
};

/**
 * @struct HollowingDetectionResult
 * @brief Complete result of hollowing detection for a process.
 */
struct alignas(64) HollowingDetectionResult {
    // Target identification
    uint32_t processId = 0;
    std::wstring processName;
    std::wstring processPath;
    std::wstring imagePath;                   ///< May differ if hollowed
    std::chrono::system_clock::time_point scanTime;

    // Detection result
    bool isHollowed = false;
    HollowingType hollowingType = HollowingType::Unknown;
    HollowingConfidence confidence = HollowingConfidence::None;

    // Detection methods that triggered
    std::vector<DetectionMethod> detectionMethods;
    std::vector<std::wstring> detectionDetails;

    // Analysis components
    PEHeaderInfo diskHeader;
    PEHeaderInfo memoryHeader;
    HeaderComparison headerComparison;
    EntryPointAnalysis entryPointAnalysis;
    CreationPatternAnalysis creationPattern;

    // Memory analysis
    bool hasUnbackedExecutableMemory = false;
    bool hasRWXRegions = false;
    std::vector<MemoryRegionInfo> suspiciousRegions;

    // Module analysis (for module stomping)
    bool moduleStompingDetected = false;
    std::wstring stompedModuleName;
    uintptr_t stompedModuleBase = 0;

    // Payload information (if detected)
    bool payloadExtracted = false;
    std::array<uint8_t, 32> payloadHash{};
    size_t payloadSize = 0;
    double payloadEntropy = 0.0;

    // Threat correlation
    bool correlatedWithKnownThreat = false;
    std::wstring threatName;
    std::string threatFamily;

    // Risk assessment
    uint32_t riskScore = 0;                   ///< 0-100
    std::vector<std::wstring> riskFactors;

    // Scan metadata
    ScanMode scanMode = ScanMode::Standard;
    uint32_t scanDurationMs = 0;
    bool scanComplete = false;
    std::wstring scanError;

    // MITRE ATT&CK mapping
    std::vector<std::string> mitreAttackTechniques;

    /**
     * @brief Calculate confidence from detection methods.
     */
    void CalculateConfidence() noexcept;

    /**
     * @brief Calculate risk score from all factors.
     */
    void CalculateRiskScore() noexcept;
};

/**
 * @struct HollowingAlert
 * @brief Alert generated when hollowing is detected.
 */
struct HollowingAlert {
    uint64_t alertId = 0;
    std::chrono::system_clock::time_point timestamp;
    uint32_t processId = 0;
    std::wstring processName;
    std::wstring processPath;
    HollowingType hollowingType = HollowingType::Unknown;
    HollowingConfidence confidence = HollowingConfidence::None;
    uint32_t riskScore = 0;
    std::wstring description;
    std::vector<std::wstring> indicators;
    std::wstring recommendedAction;
    bool acknowledged = false;
    bool remediated = false;
};

/**
 * @struct HollowingDetectorConfig
 * @brief Configuration for the hollowing detector.
 */
struct HollowingDetectorConfig {
    // Detection settings
    ScanMode defaultScanMode = ScanMode::Standard;
    MonitorMode monitorMode = MonitorMode::Active;
    bool enableRealTimeMonitoring = true;
    bool enableOnDemandScanning = true;

    // Sensitivity
    HollowingConfidence alertThreshold = HollowingConfidence::Medium;
    bool alertOnLowConfidence = false;
    double sectionDifferenceThreshold = HollowingConstants::SECTION_DIFF_THRESHOLD;
    double entropyThreshold = HollowingConstants::ENTROPY_THRESHOLD_PACKED;

    // Detection features
    bool enableHeaderComparison = true;
    bool enableEntryPointValidation = true;
    bool enableSectionAnalysis = true;
    bool enableCreationPatternMonitoring = true;
    bool enableTransactionMonitoring = true;
    bool enableModuleStompingDetection = true;
    bool enableThreadContextValidation = true;
    bool enablePayloadExtraction = false;     ///< Expensive, for forensics

    // Performance settings
    uint32_t scanTimeoutMs = HollowingConstants::SCAN_TIMEOUT_MS;
    uint32_t maxProcessesToScan = HollowingConstants::MAX_PROCESSES_TO_SCAN;
    uint32_t maxConcurrentScans = 4;
    bool enableCaching = true;
    uint32_t cacheTTLSeconds = 300;

    // Integration
    bool enableThreatIntelCorrelation = true;
    bool enableHashLookup = true;
    bool reportToThreatIntel = true;

    // Response
    bool enableAutoResponse = false;
    bool terminateOnHighConfidence = false;
    bool quarantinePayload = true;

    // Exclusions
    std::vector<std::wstring> excludedProcesses;
    std::vector<std::wstring> excludedPaths;
    std::vector<uint32_t> excludedPids;

    /**
     * @brief Create default configuration.
     */
    static HollowingDetectorConfig CreateDefault() noexcept;

    /**
     * @brief Create paranoid configuration (maximum detection).
     */
    static HollowingDetectorConfig CreateParanoid() noexcept;

    /**
     * @brief Create performance-optimized configuration.
     */
    static HollowingDetectorConfig CreatePerformance() noexcept;

    /**
     * @brief Create forensic configuration (full analysis).
     */
    static HollowingDetectorConfig CreateForensic() noexcept;
};

/**
 * @struct HollowingStatistics
 * @brief Runtime statistics for the hollowing detector.
 */
struct alignas(64) HollowingStatistics {
    // Scan counts
    std::atomic<uint64_t> totalScans{0};
    std::atomic<uint64_t> quickScans{0};
    std::atomic<uint64_t> standardScans{0};
    std::atomic<uint64_t> comprehensiveScans{0};
    std::atomic<uint64_t> paranoidScans{0};

    // Detection counts
    std::atomic<uint64_t> hollowingDetected{0};
    std::atomic<uint64_t> classicHollowingDetected{0};
    std::atomic<uint64_t> doppelgangingDetected{0};
    std::atomic<uint64_t> herpaderpingDetected{0};
    std::atomic<uint64_t> ghostingDetected{0};
    std::atomic<uint64_t> moduleStompingDetected{0};
    std::atomic<uint64_t> earlyBirdDetected{0};
    std::atomic<uint64_t> otherTypesDetected{0};

    // Confidence breakdown
    std::atomic<uint64_t> lowConfidenceDetections{0};
    std::atomic<uint64_t> mediumConfidenceDetections{0};
    std::atomic<uint64_t> highConfidenceDetections{0};
    std::atomic<uint64_t> confirmedDetections{0};

    // Real-time monitoring
    std::atomic<uint64_t> suspendedCreationsMonitored{0};
    std::atomic<uint64_t> suspiciousPatternsDetected{0};
    std::atomic<uint64_t> transactionsMonitored{0};

    // False positive tracking
    std::atomic<uint64_t> alertsGenerated{0};
    std::atomic<uint64_t> alertsAcknowledged{0};
    std::atomic<uint64_t> falsePositivesReported{0};

    // Performance
    std::atomic<uint64_t> totalScanTimeMs{0};
    std::atomic<uint64_t> minScanTimeMs{UINT64_MAX};
    std::atomic<uint64_t> maxScanTimeMs{0};

    // Cache
    std::atomic<uint64_t> cacheHits{0};
    std::atomic<uint64_t> cacheMisses{0};

    // Errors
    std::atomic<uint64_t> scanErrors{0};
    std::atomic<uint64_t> accessDeniedErrors{0};
    std::atomic<uint64_t> timeoutErrors{0};

    /**
     * @brief Reset all statistics.
     */
    void Reset() noexcept;

    /**
     * @brief Get average scan time.
     */
    [[nodiscard]] double GetAverageScanTimeMs() const noexcept;

    /**
     * @brief Get detection rate.
     */
    [[nodiscard]] double GetDetectionRate() const noexcept;
};

// ============================================================================
// CALLBACK DEFINITIONS
// ============================================================================

/**
 * @brief Callback when hollowing is detected.
 * @param result Detection result
 */
using HollowingDetectedCallback = std::function<void(
    const HollowingDetectionResult& result
)>;

/**
 * @brief Callback when suspicious creation pattern is observed.
 * @param pid Process ID
 * @param pattern Creation pattern analysis
 */
using SuspiciousCreationCallback = std::function<void(
    uint32_t pid,
    const CreationPatternAnalysis& pattern
)>;

/**
 * @brief Callback for scan progress.
 * @param pid Process ID being scanned
 * @param stage Current scan stage
 * @param percentComplete 0-100
 */
using ScanProgressCallback = std::function<void(
    uint32_t pid,
    const std::wstring& stage,
    uint32_t percentComplete
)>;

// ============================================================================
// PROCESS HOLLOWING DETECTOR CLASS
// ============================================================================

/**
 * @class ProcessHollowingDetector
 * @brief Enterprise-grade process hollowing detection engine.
 *
 * Thread-safety: All public methods are thread-safe.
 * Pattern: Singleton with PIMPL for ABI stability.
 *
 * Usage:
 * @code
 * auto& detector = ProcessHollowingDetector::Instance();
 *
 * // Check specific process
 * auto result = detector.ScanProcess(targetPid, ScanMode::Standard);
 * if (result.isHollowed) {
 *     std::wcout << L"Hollowing detected: " << result.processName << std::endl;
 *     // Handle threat...
 * }
 *
 * // Enable real-time monitoring
 * detector.StartMonitoring();
 * @endcode
 */
class ProcessHollowingDetector {
public:
    // ========================================================================
    // SINGLETON ACCESS
    // ========================================================================

    /**
     * @brief Get singleton instance.
     * @return Reference to the singleton instance.
     */
    [[nodiscard]] static ProcessHollowingDetector& Instance() noexcept;

    /**
     * @brief Check if singleton instance has been created.
     * @return True if instance exists.
     */
    [[nodiscard]] static bool HasInstance() noexcept;

    /**
     * @brief Delete copy constructor.
     */
    ProcessHollowingDetector(const ProcessHollowingDetector&) = delete;

    /**
     * @brief Delete copy assignment.
     */
    ProcessHollowingDetector& operator=(const ProcessHollowingDetector&) = delete;

    // ========================================================================
    // LIFECYCLE MANAGEMENT
    // ========================================================================

    /**
     * @brief Initialize the detector.
     * @param config Configuration settings.
     * @return True if initialization succeeded.
     */
    [[nodiscard]] bool Initialize(
        const HollowingDetectorConfig& config = HollowingDetectorConfig::CreateDefault()
    );

    /**
     * @brief Shutdown the detector.
     */
    void Shutdown() noexcept;

    /**
     * @brief Check if detector is initialized.
     * @return True if ready for scanning.
     */
    [[nodiscard]] bool IsInitialized() const noexcept;

    /**
     * @brief Update configuration.
     * @param config New configuration.
     * @return True if applied successfully.
     */
    bool UpdateConfig(const HollowingDetectorConfig& config);

    /**
     * @brief Get current configuration.
     * @return Current configuration.
     */
    [[nodiscard]] HollowingDetectorConfig GetConfig() const;

    // ========================================================================
    // SINGLE PROCESS SCANNING
    // ========================================================================

    /**
     * @brief Scan a process for hollowing.
     * @param pid Process ID to scan.
     * @param mode Scan mode (depth of analysis).
     * @return Detection result.
     */
    [[nodiscard]] HollowingDetectionResult ScanProcess(
        uint32_t pid,
        ScanMode mode = ScanMode::Standard
    );

    /**
     * @brief Quick check if a process is hollowed.
     * @param pid Process ID.
     * @return True if hollowing is detected.
     */
    [[nodiscard]] bool IsHollowed(uint32_t pid);

    /**
     * @brief Scan process by path (all instances).
     * @param processPath Process path.
     * @param mode Scan mode.
     * @return Detection results for all matching processes.
     */
    [[nodiscard]] std::vector<HollowingDetectionResult> ScanByPath(
        const std::wstring& processPath,
        ScanMode mode = ScanMode::Standard
    );

    /**
     * @brief Scan process by name (all instances).
     * @param processName Process name.
     * @param mode Scan mode.
     * @return Detection results for all matching processes.
     */
    [[nodiscard]] std::vector<HollowingDetectionResult> ScanByName(
        const std::wstring& processName,
        ScanMode mode = ScanMode::Standard
    );

    // ========================================================================
    // BULK SCANNING
    // ========================================================================

    /**
     * @brief Scan all running processes.
     * @param mode Scan mode.
     * @param maxConcurrent Maximum concurrent scans.
     * @return Detection results for all processes.
     */
    [[nodiscard]] std::vector<HollowingDetectionResult> ScanAllProcesses(
        ScanMode mode = ScanMode::Quick,
        uint32_t maxConcurrent = 4
    );

    /**
     * @brief Scan specific processes.
     * @param pids Process IDs to scan.
     * @param mode Scan mode.
     * @return Detection results.
     */
    [[nodiscard]] std::vector<HollowingDetectionResult> ScanProcesses(
        const std::vector<uint32_t>& pids,
        ScanMode mode = ScanMode::Standard
    );

    /**
     * @brief Get list of processes that appear hollowed.
     * @return Process IDs of detected hollowed processes.
     */
    [[nodiscard]] std::vector<uint32_t> GetHollowedProcesses();

    // ========================================================================
    // PE ANALYSIS
    // ========================================================================

    /**
     * @brief Parse PE header from memory.
     * @param pid Process ID.
     * @param moduleBase Base address of module.
     * @return Parsed PE header info.
     */
    [[nodiscard]] PEHeaderInfo ParseMemoryPE(uint32_t pid, uintptr_t moduleBase);

    /**
     * @brief Parse PE header from disk file.
     * @param filePath Path to PE file.
     * @return Parsed PE header info.
     */
    [[nodiscard]] PEHeaderInfo ParseFilePE(const std::wstring& filePath);

    /**
     * @brief Compare PE headers (disk vs memory).
     * @param disk Disk PE header.
     * @param memory Memory PE header.
     * @return Comparison result.
     */
    [[nodiscard]] HeaderComparison ComparePEHeaders(
        const PEHeaderInfo& disk,
        const PEHeaderInfo& memory
    );

    /**
     * @brief Validate PE header integrity.
     * @param header PE header to validate.
     * @return True if header is valid.
     */
    [[nodiscard]] bool ValidatePEHeader(const PEHeaderInfo& header);

    /**
     * @brief Validate that in-memory image matches disk.
     * @param pid Process ID.
     * @param moduleBase Module base address.
     * @return True if image matches disk file.
     */
    [[nodiscard]] bool ValidateImageBase(
        uint32_t pid,
        uintptr_t moduleBase
    );

    // ========================================================================
    // ENTRY POINT ANALYSIS
    // ========================================================================

    /**
     * @brief Analyze process entry point.
     * @param pid Process ID.
     * @return Entry point analysis result.
     */
    [[nodiscard]] EntryPointAnalysis AnalyzeEntryPoint(uint32_t pid);

    /**
     * @brief Validate entry point is in code section.
     * @param pid Process ID.
     * @return True if entry point is valid.
     */
    [[nodiscard]] bool ValidateEntryPoint(uint32_t pid);

    /**
     * @brief Check if main thread is at expected entry point.
     * @param pid Process ID.
     * @return True if thread is at entry point.
     */
    [[nodiscard]] bool ValidateMainThread(uint32_t pid);

    // ========================================================================
    // CREATION PATTERN MONITORING
    // ========================================================================

    /**
     * @brief Analyze process creation pattern.
     * @param pid Process ID.
     * @return Creation pattern analysis.
     */
    [[nodiscard]] CreationPatternAnalysis AnalyzeCreationPattern(uint32_t pid);

    /**
     * @brief Check if process was created with suspicious pattern.
     * @param pid Process ID.
     * @return True if suspicious creation pattern detected.
     */
    [[nodiscard]] bool HasSuspiciousCreationPattern(uint32_t pid);

    /**
     * @brief Notify of process creation (for pattern tracking).
     * @param pid Process ID.
     * @param creatorPid Creator process ID.
     * @param createdSuspended Whether created in suspended state.
     * @param imagePath Image path.
     */
    void OnProcessCreated(
        uint32_t pid,
        uint32_t creatorPid,
        bool createdSuspended,
        const std::wstring& imagePath
    );

    /**
     * @brief Notify of process resume (for pattern tracking).
     * @param pid Process ID.
     */
    void OnProcessResumed(uint32_t pid);

    /**
     * @brief Notify of memory operation (for pattern tracking).
     * @param pid Target process ID.
     * @param operationType Type of operation.
     * @param address Memory address.
     * @param size Size of operation.
     */
    void OnMemoryOperation(
        uint32_t pid,
        const std::wstring& operationType,
        uintptr_t address,
        size_t size
    );

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
     * @brief Get current monitoring mode.
     * @return Monitoring mode.
     */
    [[nodiscard]] MonitorMode GetMonitorMode() const noexcept;

    /**
     * @brief Set monitoring mode.
     * @param mode New monitoring mode.
     */
    void SetMonitorMode(MonitorMode mode);

    // ========================================================================
    // ALERT MANAGEMENT
    // ========================================================================

    /**
     * @brief Get all active alerts.
     * @return Vector of alerts.
     */
    [[nodiscard]] std::vector<HollowingAlert> GetAlerts() const;

    /**
     * @brief Get alerts for specific process.
     * @param pid Process ID.
     * @return Alerts for process.
     */
    [[nodiscard]] std::vector<HollowingAlert> GetAlertsForProcess(uint32_t pid) const;

    /**
     * @brief Acknowledge an alert.
     * @param alertId Alert ID.
     * @return True if acknowledged.
     */
    bool AcknowledgeAlert(uint64_t alertId);

    /**
     * @brief Mark alert as remediated.
     * @param alertId Alert ID.
     * @return True if marked.
     */
    bool MarkRemediated(uint64_t alertId);

    /**
     * @brief Clear all alerts.
     */
    void ClearAlerts();

    /**
     * @brief Report false positive.
     * @param alertId Alert ID.
     * @param reason Reason for false positive.
     */
    void ReportFalsePositive(uint64_t alertId, const std::wstring& reason);

    // ========================================================================
    // CALLBACK REGISTRATION
    // ========================================================================

    /**
     * @brief Register callback for hollowing detection.
     * @param callback Detection callback.
     * @return Callback ID.
     */
    [[nodiscard]] uint64_t RegisterDetectionCallback(HollowingDetectedCallback callback);

    /**
     * @brief Register callback for suspicious creation patterns.
     * @param callback Creation callback.
     * @return Callback ID.
     */
    [[nodiscard]] uint64_t RegisterCreationCallback(SuspiciousCreationCallback callback);

    /**
     * @brief Register callback for scan progress.
     * @param callback Progress callback.
     * @return Callback ID.
     */
    [[nodiscard]] uint64_t RegisterProgressCallback(ScanProgressCallback callback);

    /**
     * @brief Unregister a callback.
     * @param callbackId Callback ID.
     */
    void UnregisterCallback(uint64_t callbackId);

    // ========================================================================
    // PAYLOAD EXTRACTION
    // ========================================================================

    /**
     * @brief Extract payload from hollowed process.
     * @param pid Process ID.
     * @return Extracted payload data, or empty vector if failed.
     *
     * This extracts the injected code from a hollowed process for analysis.
     */
    [[nodiscard]] std::vector<uint8_t> ExtractPayload(uint32_t pid);

    /**
     * @brief Dump process memory to file.
     * @param pid Process ID.
     * @param outputPath Output file path.
     * @return True if dump succeeded.
     */
    bool DumpProcessMemory(uint32_t pid, const std::wstring& outputPath);

    /**
     * @brief Get hash of injected payload.
     * @param pid Process ID.
     * @return SHA256 hash of payload.
     */
    [[nodiscard]] std::array<uint8_t, 32> GetPayloadHash(uint32_t pid);

    // ========================================================================
    // STATISTICS & DIAGNOSTICS
    // ========================================================================

    /**
     * @brief Get detector statistics.
     * @return Current statistics.
     */
    [[nodiscard]] const HollowingStatistics& GetStatistics() const noexcept;

    /**
     * @brief Reset statistics.
     */
    void ResetStatistics() noexcept;

    /**
     * @brief Get detector version.
     * @return Version string.
     */
    [[nodiscard]] static std::string GetVersionString() noexcept;

    /**
     * @brief Run self-test.
     * @return True if all tests pass.
     */
    [[nodiscard]] bool SelfTest();

    /**
     * @brief Run self-diagnostics.
     * @return Diagnostic messages.
     */
    [[nodiscard]] std::vector<std::wstring> RunDiagnostics() const;

    // ========================================================================
    // EXCLUSION MANAGEMENT
    // ========================================================================

    /**
     * @brief Add process to exclusion list.
     * @param processName Process name to exclude.
     */
    void AddExclusion(const std::wstring& processName);

    /**
     * @brief Remove process from exclusion list.
     * @param processName Process name.
     */
    void RemoveExclusion(const std::wstring& processName);

    /**
     * @brief Check if process is excluded.
     * @param pid Process ID.
     * @return True if excluded.
     */
    [[nodiscard]] bool IsExcluded(uint32_t pid) const;

    /**
     * @brief Get all exclusions.
     * @return List of excluded process names.
     */
    [[nodiscard]] std::vector<std::wstring> GetExclusions() const;

private:
    // ========================================================================
    // PRIVATE CONSTRUCTOR (SINGLETON)
    // ========================================================================

    ProcessHollowingDetector();
    ~ProcessHollowingDetector();

    // ========================================================================
    // IMPLEMENTATION
    // ========================================================================

    std::unique_ptr<ProcessHollowingDetectorImpl> m_impl;
    static std::atomic<bool> s_instanceCreated;
};

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

[[nodiscard]] std::string_view GetHollowingTypeName(HollowingType type) noexcept;
[[nodiscard]] std::string_view GetConfidenceName(HollowingConfidence confidence) noexcept;
[[nodiscard]] std::string_view GetDetectionMethodName(DetectionMethod method) noexcept;
[[nodiscard]] std::string_view GetScanModeName(ScanMode mode) noexcept;
[[nodiscard]] std::string_view GetMonitorModeName(MonitorMode mode) noexcept;

} // namespace Process
} // namespace Core
} // namespace ShadowStrike
