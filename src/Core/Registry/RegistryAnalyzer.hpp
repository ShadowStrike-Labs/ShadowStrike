/**
 * ============================================================================
 * ShadowStrike Core Registry - REGISTRY ANALYZER (The Deep Inspector)
 * ============================================================================
 *
 * @file RegistryAnalyzer.hpp
 * @brief Enterprise-grade deep registry forensic analysis engine.
 *
 * This module provides comprehensive registry hive analysis for detecting
 * hidden entries, malformed structures, rootkit artifacts, and advanced
 * persistence mechanisms that evade standard API enumeration.
 *
 * Key Capabilities:
 * =================
 * 1. HIDDEN KEY DETECTION
 *    - NULL byte injection (RegHider technique)
 *    - Unicode control characters
 *    - Extended ASCII abuse
 *    - Abnormal key lengths
 *
 * 2. HIVE FORENSICS
 *    - Direct hive parsing (offline analysis)
 *    - Deleted key recovery
 *    - Timestamp analysis
 *    - Structure validation
 *
 * 3. ANOMALY DETECTION
 *    - Unusual value types
 *    - Oversized values
 *    - Embedded executables
 *    - Encoded/encrypted data
 *
 * 4. ROOTKIT DETECTION
 *    - API vs raw enumeration comparison
 *    - Cross-view detection
 *    - DKOM artifacts
 *    - Registry callbacks manipulation
 *
 * 5. THREAT HUNTING
 *    - Pattern-based search
 *    - YARA rule matching
 *    - IOC matching
 *    - Malware family detection
 *
 * Registry Analysis Architecture:
 * ===============================
 *   ┌─────────────────────────────────────────────────────────────────────┐
 *   │                        RegistryAnalyzer                             │
 *   ├─────────────────────────────────────────────────────────────────────┤
 *   │  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────────┐  │
 *   │  │ HiveParser   │  │HiddenDetector│  │    AnomalyDetector       │  │
 *   │  │              │  │              │  │                          │  │
 *   │  │ - Raw parse  │  │ - NULL bytes │  │ - Structure              │  │
 *   │  │ - Recovery   │  │ - Unicode    │  │ - Size                   │  │
 *   │  │ - Validation │  │ - Length     │  │ - Type                   │  │
 *   │  └──────────────┘  └──────────────┘  └──────────────────────────┘  │
 *   │                                                                     │
 *   │  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────────┐  │
 *   │  │RootkitFinder │  │ ThreatHunter │  │    ForensicEngine        │  │
 *   │  │              │  │              │  │                          │  │
 *   │  │ - Cross-view │  │ - Patterns   │  │ - Timeline               │  │
 *   │  │ - DKOM       │  │ - YARA       │  │ - Evidence               │  │
 *   │  │ - Callbacks  │  │ - IOCs       │  │ - Export                 │  │
 *   │  └──────────────┘  └──────────────┘  └──────────────────────────┘  │
 *   └─────────────────────────────────────────────────────────────────────┘
 *
 * Detection Techniques:
 * =====================
 * - API enumeration vs NtEnumerateKey comparison
 * - Raw hive parsing bypassing filter drivers
 * - Key name validation (NULL, control chars)
 * - Value data entropy analysis
 * - Structure offset validation
 * - Slack space analysis
 *
 * Integration Points:
 * ===================
 * - RegistryMonitor: Real-time complementary analysis
 * - PatternStore: YARA pattern matching
 * - ThreatIntel: IOC matching
 * - HashStore: Hash lookups
 *
 * MITRE ATT&CK Coverage:
 * ======================
 * - T1112: Modify Registry
 * - T1564.001: Hidden Files and Directories
 * - T1014: Rootkit (Registry hiding)
 * - T1547: Boot or Logon Autostart Execution
 *
 * Thread Safety:
 * ==============
 * - All public methods are thread-safe
 * - Concurrent analysis supported
 * - State is protected by shared mutex
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @date 2026
 * @copyright 2026 ShadowStrike Security Suite
 *
 * @see RegistryMonitor.hpp for real-time monitoring
 * @see PersistenceDetector.hpp for ASEP detection
 */

#pragma once

// ============================================================================
// STANDARD LIBRARY INCLUDES
// ============================================================================
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>
#include <array>
#include <unordered_map>
#include <unordered_set>
#include <set>
#include <optional>
#include <memory>
#include <functional>
#include <chrono>
#include <atomic>
#include <shared_mutex>
#include <span>

namespace ShadowStrike {
namespace Core {
namespace Registry {

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================
class RegistryAnalyzerImpl;  // PIMPL implementation

// ============================================================================
// NAMESPACE CONSTANTS
// ============================================================================
namespace RegistryAnalyzerConstants {

    // Version
    constexpr uint32_t VERSION_MAJOR = 3;
    constexpr uint32_t VERSION_MINOR = 0;
    constexpr uint32_t VERSION_PATCH = 0;

    // Limits
    constexpr size_t MAX_ANOMALIES = 100000;
    constexpr size_t MAX_KEY_NAME_LENGTH = 255;
    constexpr size_t MAX_VALUE_SIZE = 1024 * 1024;  // 1 MB
    constexpr uint32_t MAX_SCAN_DEPTH = 50;

    // Entropy thresholds
    constexpr double HIGH_ENTROPY_THRESHOLD = 7.0;
    constexpr double SUSPICIOUS_ENTROPY_THRESHOLD = 6.0;

    // Hive signatures
    constexpr uint32_t HIVE_SIGNATURE = 0x66676572;  // "regf"
    constexpr uint32_t HBIN_SIGNATURE = 0x6E696268;  // "hbin"

}  // namespace RegistryAnalyzerConstants

// ============================================================================
// ENUMERATIONS
// ============================================================================

/**
 * @enum AnalysisMode
 * @brief Registry analysis mode.
 */
enum class AnalysisMode : uint8_t {
    Quick = 0,                     // Fast API-based scan
    Standard = 1,                  // API + basic hidden detection
    Deep = 2,                      // Full forensic analysis
    Forensic = 3,                  // Offline hive analysis
    RootkitHunting = 4             // Cross-view rootkit detection
};

/**
 * @enum AnomalyType
 * @brief Type of registry anomaly.
 */
enum class AnomalyType : uint16_t {
    None = 0,

    // Hidden key techniques
    NullByteInjection = 1,         // NULL in key name
    UnicodeControlChar = 2,        // Control characters
    ExtendedAscii = 3,             // Non-printable characters
    OverlongName = 4,              // Name > MAX_KEY_NAME_LENGTH
    ZeroLengthName = 5,            // Empty name

    // Structural anomalies
    InvalidStructure = 10,         // Malformed structure
    CorruptedHeader = 11,          // Invalid header
    InvalidOffset = 12,            // Bad offset reference
    OrphanedCell = 13,             // Unlinked cell
    DeletedNotCleared = 14,        // Deleted but data remains

    // Value anomalies
    UnusualValueType = 20,         // Rare REG_* type
    OversizedValue = 21,           // Value too large
    EmbeddedExecutable = 22,       // PE/script in value
    EncodedData = 23,              // Base64/encoded content
    HighEntropy = 24,              // Encrypted/compressed
    SuspiciousPath = 25,           // Path to temp/unusual location

    // API discrepancy
    APIHiddenKey = 30,             // Found raw, not via API
    APIHiddenValue = 31,           // Value hidden from API
    CallbackFiltered = 32,         // Filtered by callback

    // Rootkit artifacts
    DKOMEvidence = 40,             // Direct kernel manipulation
    HookedFunction = 41,           // Registry API hooked
    ModifiedCallback = 42,         // CM callback modified

    // Threat indicators
    KnownMalwareKey = 50,          // Known malware location
    KnownMalwareValue = 51,        // Known malicious value
    SuspiciousAutorun = 52,        // Suspicious ASEP entry
    DataExfiltration = 53,         // Exfil staging

    // Timestamp anomalies
    FutureTimestamp = 60,          // Timestamp in future
    AncientTimestamp = 61,         // Impossibly old timestamp
    TimestampMismatch = 62         // Inconsistent timestamps
};

/**
 * @enum HiveType
 * @brief Windows registry hive type.
 */
enum class HiveType : uint8_t {
    Unknown = 0,
    SAM = 1,
    SECURITY = 2,
    SOFTWARE = 3,
    SYSTEM = 4,
    DEFAULT = 5,
    NTUSER = 6,
    USRCLASS = 7,
    AMCACHE = 8,
    BCD = 9,
    COMPONENTS = 10
};

/**
 * @enum AnomalySeverity
 * @brief Severity of detected anomaly.
 */
enum class AnomalySeverity : uint8_t {
    Info = 0,
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4
};

/**
 * @enum ValueDataType
 * @brief Detected data type in value.
 */
enum class ValueDataType : uint8_t {
    Unknown = 0,
    String = 1,
    Integer = 2,
    Binary = 3,
    Path = 4,
    URL = 5,
    IPAddress = 6,
    Base64 = 7,
    Hex = 8,
    Executable = 9,
    Script = 10,
    Encrypted = 11,
    Compressed = 12,
    GUID = 13
};

// ============================================================================
// DATA STRUCTURES
// ============================================================================

/**
 * @struct HiveHeader
 * @brief Parsed registry hive header.
 */
struct alignas(64) HiveHeader {
    uint32_t signature{ 0 };
    uint32_t sequence1{ 0 };
    uint32_t sequence2{ 0 };
    std::chrono::system_clock::time_point lastWritten;
    uint32_t majorVersion{ 0 };
    uint32_t minorVersion{ 0 };
    uint32_t hiveType{ 0 };
    uint32_t format{ 0 };
    uint32_t rootCellOffset{ 0 };
    uint32_t dataLength{ 0 };
    std::wstring hiveName;

    bool isValid{ false };
    bool isCorrupted{ false };
    bool isDirty{ false };
};

/**
 * @struct KeyCell
 * @brief Registry key cell information.
 */
struct alignas(128) KeyCell {
    uint32_t offset{ 0 };
    int32_t cellSize{ 0 };
    bool isAllocated{ false };
    bool isDeleted{ false };

    std::wstring keyName;
    std::wstring keyNameRaw;           // With control chars
    uint32_t subKeyCount{ 0 };
    uint32_t valueCount{ 0 };

    std::chrono::system_clock::time_point lastWritten;

    uint32_t parentOffset{ 0 };
    uint32_t classNameOffset{ 0 };
    uint32_t securityOffset{ 0 };
    std::wstring className;

    // Anomaly indicators
    bool hasHiddenChars{ false };
    bool hasNullByte{ false };
    bool isOrphaned{ false };
};

/**
 * @struct ValueCell
 * @brief Registry value cell information.
 */
struct alignas(128) ValueCell {
    uint32_t offset{ 0 };
    std::wstring valueName;
    uint32_t valueType{ 0 };           // REG_* type
    uint32_t dataSize{ 0 };
    uint32_t dataOffset{ 0 };

    std::vector<uint8_t> data;
    std::wstring dataAsString;

    // Analysis results
    ValueDataType detectedType{ ValueDataType::Unknown };
    double entropy{ 0.0 };
    bool isExecutable{ false };
    bool isEncoded{ false };
    bool isHighEntropy{ false };

    // Anomaly indicators
    bool hasHiddenChars{ false };
    bool isDeleted{ false };
};

/**
 * @struct RegistryAnomaly
 * @brief Detected registry anomaly.
 */
struct alignas(256) RegistryAnomaly {
    uint64_t anomalyId{ 0 };
    std::chrono::system_clock::time_point detectedTime;

    // Location
    HiveType hive{ HiveType::Unknown };
    std::wstring hivePath;
    std::wstring keyPath;
    std::wstring valueName;

    // Anomaly details
    AnomalyType type{ AnomalyType::None };
    AnomalySeverity severity{ AnomalySeverity::Info };
    std::string description;
    std::string technique;             // MITRE technique ID

    // Evidence
    std::vector<uint8_t> rawData;
    std::wstring decodedData;
    std::string hexDump;

    // Analysis
    double entropy{ 0.0 };
    bool isHidden{ false };
    bool isDeleted{ false };
    bool isMalicious{ false };

    // Threat info
    std::string malwareFamily;
    std::vector<std::string> matchedPatterns;
    std::vector<std::string> matchedIOCs;

    // Hashes
    std::array<uint8_t, 32> sha256{ 0 };
    std::string sha256Hex;

    // Raw offsets (for forensics)
    uint32_t keyCellOffset{ 0 };
    uint32_t valueCellOffset{ 0 };
};

/**
 * @struct CrossViewResult
 * @brief Result of cross-view rootkit detection.
 */
struct alignas(128) CrossViewResult {
    std::wstring keyPath;

    // API enumeration
    bool foundViaAPI{ false };
    std::vector<std::wstring> apiSubKeys;
    std::vector<std::wstring> apiValues;

    // Raw enumeration
    bool foundViaRaw{ false };
    std::vector<std::wstring> rawSubKeys;
    std::vector<std::wstring> rawValues;

    // Differences
    std::vector<std::wstring> hiddenSubKeys;
    std::vector<std::wstring> hiddenValues;
    bool hasDiscrepancy{ false };
};

/**
 * @struct DeletedEntry
 * @brief Recovered deleted registry entry.
 */
struct alignas(128) DeletedEntry {
    bool isKey{ false };
    std::wstring path;
    std::wstring name;

    // For values
    uint32_t valueType{ 0 };
    std::vector<uint8_t> data;

    // Metadata
    std::chrono::system_clock::time_point deletedTime;
    uint32_t cellOffset{ 0 };
    bool isRecoverable{ false };
    bool isPartial{ false };
};

/**
 * @struct AnalysisScope
 * @brief Scope of registry analysis.
 */
struct alignas(64) AnalysisScope {
    // Hives to analyze
    bool analyzeSAM{ false };
    bool analyzeSECURITY{ false };
    bool analyzeSOFTWARE{ true };
    bool analyzeSYSTEM{ true };
    bool analyzeNTUSER{ true };
    bool analyzeUSRCLASS{ true };

    // Specific paths
    std::vector<std::wstring> specificPaths;

    // Depth
    uint32_t maxDepth{ RegistryAnalyzerConstants::MAX_SCAN_DEPTH };

    // Filters
    bool includeDeleted{ false };
    bool includeSlackSpace{ false };
    std::chrono::system_clock::time_point modifiedAfter;
    std::chrono::system_clock::time_point modifiedBefore;
};

/**
 * @struct AnalysisResult
 * @brief Result of registry analysis.
 */
struct alignas(128) AnalysisResult {
    // Scope
    AnalysisMode mode{ AnalysisMode::Standard };
    std::chrono::system_clock::time_point startTime;
    std::chrono::system_clock::time_point endTime;
    std::chrono::milliseconds duration{ 0 };

    // Counts
    uint64_t keysAnalyzed{ 0 };
    uint64_t valuesAnalyzed{ 0 };
    uint64_t hivesAnalyzed{ 0 };
    uint64_t bytesAnalyzed{ 0 };

    // Findings
    uint64_t anomaliesFound{ 0 };
    uint64_t hiddenKeysFound{ 0 };
    uint64_t hiddenValuesFound{ 0 };
    uint64_t deletedRecovered{ 0 };
    uint64_t maliciousEntries{ 0 };

    // Severity breakdown
    uint32_t criticalAnomalies{ 0 };
    uint32_t highAnomalies{ 0 };
    uint32_t mediumAnomalies{ 0 };
    uint32_t lowAnomalies{ 0 };

    // Status
    bool completed{ false };
    bool hadErrors{ false };
    std::vector<std::string> errors;
};

/**
 * @struct ThreatIndicator
 * @brief Registry-based threat indicator.
 */
struct alignas(64) ThreatIndicator {
    std::wstring keyPattern;
    std::wstring valuePattern;
    std::vector<uint8_t> dataPattern;

    std::string threatName;
    std::string malwareFamily;
    std::string mitreId;

    bool isRegex{ false };
};

/**
 * @struct ForensicTimeline
 * @brief Forensic timeline entry.
 */
struct alignas(128) ForensicTimeline {
    std::chrono::system_clock::time_point timestamp;
    std::string action;                // Created, Modified, Deleted
    HiveType hive{ HiveType::Unknown };
    std::wstring keyPath;
    std::wstring valueName;

    std::string description;
    bool isAnomaly{ false };
};

/**
 * @struct RegistryAnalyzerConfig
 * @brief Configuration for registry analyzer.
 */
struct alignas(64) RegistryAnalyzerConfig {
    // Analysis options
    AnalysisMode defaultMode{ AnalysisMode::Standard };
    bool detectHiddenKeys{ true };
    bool detectHiddenValues{ true };
    bool analyzeEntropy{ true };
    bool detectEmbeddedExecutables{ true };

    // Rootkit detection
    bool enableCrossView{ true };
    bool detectDKOM{ true };

    // Forensics
    bool recoverDeleted{ false };
    bool analyzeSlackSpace{ false };
    bool buildTimeline{ true };

    // Threat hunting
    bool matchPatterns{ true };
    bool matchIOCs{ true };
    std::wstring patternDatabasePath;
    std::wstring iocDatabasePath;

    // Performance
    uint32_t maxAnomalies{ RegistryAnalyzerConstants::MAX_ANOMALIES };
    uint32_t threadCount{ 4 };

    // Factory methods
    static RegistryAnalyzerConfig CreateDefault() noexcept;
    static RegistryAnalyzerConfig CreateForensic() noexcept;
    static RegistryAnalyzerConfig CreateRootkitHunting() noexcept;
    static RegistryAnalyzerConfig CreateQuick() noexcept;
};

/**
 * @struct RegistryAnalyzerStatistics
 * @brief Runtime statistics.
 */
struct alignas(128) RegistryAnalyzerStatistics {
    std::atomic<uint64_t> totalScans{ 0 };
    std::atomic<uint64_t> keysAnalyzed{ 0 };
    std::atomic<uint64_t> valuesAnalyzed{ 0 };
    std::atomic<uint64_t> bytesAnalyzed{ 0 };

    std::atomic<uint64_t> anomaliesDetected{ 0 };
    std::atomic<uint64_t> hiddenKeysFound{ 0 };
    std::atomic<uint64_t> hiddenValuesFound{ 0 };
    std::atomic<uint64_t> rootkitIndicators{ 0 };
    std::atomic<uint64_t> maliciousEntries{ 0 };

    std::atomic<uint64_t> deletedRecovered{ 0 };
    std::atomic<uint64_t> patternsMatched{ 0 };
    std::atomic<uint64_t> iocsMatched{ 0 };

    void Reset() noexcept;
};

// ============================================================================
// CALLBACK TYPE DEFINITIONS
// ============================================================================

/**
 * @brief Callback for anomaly detection.
 */
using AnomalyCallback = std::function<void(const RegistryAnomaly& anomaly)>;

/**
 * @brief Callback for scan progress.
 */
using ScanProgressCallback = std::function<void(const std::wstring& currentPath, uint32_t progressPercent)>;

/**
 * @brief Callback for hidden entry detection.
 */
using HiddenEntryCallback = std::function<void(const std::wstring& path, bool isKey)>;

// ============================================================================
// MAIN CLASS DEFINITION
// ============================================================================

/**
 * @class RegistryAnalyzer
 * @brief Enterprise-grade registry forensic analysis engine.
 *
 * Thread Safety:
 * All public methods are thread-safe.
 *
 * Usage Example:
 * @code
 * auto& analyzer = RegistryAnalyzer::Instance();
 * 
 * // Configure forensic mode
 * auto config = RegistryAnalyzerConfig::CreateForensic();
 * analyzer.Initialize(config);
 * 
 * // Set scope
 * AnalysisScope scope;
 * scope.analyzeSOFTWARE = true;
 * scope.analyzeSYSTEM = true;
 * scope.includeDeleted = true;
 * 
 * // Run analysis
 * auto result = analyzer.Analyze(scope, AnalysisMode::Deep);
 * 
 * // Get anomalies
 * auto anomalies = analyzer.GetAnomalies();
 * for (const auto& anomaly : anomalies) {
 *     if (anomaly.severity >= AnomalySeverity::High) {
 *         // Handle high severity anomaly
 *     }
 * }
 * 
 * // Get hidden keys
 * auto hidden = analyzer.GetHiddenKeys();
 * 
 * // Export forensic timeline
 * analyzer.ExportTimeline(L"C:\\Evidence\\timeline.csv");
 * @endcode
 */
class RegistryAnalyzer {
public:
    // ========================================================================
    // SINGLETON ACCESS
    // ========================================================================

    static RegistryAnalyzer& Instance();

    // ========================================================================
    // LIFECYCLE MANAGEMENT
    // ========================================================================

    /**
     * @brief Initializes the registry analyzer.
     * @param config Configuration settings.
     * @return True if successful.
     */
    bool Initialize(const RegistryAnalyzerConfig& config);

    /**
     * @brief Shuts down and releases resources.
     */
    void Shutdown() noexcept;

    // ========================================================================
    // ANALYSIS OPERATIONS
    // ========================================================================

    /**
     * @brief Runs registry analysis.
     * @param scope Analysis scope.
     * @param mode Analysis mode.
     * @return Analysis result.
     */
    [[nodiscard]] AnalysisResult Analyze(const AnalysisScope& scope, AnalysisMode mode = AnalysisMode::Standard);

    /**
     * @brief Analyzes specific key path.
     * @param keyPath Registry key path.
     * @param recursive Analyze subkeys.
     * @return Vector of anomalies.
     */
    [[nodiscard]] std::vector<RegistryAnomaly> AnalyzeKey(const std::wstring& keyPath, bool recursive = true);

    /**
     * @brief Analyzes offline hive file.
     * @param hivePath Path to hive file.
     * @return Analysis result.
     */
    [[nodiscard]] AnalysisResult AnalyzeHiveFile(const std::wstring& hivePath);

    /**
     * @brief Aborts running analysis.
     */
    void AbortAnalysis() noexcept;

    /**
     * @brief Checks if analysis is running.
     * @return True if running.
     */
    [[nodiscard]] bool IsAnalysisRunning() const noexcept;

    // ========================================================================
    // HIDDEN ENTRY DETECTION
    // ========================================================================

    /**
     * @brief Detects hidden keys using NULL byte technique.
     * @param rootKey Root key to scan.
     * @return Vector of hidden key paths.
     */
    [[nodiscard]] std::vector<std::wstring> DetectNullByteKeys(const std::wstring& rootKey);

    /**
     * @brief Performs cross-view rootkit detection.
     * @param keyPath Key to analyze.
     * @return Cross-view result.
     */
    [[nodiscard]] CrossViewResult PerformCrossViewDetection(const std::wstring& keyPath);

    /**
     * @brief Gets all detected hidden keys.
     * @return Vector of hidden key paths.
     */
    [[nodiscard]] std::vector<std::wstring> GetHiddenKeys() const;

    /**
     * @brief Gets all detected hidden values.
     * @return Map of key path to hidden value names.
     */
    [[nodiscard]] std::unordered_map<std::wstring, std::vector<std::wstring>> GetHiddenValues() const;

    // ========================================================================
    // ANOMALY ACCESS
    // ========================================================================

    /**
     * @brief Gets all detected anomalies.
     * @return Vector of anomalies.
     */
    [[nodiscard]] std::vector<RegistryAnomaly> GetAnomalies() const;

    /**
     * @brief Gets anomalies by type.
     * @param type Anomaly type.
     * @return Vector of anomalies.
     */
    [[nodiscard]] std::vector<RegistryAnomaly> GetAnomaliesByType(AnomalyType type) const;

    /**
     * @brief Gets anomalies by severity.
     * @param minSeverity Minimum severity.
     * @return Vector of anomalies.
     */
    [[nodiscard]] std::vector<RegistryAnomaly> GetAnomaliesBySeverity(AnomalySeverity minSeverity) const;

    /**
     * @brief Gets anomaly by ID.
     * @param anomalyId Anomaly ID.
     * @return Anomaly, or nullopt.
     */
    [[nodiscard]] std::optional<RegistryAnomaly> GetAnomalyById(uint64_t anomalyId) const;

    /**
     * @brief Clears detected anomalies.
     */
    void ClearAnomalies() noexcept;

    // ========================================================================
    // DELETED ENTRY RECOVERY
    // ========================================================================

    /**
     * @brief Recovers deleted entries from hive.
     * @param hive Hive to recover from.
     * @return Vector of deleted entries.
     */
    [[nodiscard]] std::vector<DeletedEntry> RecoverDeletedEntries(HiveType hive);

    /**
     * @brief Recovers deleted entries from hive file.
     * @param hivePath Path to hive file.
     * @return Vector of deleted entries.
     */
    [[nodiscard]] std::vector<DeletedEntry> RecoverFromHiveFile(const std::wstring& hivePath);

    // ========================================================================
    // HIVE PARSING
    // ========================================================================

    /**
     * @brief Parses hive header.
     * @param hivePath Path to hive file.
     * @return Parsed header.
     */
    [[nodiscard]] HiveHeader ParseHiveHeader(const std::wstring& hivePath);

    /**
     * @brief Validates hive structure.
     * @param hivePath Path to hive file.
     * @return True if valid.
     */
    [[nodiscard]] bool ValidateHiveStructure(const std::wstring& hivePath);

    /**
     * @brief Gets key cell at offset.
     * @param hivePath Path to hive file.
     * @param offset Cell offset.
     * @return Key cell, or nullopt.
     */
    [[nodiscard]] std::optional<KeyCell> GetKeyCell(const std::wstring& hivePath, uint32_t offset);

    // ========================================================================
    // THREAT HUNTING
    // ========================================================================

    /**
     * @brief Loads threat indicators.
     * @param indicatorsPath Path to indicators file.
     * @return Number loaded.
     */
    size_t LoadThreatIndicators(const std::wstring& indicatorsPath);

    /**
     * @brief Adds threat indicator.
     * @param indicator Indicator to add.
     */
    void AddThreatIndicator(const ThreatIndicator& indicator);

    /**
     * @brief Searches for IOCs.
     * @param iocs Vector of IOC patterns.
     * @return Vector of matching anomalies.
     */
    [[nodiscard]] std::vector<RegistryAnomaly> SearchIOCs(const std::vector<std::wstring>& iocs);

    // ========================================================================
    // FORENSIC TIMELINE
    // ========================================================================

    /**
     * @brief Gets forensic timeline.
     * @param startTime Start of timeframe.
     * @param endTime End of timeframe.
     * @return Vector of timeline entries.
     */
    [[nodiscard]] std::vector<ForensicTimeline> GetTimeline(
        std::chrono::system_clock::time_point startTime,
        std::chrono::system_clock::time_point endTime) const;

    /**
     * @brief Exports timeline to file.
     * @param outputPath Output file path.
     * @return True if successful.
     */
    bool ExportTimeline(const std::wstring& outputPath) const;

    // ========================================================================
    // ENTROPY ANALYSIS
    // ========================================================================

    /**
     * @brief Calculates entropy of data.
     * @param data Data to analyze.
     * @return Entropy value (0-8).
     */
    [[nodiscard]] double CalculateEntropy(std::span<const uint8_t> data) const noexcept;

    /**
     * @brief Gets high-entropy values.
     * @param minEntropy Minimum entropy threshold.
     * @return Vector of anomalies.
     */
    [[nodiscard]] std::vector<RegistryAnomaly> GetHighEntropyValues(double minEntropy = 7.0) const;

    // ========================================================================
    // CALLBACK REGISTRATION
    // ========================================================================

    [[nodiscard]] uint64_t RegisterAnomalyCallback(AnomalyCallback callback);
    [[nodiscard]] uint64_t RegisterProgressCallback(ScanProgressCallback callback);
    [[nodiscard]] uint64_t RegisterHiddenEntryCallback(HiddenEntryCallback callback);
    bool UnregisterCallback(uint64_t callbackId);

    // ========================================================================
    // STATISTICS
    // ========================================================================

    [[nodiscard]] const RegistryAnalyzerStatistics& GetStatistics() const noexcept;
    void ResetStatistics() noexcept;

    // ========================================================================
    // EXPORT
    // ========================================================================

    bool ExportReport(const std::wstring& outputPath) const;
    bool ExportAnomalies(const std::wstring& outputPath) const;
    bool ExportHiddenEntries(const std::wstring& outputPath) const;

private:
    RegistryAnalyzer();
    ~RegistryAnalyzer();

    RegistryAnalyzer(const RegistryAnalyzer&) = delete;
    RegistryAnalyzer& operator=(const RegistryAnalyzer&) = delete;

    std::unique_ptr<RegistryAnalyzerImpl> m_impl;
};

}  // namespace Registry
}  // namespace Core
}  // namespace ShadowStrike
