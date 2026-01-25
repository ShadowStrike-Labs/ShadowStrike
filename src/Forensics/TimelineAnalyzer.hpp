/**
 * ============================================================================
 * ShadowStrike Forensics - ATTACK TIMELINE ANALYZER
 * ============================================================================
 *
 * @file TimelineAnalyzer.hpp
 * @brief Enterprise-grade attack timeline reconstruction and analysis engine
 *        for forensic investigation of malicious activity sequences.
 *
 * This module provides comprehensive timeline analysis capabilities for
 * reconstructing attack chains and understanding the sequence of malicious
 * events during incident investigation.
 *
 * TIMELINE CAPABILITIES:
 * ======================
 *
 * 1. EVENT COLLECTION
 *    - Process creation/termination
 *    - File system operations
 *    - Registry modifications
 *    - Network connections
 *    - Module loads
 *    - User sessions
 *
 * 2. EVENT ORDERING
 *    - 100ns precision timestamps
 *    - Clock skew detection
 *    - Event correlation
 *    - Gap analysis
 *    - Overlapping event handling
 *
 * 3. CAUSAL ANALYSIS
 *    - Process lineage tracking
 *    - File provenance chains
 *    - Code injection paths
 *    - Privilege escalation chains
 *    - Lateral movement detection
 *
 * 4. ATTACK CHAIN DETECTION
 *    - MITRE ATT&CK mapping
 *    - Kill chain identification
 *    - Technique sequences
 *    - Campaign patterns
 *    - TTP clustering
 *
 * 5. VISUALIZATION DATA
 *    - Graph export (DOT, GEXF)
 *    - Interactive timeline JSON
 *    - Process tree generation
 *    - Attack path diagrams
 *
 * 6. ANOMALY DETECTION
 *    - Temporal anomalies
 *    - Sequence anomalies
 *    - Frequency anomalies
 *    - Pattern deviations
 *
 * INTEGRATION:
 * ============
 * - ETW event correlation
 * - Windows Event Log analysis
 * - USN journal parsing
 * - Prefetch correlation
 * - SIEM timeline export
 *
 * @note Requires data from EvidenceCollector, ArtifactExtractor, IncidentRecorder.
 * @note Timestamps should be normalized to UTC for consistency.
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
#include "../Utils/HashUtils.hpp"
#include "../Utils/TimeUtils.hpp"

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

namespace ShadowStrike::Forensics {
    class TimelineAnalyzerImpl;
    class IncidentRecorder;
    class ArtifactExtractor;
}

namespace ShadowStrike {
namespace Forensics {

// ============================================================================
// COMPILE-TIME CONSTANTS
// ============================================================================

namespace TimelineConstants {

    // ========================================================================
    // VERSION
    // ========================================================================
    
    inline constexpr uint32_t VERSION_MAJOR = 3;
    inline constexpr uint32_t VERSION_MINOR = 0;
    inline constexpr uint32_t VERSION_PATCH = 0;

    // ========================================================================
    // LIMITS
    // ========================================================================
    
    /// @brief Maximum events in timeline
    inline constexpr size_t MAX_TIMELINE_EVENTS = 1000000;
    
    /// @brief Maximum attack chains
    inline constexpr size_t MAX_ATTACK_CHAINS = 100;
    
    /// @brief Maximum causal links
    inline constexpr size_t MAX_CAUSAL_LINKS = 10000;
    
    /// @brief Maximum graph nodes
    inline constexpr size_t MAX_GRAPH_NODES = 5000;
    
    /// @brief Maximum techniques per chain
    inline constexpr size_t MAX_TECHNIQUES_PER_CHAIN = 50;

    // ========================================================================
    // TIMING
    // ========================================================================
    
    /// @brief Clock skew threshold (nanoseconds)
    inline constexpr int64_t CLOCK_SKEW_THRESHOLD_NS = 1000000000;  // 1 second
    
    /// @brief Event correlation window (milliseconds)
    inline constexpr uint32_t CORRELATION_WINDOW_MS = 5000;
    
    /// @brief Gap detection threshold (seconds)
    inline constexpr uint32_t GAP_THRESHOLD_SECS = 60;

    // ========================================================================
    // ANALYSIS
    // ========================================================================
    
    /// @brief Minimum events for pattern detection
    inline constexpr size_t MIN_EVENTS_FOR_PATTERN = 3;
    
    /// @brief Confidence threshold for chains
    inline constexpr double CONFIDENCE_THRESHOLD = 0.7;

}  // namespace TimelineConstants

// ============================================================================
// TYPE ALIASES
// ============================================================================

using Clock = std::chrono::steady_clock;
using TimePoint = std::chrono::steady_clock::time_point;
using SystemTimePoint = std::chrono::system_clock::time_point;
using FileTime = uint64_t;  // FILETIME as 100ns intervals since 1601
using Hash256 = std::array<uint8_t, 32>;

// ============================================================================
// ENUMERATIONS
// ============================================================================

/**
 * @brief Timeline event type
 */
enum class TimelineEventType : uint8_t {
    Unknown             = 0,
    
    // Process events
    ProcessCreate       = 1,
    ProcessTerminate    = 2,
    ProcessInject       = 3,
    
    // File events
    FileCreate          = 10,
    FileModify          = 11,
    FileDelete          = 12,
    FileRename          = 13,
    FileRead            = 14,
    FileExecute         = 15,
    
    // Registry events
    RegistryCreate      = 20,
    RegistryModify      = 21,
    RegistryDelete      = 22,
    
    // Network events
    NetworkConnect      = 30,
    NetworkListen       = 31,
    NetworkData         = 32,
    DNSQuery            = 33,
    
    // Module events
    ModuleLoad          = 40,
    ModuleUnload        = 41,
    
    // User events
    UserLogon           = 50,
    UserLogoff          = 51,
    PrivilegeUse        = 52,
    
    // Security events
    Detection           = 60,
    Remediation         = 61,
    Quarantine          = 62
};

/**
 * @brief Event severity
 */
enum class EventSeverity : uint8_t {
    Info        = 0,
    Low         = 1,
    Medium      = 2,
    High        = 3,
    Critical    = 4
};

/**
 * @brief Causal relationship type
 */
enum class CausalRelationType : uint8_t {
    Unknown         = 0,
    ParentOf        = 1,    ///< Process parent-child
    CreatedBy       = 2,    ///< File created by process
    ExecutedBy      = 3,    ///< File executed by process
    ModifiedBy      = 4,    ///< Object modified by process
    LoadedBy        = 5,    ///< Module loaded by process
    InjectedBy      = 6,    ///< Code injected by process
    ConnectedFrom   = 7,    ///< Network from process
    EscalatedTo     = 8,    ///< Privilege escalation
    PersistsVia     = 9     ///< Persistence mechanism
};

/**
 * @brief Attack chain confidence
 */
enum class ChainConfidence : uint8_t {
    Unknown     = 0,
    Low         = 1,
    Medium      = 2,
    High        = 3,
    Confirmed   = 4
};

/**
 * @brief MITRE ATT&CK tactic
 */
enum class MitreTactic : uint8_t {
    Unknown                 = 0,
    InitialAccess           = 1,
    Execution               = 2,
    Persistence             = 3,
    PrivilegeEscalation     = 4,
    DefenseEvasion          = 5,
    CredentialAccess        = 6,
    Discovery               = 7,
    LateralMovement         = 8,
    Collection              = 9,
    CommandAndControl       = 10,
    Exfiltration            = 11,
    Impact                  = 12
};

/**
 * @brief Timeline export format
 */
enum class TimelineFormat : uint8_t {
    JSON        = 0,    ///< JSON format
    CSV         = 1,    ///< CSV format
    XML         = 2,    ///< XML format
    STIX        = 3,    ///< STIX 2.1 format
    GraphViz    = 4,    ///< DOT format
    GEXF        = 5,    ///< GEXF format
    Plaso       = 6     ///< Plaso format
};

/**
 * @brief Analysis mode
 */
enum class AnalysisMode : uint8_t {
    Quick       = 0,    ///< Fast analysis
    Standard    = 1,    ///< Standard analysis
    Deep        = 2,    ///< Deep analysis
    Forensic    = 3     ///< Full forensic analysis
};

/**
 * @brief Module status
 */
enum class ModuleStatus : uint8_t {
    Uninitialized   = 0,
    Initializing    = 1,
    Running         = 2,
    Analyzing       = 3,
    Paused          = 4,
    Stopping        = 5,
    Stopped         = 6,
    Error           = 7
};

// ============================================================================
// STRUCTURES
// ============================================================================

/**
 * @brief Timeline event
 */
struct TimelineEvent {
    /// @brief Event ID
    uint64_t eventId = 0;
    
    /// @brief Timestamp (FILETIME)
    FileTime timestamp = 0;
    
    /// @brief System time
    SystemTimePoint systemTime;
    
    /// @brief Event type
    TimelineEventType eventType = TimelineEventType::Unknown;
    
    /// @brief Severity
    EventSeverity severity = EventSeverity::Info;
    
    /// @brief Actor process ID
    uint32_t actorPid = 0;
    
    /// @brief Actor process name
    std::wstring actorName;
    
    /// @brief Actor process path
    std::wstring actorPath;
    
    /// @brief Action description
    std::wstring action;
    
    /// @brief Target object
    std::wstring targetObject;
    
    /// @brief Target path
    std::wstring targetPath;
    
    /// @brief Additional details
    std::wstring details;
    
    /// @brief MITRE tactic
    MitreTactic tactic = MitreTactic::Unknown;
    
    /// @brief MITRE technique ID
    std::string techniqueId;
    
    /// @brief Source (e.g., "ETW", "EventLog", "USN")
    std::string source;
    
    /// @brief Is suspicious
    bool isSuspicious = false;
    
    /// @brief Related event IDs
    std::vector<uint64_t> relatedEvents;
    
    /**
     * @brief Serialize to JSON
     */
    [[nodiscard]] std::string ToJson() const;
    
    /**
     * @brief Compare by timestamp
     */
    [[nodiscard]] bool operator<(const TimelineEvent& other) const noexcept {
        return timestamp < other.timestamp;
    }
};

/**
 * @brief Legacy compatibility structure
 */
struct TimelinePoint {
    uint64_t timestamp;
    std::wstring actor;
    std::wstring action;
    std::wstring object;
    
    /**
     * @brief Convert from TimelineEvent
     */
    static TimelinePoint FromEvent(const TimelineEvent& event);
};

/**
 * @brief Causal link between events
 */
struct CausalLink {
    /// @brief Link ID
    uint64_t linkId = 0;
    
    /// @brief Source event ID
    uint64_t sourceEventId = 0;
    
    /// @brief Target event ID
    uint64_t targetEventId = 0;
    
    /// @brief Relationship type
    CausalRelationType relationType = CausalRelationType::Unknown;
    
    /// @brief Confidence score (0.0 - 1.0)
    double confidence = 0.0;
    
    /// @brief Evidence for link
    std::string evidence;
    
    /**
     * @brief Serialize to JSON
     */
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Attack technique
 */
struct AttackTechnique {
    /// @brief MITRE technique ID (e.g., "T1055.001")
    std::string techniqueId;
    
    /// @brief Technique name
    std::string techniqueName;
    
    /// @brief Tactic
    MitreTactic tactic = MitreTactic::Unknown;
    
    /// @brief Related event IDs
    std::vector<uint64_t> eventIds;
    
    /// @brief First occurrence
    FileTime firstOccurrence = 0;
    
    /// @brief Last occurrence
    FileTime lastOccurrence = 0;
    
    /// @brief Occurrence count
    uint32_t occurrenceCount = 0;
    
    /// @brief Confidence
    double confidence = 0.0;
    
    /**
     * @brief Serialize to JSON
     */
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Attack chain
 */
struct AttackChain {
    /// @brief Chain ID
    std::string chainId;
    
    /// @brief Chain name
    std::string chainName;
    
    /// @brief Start time
    FileTime startTime = 0;
    
    /// @brief End time
    FileTime endTime = 0;
    
    /// @brief Duration (milliseconds)
    uint64_t durationMs = 0;
    
    /// @brief Initial access vector
    std::wstring initialAccessVector;
    
    /// @brief Final objective
    std::wstring finalObjective;
    
    /// @brief Techniques in order
    std::vector<AttackTechnique> techniques;
    
    /// @brief Event IDs in chain
    std::vector<uint64_t> eventIds;
    
    /// @brief Causal links
    std::vector<CausalLink> causalLinks;
    
    /// @brief Confidence
    ChainConfidence confidence = ChainConfidence::Unknown;
    
    /// @brief Confidence score
    double confidenceScore = 0.0;
    
    /// @brief Summary
    std::string summary;
    
    /**
     * @brief Serialize to JSON
     */
    [[nodiscard]] std::string ToJson() const;
    
    /**
     * @brief Generate MITRE ATT&CK Navigator layer
     */
    [[nodiscard]] std::string ToATTCKNavigator() const;
};

/**
 * @brief Process node in timeline graph
 */
struct ProcessNode {
    /// @brief Process ID
    uint32_t pid = 0;
    
    /// @brief Process name
    std::wstring processName;
    
    /// @brief Process path
    std::wstring processPath;
    
    /// @brief Command line
    std::wstring commandLine;
    
    /// @brief Parent PID
    uint32_t parentPid = 0;
    
    /// @brief Creation time
    FileTime creationTime = 0;
    
    /// @brief Termination time
    FileTime terminationTime = 0;
    
    /// @brief User SID
    std::wstring userSid;
    
    /// @brief Integrity level
    uint32_t integrityLevel = 0;
    
    /// @brief Event IDs associated
    std::vector<uint64_t> eventIds;
    
    /// @brief Is suspicious
    bool isSuspicious = false;
    
    /**
     * @brief Serialize to JSON
     */
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Timeline gap
 */
struct TimelineGap {
    /// @brief Gap start time
    FileTime startTime = 0;
    
    /// @brief Gap end time
    FileTime endTime = 0;
    
    /// @brief Duration (milliseconds)
    uint64_t durationMs = 0;
    
    /// @brief Event before gap
    uint64_t eventBeforeId = 0;
    
    /// @brief Event after gap
    uint64_t eventAfterId = 0;
    
    /// @brief Is suspicious
    bool isSuspicious = false;
    
    /// @brief Reason
    std::string reason;
};

/**
 * @brief Timeline analysis result
 */
struct TimelineAnalysisResult {
    /// @brief Analysis ID
    std::string analysisId;
    
    /// @brief Analysis time
    SystemTimePoint analysisTime;
    
    /// @brief Duration (milliseconds)
    uint64_t analysisDurationMs = 0;
    
    /// @brief Analysis mode
    AnalysisMode mode = AnalysisMode::Standard;
    
    /// @brief Total events
    uint64_t totalEvents = 0;
    
    /// @brief Suspicious events
    uint64_t suspiciousEvents = 0;
    
    /// @brief Attack chains detected
    std::vector<AttackChain> attackChains;
    
    /// @brief Techniques detected
    std::vector<AttackTechnique> techniques;
    
    /// @brief Timeline gaps
    std::vector<TimelineGap> gaps;
    
    /// @brief Key findings
    std::vector<std::string> keyFindings;
    
    /// @brief Recommendations
    std::vector<std::string> recommendations;
    
    /// @brief Overall risk score (0-100)
    uint8_t riskScore = 0;
    
    /**
     * @brief Serialize to JSON
     */
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Timeline filter
 */
struct TimelineFilter {
    /// @brief Start time
    std::optional<FileTime> startTime;
    
    /// @brief End time
    std::optional<FileTime> endTime;
    
    /// @brief Event types
    std::vector<TimelineEventType> eventTypes;
    
    /// @brief Process IDs
    std::vector<uint32_t> processIds;
    
    /// @brief Process names (wildcard supported)
    std::vector<std::wstring> processNames;
    
    /// @brief Target paths (wildcard supported)
    std::vector<std::wstring> targetPaths;
    
    /// @brief Minimum severity
    EventSeverity minSeverity = EventSeverity::Info;
    
    /// @brief Only suspicious
    bool onlySuspicious = false;
    
    /// @brief Include MITRE techniques
    std::vector<std::string> includeTechniques;
    
    /// @brief Maximum results
    size_t maxResults = TimelineConstants::MAX_TIMELINE_EVENTS;
    
    /**
     * @brief Check if event matches filter
     */
    [[nodiscard]] bool Matches(const TimelineEvent& event) const;
};

/**
 * @brief Timeline configuration
 */
struct TimelineAnalyzerConfiguration {
    /// @brief Default analysis mode
    AnalysisMode defaultMode = AnalysisMode::Standard;
    
    /// @brief Enable MITRE mapping
    bool enableMitreMapping = true;
    
    /// @brief Enable causal analysis
    bool enableCausalAnalysis = true;
    
    /// @brief Enable gap detection
    bool enableGapDetection = true;
    
    /// @brief Correlation window (milliseconds)
    uint32_t correlationWindowMs = TimelineConstants::CORRELATION_WINDOW_MS;
    
    /// @brief Maximum events to load
    size_t maxEvents = TimelineConstants::MAX_TIMELINE_EVENTS;
    
    /// @brief Cache directory
    std::wstring cacheDirectory;
    
    /// @brief Verbose logging
    bool verboseLogging = false;
    
    /**
     * @brief Validate configuration
     */
    [[nodiscard]] bool IsValid() const noexcept;
};

/**
 * @brief Timeline statistics
 */
struct TimelineStatistics {
    /// @brief Total events processed
    std::atomic<uint64_t> totalEvents{0};
    
    /// @brief Events by type
    std::array<std::atomic<uint64_t>, 64> eventsByType{};
    
    /// @brief Attack chains detected
    std::atomic<uint64_t> attackChainsDetected{0};
    
    /// @brief Causal links created
    std::atomic<uint64_t> causalLinksCreated{0};
    
    /// @brief Analyses performed
    std::atomic<uint64_t> analysesPerformed{0};
    
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

// ============================================================================
// CALLBACK TYPES
// ============================================================================

/// @brief Event callback
using EventCallback = std::function<void(const TimelineEvent&)>;

/// @brief Chain callback
using ChainCallback = std::function<void(const AttackChain&)>;

/// @brief Progress callback
using ProgressCallback = std::function<void(uint64_t processed, uint64_t total)>;

// ============================================================================
// TIMELINE ANALYZER CLASS
// ============================================================================

/**
 * @class TimelineAnalyzer
 * @brief Enterprise-grade attack timeline analysis engine
 *
 * Provides comprehensive timeline reconstruction and analysis capabilities
 * for forensic investigation of malicious activity sequences.
 *
 * THREAD SAFETY: All public methods are thread-safe.
 *
 * USAGE:
 * @code
 *     auto& analyzer = TimelineAnalyzer::Instance();
 *     
 *     // Build timeline for process
 *     auto timeline = analyzer.BuildAttackTimeline(suspiciousPid);
 *     
 *     // Analyze for attack chains
 *     auto result = analyzer.AnalyzeTimeline(timeline);
 * @endcode
 */
class TimelineAnalyzer final {
public:
    // ========================================================================
    // SINGLETON ACCESS
    // ========================================================================
    
    /**
     * @brief Get singleton instance
     */
    [[nodiscard]] static TimelineAnalyzer& Instance() noexcept;
    
    /**
     * @brief Check if instance exists
     */
    [[nodiscard]] static bool HasInstance() noexcept;
    
    // Non-copyable, non-movable
    TimelineAnalyzer(const TimelineAnalyzer&) = delete;
    TimelineAnalyzer& operator=(const TimelineAnalyzer&) = delete;
    TimelineAnalyzer(TimelineAnalyzer&&) = delete;
    TimelineAnalyzer& operator=(TimelineAnalyzer&&) = delete;

    // ========================================================================
    // LIFECYCLE MANAGEMENT
    // ========================================================================
    
    /**
     * @brief Initialize timeline analyzer
     */
    [[nodiscard]] bool Initialize(const TimelineAnalyzerConfiguration& config = {});
    
    /**
     * @brief Shutdown timeline analyzer
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
    // TIMELINE BUILDING
    // ========================================================================
    
    /**
     * @brief Build attack timeline for terminal PID
     */
    [[nodiscard]] std::vector<TimelinePoint> BuildAttackTimeline(uint32_t terminalPid);
    
    /**
     * @brief Build comprehensive timeline for PID
     */
    [[nodiscard]] std::vector<TimelineEvent> BuildTimeline(uint32_t pid);
    
    /**
     * @brief Build timeline for time range
     */
    [[nodiscard]] std::vector<TimelineEvent> BuildTimeline(
        FileTime startTime, FileTime endTime,
        const TimelineFilter& filter = {});
    
    /**
     * @brief Build timeline for incident
     */
    [[nodiscard]] std::vector<TimelineEvent> BuildTimeline(
        const std::string& incidentId);
    
    /**
     * @brief Add event to timeline
     */
    void AddEvent(const TimelineEvent& event);
    
    /**
     * @brief Add multiple events
     */
    void AddEvents(std::span<const TimelineEvent> events);
    
    /**
     * @brief Clear timeline
     */
    void ClearTimeline();
    
    // ========================================================================
    // TIMELINE ANALYSIS
    // ========================================================================
    
    /**
     * @brief Analyze timeline for attack patterns
     */
    [[nodiscard]] TimelineAnalysisResult AnalyzeTimeline(
        std::span<const TimelineEvent> events,
        AnalysisMode mode = AnalysisMode::Standard);
    
    /**
     * @brief Detect attack chains
     */
    [[nodiscard]] std::vector<AttackChain> DetectAttackChains(
        std::span<const TimelineEvent> events);
    
    /**
     * @brief Build causal graph
     */
    [[nodiscard]] std::vector<CausalLink> BuildCausalGraph(
        std::span<const TimelineEvent> events);
    
    /**
     * @brief Detect timeline gaps
     */
    [[nodiscard]] std::vector<TimelineGap> DetectGaps(
        std::span<const TimelineEvent> events,
        uint32_t thresholdSeconds = TimelineConstants::GAP_THRESHOLD_SECS);
    
    /**
     * @brief Map events to MITRE ATT&CK
     */
    [[nodiscard]] std::vector<AttackTechnique> MapToMitre(
        std::span<const TimelineEvent> events);
    
    // ========================================================================
    // PROCESS TREE ANALYSIS
    // ========================================================================
    
    /**
     * @brief Build process tree
     */
    [[nodiscard]] std::vector<ProcessNode> BuildProcessTree(uint32_t rootPid);
    
    /**
     * @brief Get process lineage (ancestors)
     */
    [[nodiscard]] std::vector<ProcessNode> GetProcessLineage(uint32_t pid);
    
    /**
     * @brief Get process descendants
     */
    [[nodiscard]] std::vector<ProcessNode> GetProcessDescendants(uint32_t pid);
    
    /**
     * @brief Find suspicious processes
     */
    [[nodiscard]] std::vector<ProcessNode> FindSuspiciousProcesses(
        std::span<const ProcessNode> tree);
    
    // ========================================================================
    // CORRELATION
    // ========================================================================
    
    /**
     * @brief Correlate events
     */
    [[nodiscard]] std::vector<std::pair<uint64_t, uint64_t>> CorrelateEvents(
        std::span<const TimelineEvent> events,
        uint32_t windowMs = TimelineConstants::CORRELATION_WINDOW_MS);
    
    /**
     * @brief Find related events
     */
    [[nodiscard]] std::vector<TimelineEvent> FindRelatedEvents(
        uint64_t eventId, std::span<const TimelineEvent> events);
    
    /**
     * @brief Find events by pattern
     */
    [[nodiscard]] std::vector<TimelineEvent> FindEventsByPattern(
        std::span<const TimelineEvent> events,
        const std::string& pattern);
    
    // ========================================================================
    // EXPORT
    // ========================================================================
    
    /**
     * @brief Export timeline to file
     */
    [[nodiscard]] bool ExportTimeline(std::span<const TimelineEvent> events,
                                      std::wstring_view outputPath,
                                      TimelineFormat format = TimelineFormat::JSON);
    
    /**
     * @brief Export process tree to GraphViz
     */
    [[nodiscard]] bool ExportProcessTree(std::span<const ProcessNode> tree,
                                         std::wstring_view outputPath);
    
    /**
     * @brief Export attack chain to STIX
     */
    [[nodiscard]] bool ExportToSTIX(const AttackChain& chain,
                                    std::wstring_view outputPath);
    
    /**
     * @brief Generate timeline report
     */
    [[nodiscard]] std::string GenerateReport(
        const TimelineAnalysisResult& result);
    
    // ========================================================================
    // CALLBACKS
    // ========================================================================
    
    /**
     * @brief Set event callback
     */
    void SetEventCallback(EventCallback callback);
    
    /**
     * @brief Set chain callback
     */
    void SetChainCallback(ChainCallback callback);
    
    /**
     * @brief Set progress callback
     */
    void SetProgressCallback(ProgressCallback callback);
    
    // ========================================================================
    // STATISTICS
    // ========================================================================
    
    /**
     * @brief Get statistics
     */
    [[nodiscard]] TimelineStatistics GetStatistics() const;
    
    /**
     * @brief Reset statistics
     */
    void ResetStatistics();
    
    // ========================================================================
    // UTILITY
    // ========================================================================
    
    /**
     * @brief Convert FILETIME to system time
     */
    [[nodiscard]] static SystemTimePoint FileTimeToSystemTime(FileTime ft) noexcept;
    
    /**
     * @brief Convert system time to FILETIME
     */
    [[nodiscard]] static FileTime SystemTimeToFileTime(SystemTimePoint st) noexcept;
    
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
    
    TimelineAnalyzer();
    ~TimelineAnalyzer();
    
    // ========================================================================
    // PIMPL
    // ========================================================================
    
    std::unique_ptr<TimelineAnalyzerImpl> m_impl;
    
    // ========================================================================
    // STATIC INSTANCE FLAG
    // ========================================================================
    
    static std::atomic<bool> s_instanceCreated;
};

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

/**
 * @brief Get event type name
 */
[[nodiscard]] std::string_view GetEventTypeName(TimelineEventType type) noexcept;

/**
 * @brief Get event type from string
 */
[[nodiscard]] TimelineEventType GetEventTypeFromString(std::string_view name) noexcept;

/**
 * @brief Get severity name
 */
[[nodiscard]] std::string_view GetSeverityName(EventSeverity severity) noexcept;

/**
 * @brief Get causal relation name
 */
[[nodiscard]] std::string_view GetCausalRelationName(CausalRelationType type) noexcept;

/**
 * @brief Get MITRE tactic name
 */
[[nodiscard]] std::string_view GetMitreTacticName(MitreTactic tactic) noexcept;

/**
 * @brief Get MITRE tactic ID
 */
[[nodiscard]] std::string_view GetMitreTacticId(MitreTactic tactic) noexcept;

/**
 * @brief Get timeline format name
 */
[[nodiscard]] std::string_view GetTimelineFormatName(TimelineFormat format) noexcept;

/**
 * @brief Get timeline format extension
 */
[[nodiscard]] std::wstring_view GetTimelineFormatExtension(TimelineFormat format) noexcept;

/**
 * @brief Get chain confidence name
 */
[[nodiscard]] std::string_view GetChainConfidenceName(ChainConfidence conf) noexcept;

/**
 * @brief Format FILETIME as string
 */
[[nodiscard]] std::string FormatFileTime(FileTime ft);

/**
 * @brief Parse FILETIME from string
 */
[[nodiscard]] std::optional<FileTime> ParseFileTime(std::string_view str);

}  // namespace Forensics
}  // namespace ShadowStrike

// ============================================================================
// MACROS
// ============================================================================

/**
 * @brief Build attack timeline for PID
 */
#define SS_BUILD_TIMELINE(pid) \
    ::ShadowStrike::Forensics::TimelineAnalyzer::Instance().BuildAttackTimeline(pid)

/**
 * @brief Add event to timeline
 */
#define SS_TIMELINE_ADD_EVENT(event) \
    ::ShadowStrike::Forensics::TimelineAnalyzer::Instance().AddEvent(event)
