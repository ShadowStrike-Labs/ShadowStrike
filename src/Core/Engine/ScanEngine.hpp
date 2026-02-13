/**
 * ============================================================================
 * ShadowStrike Core Engine - SCAN ENGINE (The Brain)
 * ============================================================================
 *
 * @file ScanEngine.hpp
 * @brief Central coordination engine for all scanning operations.
 *
 * This is the "Brain" of the ShadowStrike Antivirus. It serves as the unified
 * facade that orchestrates all underlying detection technologies into a coherent
 * decision-making pipeline. It is responsible for taking a target (file, process,
 * memory buffer) and determining its safety verdict by querying:
 *
 * 1. WhitelistStore (Immune System) - Is it known safe?
 * 2. HashStore (Memory) - Is it known malware?
 * 3. ThreatIntel (Reputation) - Is the source/hash suspicious?
 * 4. SignatureStore (Deep Analysis) - YARA rules, pattern matching.
 * 5. HeuristicAnalyzer (Logic) - Static analysis, entropy, anomaly detection.
 * 6. BehaviorAnalyzer (Dynamic) - Runtime behavior analysis.
 * 7. MachineLearning (AI) - Neural network classification.
 *
 * =============================================================================
 * ENTERPRISE CAPABILITIES
 * =============================================================================
 *
 * **Scanning Modes:**
 * - Single file scanning (sync/async)
 * - Batch file scanning (multi-threaded)
 * - Directory scanning (recursive with exclusions)
 * - Archive scanning (ZIP/RAR/7z/TAR/GZ/CAB/ISO)
 * - Memory scanning (process memory, kernel memory)
 * - Boot sector scanning (MBR/GPT/UEFI)
 * - Registry scanning (persistence detection)
 * - Network traffic scanning (inline packet inspection)
 *
 * **Scan Profiles:**
 * - Quick Scan (critical areas only)
 * - Full Scan (comprehensive system scan)
 * - Custom Scan (user-defined targets)
 * - Smart Scan (ML-driven adaptive scanning)
 *
 * **Performance Features:**
 * - Multi-threaded scanning with work stealing
 * - Priority-based scan queue
 * - I/O throttling for background scans
 * - Cache warming for frequently scanned files
 * - SIMD-optimized pattern matching
 *
 * **Enterprise Integration:**
 * - Scan job management with pause/resume/cancel
 * - Real-time progress callbacks
 * - Detection event callbacks
 * - Cloud sample submission
 * - Sandbox integration
 * - SIEM integration (JSON/CEF logging)
 *
 * **Advanced Features:**
 * - Rootkit detection (kernel-mode scanning)
 * - Bootkit detection (pre-OS scanning)
 * - Fileless malware detection
 * - Supply chain attack detection
 * - Zero-day exploit detection
 *
 * Architecture Position:
 * ----------------------
 *   ┌─────────────────────────────────────────────────────────────┐
 *   │                 Kernel / User Interface                      │
 *   └───────────┬──────────────────────────────────┬──────────────┘
 *               │ (File Event)                     │ (Scan Request)
 *               ▼                                  ▼
 *   ┌─────────────────────────────────────────────────────────────┐
 *   │                      SCAN ENGINE                             │ ◄── YOU ARE HERE
 *   │           (Orchestrator, Decision Maker, Logger)             │
 *   └──────────────────────────┬──────────────────────────────────┘
 *                              │
 *        ┌────────────┬────────┴────────┬─────────────┐
 *        ▼            ▼                 ▼             ▼
 *   ┌─────────┐  ┌─────────┐      ┌──────────┐  ┌────────────┐
 *   │Whitelist│  │HashStore│      │ThreatRep │  │Signatures  │
 *   └─────────┘  └─────────┘      └──────────┘  └────────────┘
 *
 * Pipeline Flow:
 * --------------
 * Target -> [PreScan: Whitelist] --(Safe)--> [Result: Clean]
 *                 │
 *                 ▼
 *           [FastScan: Hash] --(Match)--> [Result: Infected]
 *                 │
 *                 ▼
 *           [IntelScan: Reputation] --(Bad)--> [Result: Suspicious]
 *                 │
 *                 ▼
 *           [DeepScan: YARA/Patterns] --(Match)--> [Result: Infected]
 *                 │
 *                 ▼
 *           [HeuristicScan: Analysis] --(Score > Threshold)--> [Result: Suspicious]
 *                 │
 *                 ▼
 *           [BehaviorScan: Dynamic] --(Anomaly)--> [Result: Suspicious]
 *                 │
 *                 ▼
 *           [MLScan: Neural Net] --(Classification)--> [Result: Infected/Suspicious]
 *
 * Thread Safety:
 * --------------
 * This class is fully thread-safe. It is designed to be called concurrently
 * from multiple threads (e.g., Minifilter worker threads, UI scan threads).
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @copyright 2026 ShadowStrike Security Suite
 */

#pragma once

#include "../../SignatureStore/SignatureStore.hpp"
#include "../../Whitelist/WhiteListStore.hpp"
#include "../../ThreatIntel/ThreatIntelDatabase.hpp"
#include "../../Database/QuarantineDB.hpp"
#include "../../Database/LogDB.hpp"
#include "../../Database/ConfigurationDB.hpp"
#include "../../Utils/FileUtils.hpp"
#include "../../Utils/ProcessUtils.hpp"
#include "../../Utils/SystemUtils.hpp"
#include "../../Utils/ThreadPool.hpp"

// Standard Library
#include <string>
#include <string_view>
#include <vector>
#include <memory>
#include <atomic>
#include <shared_mutex>
#include <future>
#include <filesystem>
#include <span>
#include <optional>
#include <functional>
#include <chrono>
#include <set>

namespace ShadowStrike {
namespace Core {
namespace Engine {

// Forward declarations
class ScanJob;
struct ScanReport;
struct BatchScanResult;
struct DirectoryScanResult;

// ============================================================================
// SCAN TYPES & ENUMS
// ============================================================================

/**
 * @enum ScanType
 * @brief Defines the depth and intent of the scan.
 */
enum class ScanType : uint8_t {
    RealTime,       ///< Low latency, high priority (Kernel initiated)
    OnDemand,       ///< User initiated, deep scan
    Memory,         ///< Volatile memory scan
    Boot,           ///< Boot-time scan
    Contextual,     ///< "Right-click" scan
    Scheduled,      ///< Automated scheduled scan
    Cloud,          ///< Cloud-assisted deep scan
    Forensic        ///< Forensic analysis mode
};

/**
 * @enum ScanVerdict
 * @brief The final decision made by the engine.
 */
enum class ScanVerdict : uint8_t {
    Clean,          ///< No threats found
    Whitelisted,    ///< Explicitly allowed by policy/whitelist
    Infected,       ///< Confirmed malware signature match
    Suspicious,     ///< Heuristics/Reputation threshold exceeded
    PUA,            ///< Potentially Unwanted Application
    Adware,         ///< Adware detected
    Riskware,       ///< Legitimate but risky software
    Error,          ///< Scan failed (locked file, access denied)
    Timeout,        ///< Scan exceeded time limit
    Cancelled       ///< Scan was cancelled by user
};

/**
 * @enum ScanProfile
 * @brief Pre-configured scan profiles for different use cases.
 */
enum class ScanProfile : uint8_t {
    Quick,          ///< Critical areas only (memory, startup, temp)
    Full,           ///< Complete system scan
    Custom,         ///< User-defined targets
    Smart,          ///< ML-driven adaptive scan
    Rootkit,        ///< Deep rootkit/bootkit detection
    NetworkShare,   ///< Network share scanning
    RemovableMedia, ///< USB/CD/DVD scanning
    Cloud           ///< Cloud-assisted deep scan
};

/**
 * @enum ScanPriority
 * @brief Scan job priority for queue management.
 */
enum class ScanPriority : uint8_t {
    Critical = 0,   ///< Immediate execution (real-time scans)
    High = 1,       ///< High priority (user-initiated)
    Normal = 2,     ///< Normal priority (scheduled scans)
    Low = 3,        ///< Low priority (idle scans)
    Idle = 4        ///< Only run when system is idle
};

/**
 * @enum ScanJobState
 * @brief Current state of a scan job.
 */
enum class ScanJobState : uint8_t {
    Queued,         ///< Waiting in queue
    Running,        ///< Currently scanning
    Paused,         ///< Paused by user
    Completed,      ///< Scan completed successfully
    Failed,         ///< Scan failed with error
    Cancelled,      ///< Cancelled by user
    Timeout         ///< Exceeded time limit
};

/**
 * @enum ArchiveAction
 * @brief Action to take when scanning archives.
 */
enum class ArchiveAction : uint8_t {
    Skip,           ///< Don't scan archives
    Scan,           ///< Scan archive contents
    ScanIfSmall,    ///< Only scan archives < threshold
    Extract         ///< Extract and scan (slow but thorough)
};

// ============================================================================
// DATA STRUCTURES
// ============================================================================

/**
 * @struct ScanContext
 * @brief Carries metadata about the scan request through the pipeline.
 */
struct ScanContext {
    ScanType type = ScanType::OnDemand;
    ScanPriority priority = ScanPriority::Normal;

    uint32_t processId = 0;             ///< Process initiating the IO (for RealTime)
    std::wstring filePath;              ///< Target file path
    bool isNetworkPath = false;         ///< Is file on network share?
    bool isRemovableMedia = false;      ///< Is file on USB/CD/DVD?

    // Real-time constraints
    std::chrono::milliseconds timeout{ 5000 };
    bool stopOnFirstMatch = true;       ///< Performance optimization

    // Advanced context
    std::string userSid;                ///< User context
    std::wstring sessionInfo;           ///< Session information

    // Scan options
    bool scanArchives = true;
    bool scanPacked = true;
    bool deepScan = false;
    uint32_t maxNestingDepth = 10;      ///< For archives

    // Performance hints
    uint32_t maxThreads = 0;            ///< 0 = auto-detect
    bool useCache = true;
    bool submitToCloud = false;
};

/**
 * @struct EngineResult
 * @brief The unified result returned to the caller.
 */
struct EngineResult {
    ScanVerdict verdict = ScanVerdict::Clean;

    // Threat Details
    std::string threatName;             ///< e.g., "Worm.Win32.Stuxnet"
    std::string threatFamily;           ///< e.g., "Emotet"
    std::string threatCategory;         ///< e.g., "Trojan", "Ransomware"
    SignatureStore::ThreatLevel severity = SignatureStore::ThreatLevel::Info;
    uint64_t threatId = 0;
    std::string detectionSource;        ///< "HashStore", "YARA", "Heuristic", etc.

    // Confidence & Scoring
    float confidence = 0.0f;            ///< 0.0 - 100.0
    float threatScore = 0.0f;           ///< Composite threat score

    // Metadata
    uint64_t scanDurationUs = 0;        ///< Microseconds
    std::string sha256;                 ///< File hash (calculated during scan)
    std::string md5;                    ///< MD5 hash
    std::string fuzzyHash;               ///< Fuzzy hash

    // Detailed findings
    std::vector<std::string> detectionMethods;  ///< All methods that detected
    std::vector<std::string> matchedRules;      ///< YARA rules matched
    std::vector<std::string> suspiciousAPIs;    ///< Suspicious imports
    std::vector<std::string> indicators;        ///< IoCs found

    // MITRE ATT&CK mapping
    std::vector<std::string> mitreTactics;
    std::vector<std::string> mitreTechniques;

    // For Quarantine integration
    bool requiresReboot = false;
    bool canRemediate = true;
    std::wstring remediationAction;

    // Additional context
    std::wstring errorMessage;
    uint32_t errorCode = 0;
};

/**
 * @struct ExclusionRule
 * @brief Defines what to exclude from scanning.
 */
struct ExclusionRule {
    enum class Type : uint8_t {
        Path,           ///< Exact path match
        PathPrefix,     ///< Path prefix match
        Extension,      ///< File extension
        ProcessName,    ///< Process name
        Hash            ///< File hash
    };

    Type type = Type::Path;
    std::wstring pattern;
    bool enabled = true;
    std::string description;

    // Advanced
    bool caseSensitive = false;
    bool recursive = true;
};

/**
 * @struct ScanStatistics
 * @brief Detailed statistics about a scan operation.
 */
struct ScanStatistics {
    // Counts
    uint64_t filesScanned = 0;
    uint64_t filesInfected = 0;
    uint64_t filesSuspicious = 0;
    uint64_t filesCleaned = 0;
    uint64_t filesQuarantined = 0;
    uint64_t filesSkipped = 0;
    uint64_t filesErrors = 0;

    // Sizes
    uint64_t totalBytesScanned = 0;
    uint64_t infectedBytesFound = 0;

    // Timing
    std::chrono::milliseconds scanDuration{ 0 };
    std::chrono::milliseconds avgFileTimeMs{ 0 };

    // Pipeline statistics
    uint64_t whitelistHits = 0;
    uint64_t cacheHits = 0;
    uint64_t hashMatches = 0;
    uint64_t signatureMatches = 0;
    uint64_t heuristicDetections = 0;
    uint64_t mlDetections = 0;

    // Archives
    uint64_t archivesScanned = 0;
    uint64_t archiveFilesScanned = 0;
};

/**
 * @struct ScanProgress
 * @brief Real-time progress information.
 */
struct ScanProgress {
    uint64_t filesScanned = 0;
    uint64_t totalFiles = 0;            ///< 0 if unknown
    uint64_t bytesScanned = 0;
    uint64_t totalBytes = 0;            ///< 0 if unknown

    float percentComplete = 0.0f;       ///< 0.0 - 100.0
    std::wstring currentFile;
    std::chrono::milliseconds elapsed{ 0 };
    std::chrono::milliseconds estimatedRemaining{ 0 };

    // Throughput
    uint64_t filesPerSecond = 0;
    uint64_t bytesPerSecond = 0;
};

/**
 * @struct BatchScanRequest
 * @brief Request to scan multiple files.
 */
struct BatchScanRequest {
    std::vector<std::wstring> filePaths;
    ScanContext context;

    uint32_t maxConcurrency = 0;        ///< 0 = auto
    bool stopOnFirstInfection = false;
    bool generateReport = true;
};

/**
 * @struct BatchScanResult
 * @brief Result of batch scan operation.
 */
struct BatchScanResult {
    std::vector<EngineResult> results;
    ScanStatistics statistics;
    std::chrono::milliseconds totalDuration{ 0 };

    uint64_t filesScanned() const { return results.size(); }
    uint64_t threatsFound() const {
        return std::count_if(results.begin(), results.end(),
            [](const auto& r) { return r.verdict == ScanVerdict::Infected; });
    }
};

/**
 * @struct DirectoryScanRequest
 * @brief Request to scan a directory.
 */
struct DirectoryScanRequest {
    std::wstring rootPath;
    ScanContext context;

    bool recursive = true;
    uint32_t maxDepth = 100;

    std::vector<std::wstring> includeExtensions;  ///< Empty = all
    std::vector<std::wstring> excludeExtensions;
    std::vector<std::wstring> excludePaths;

    bool followSymlinks = false;
    bool scanHiddenFiles = true;
    bool scanSystemFiles = true;

    uint64_t maxFileSize = 0;           ///< 0 = unlimited
    uint32_t maxConcurrency = 0;        ///< 0 = auto
};

/**
 * @struct DirectoryScanResult
 * @brief Result of directory scan.
 */
struct DirectoryScanResult {
    std::vector<EngineResult> results;
    ScanStatistics statistics;
    std::chrono::milliseconds totalDuration{ 0 };

    std::wstring rootPath;
    uint64_t directoriesScanned = 0;
};

/**
 * @struct ArchiveScanOptions
 * @brief Options for scanning archives.
 */
struct ArchiveScanOptions {
    ArchiveAction action = ArchiveAction::Scan;

    uint64_t maxArchiveSize = 100 * 1024 * 1024;  ///< 100MB
    uint64_t maxExtractedSize = 500 * 1024 * 1024; ///< 500MB
    uint32_t maxNestingDepth = 5;
    uint32_t maxFilesInArchive = 10000;

    bool scanPasswordProtected = false;
    std::vector<std::string> passwords;  ///< Common passwords to try

    // Supported formats
    bool scanZip = true;
    bool scanRar = true;
    bool scan7z = true;
    bool scanTar = true;
    bool scanGz = true;
    bool scanCab = true;
    bool scanIso = true;
};

/**
 * @struct EngineConfig
 * @brief Configuration for the Scan Engine.
 */
struct EngineConfig {
    // Core scanning
    bool enableRealTime = true;
    bool enableHeuristics = true;
    bool enableBehaviorAnalysis = true;
    bool enableMachineLearning = true;
    bool enableCloudLookup = true;
    bool enableMemoryScanning = true;

    // Archive scanning
    ArchiveScanOptions archiveOptions;
    bool enableCompressedScanning = false; // Scan inside zips (slow)

    // Performance
    size_t maxFileSizeRealTime = 50 * 1024 * 1024; // 50MB limit for RT
    size_t maxFileSizeOnDemand = 500 * 1024 * 1024; // 500MB limit
    uint32_t sensitivityLevel = 2; // 1=Low, 2=Medium, 3=High (Paranoid)

    uint32_t maxConcurrentScans = 0;  ///< 0 = CPU count
    uint32_t scanThreads = 0;         ///< 0 = auto
    bool enableIOThrottling = false;
    uint32_t ioThrottleMBps = 100;

    // Caching
    bool enableResultCache = true;
    size_t resultCacheSize = 10000;
    std::chrono::minutes resultCacheTTL{ 15 };

    // Paths to databases
    std::wstring signatureDbPath;
    std::wstring whitelistDbPath;
    std::wstring threatIntelDbPath;

    // Exclusions
    std::vector<ExclusionRule> exclusions;

    // Timeouts
    std::chrono::milliseconds defaultTimeout{ 30000 };  // 30 seconds
    std::chrono::milliseconds maxScanTime{ 300000 };    // 5 minutes

    // Cloud integration
    bool submitUnknownSamples = false;
    std::string cloudApiEndpoint;
    std::string cloudApiKey;

    // Reporting
    bool generateDetailedReports = true;
    std::wstring reportPath;

    /**
     * @brief Create default configuration.
     */
    [[nodiscard]] static EngineConfig CreateDefault() noexcept {
        return EngineConfig{};
    }

    /**
     * @brief Create high-performance configuration.
     */
    [[nodiscard]] static EngineConfig CreateHighPerformance() noexcept {
        EngineConfig config;
        config.maxConcurrentScans = std::thread::hardware_concurrency() * 2;
        config.enableResultCache = true;
        config.resultCacheSize = 100000;
        config.enableIOThrottling = false;
        return config;
    }

    /**
     * @brief Create paranoid security configuration.
     */
    [[nodiscard]] static EngineConfig CreateParanoid() noexcept {
        EngineConfig config;
        config.sensitivityLevel = 3;
        config.enableHeuristics = true;
        config.enableBehaviorAnalysis = true;
        config.enableMachineLearning = true;
        config.enableCloudLookup = true;
        config.archiveOptions.action = ArchiveAction::Extract;
        config.archiveOptions.maxNestingDepth = 10;
        return config;
    }
};

// ============================================================================
// CALLBACK TYPES
// ============================================================================

using ScanProgressCallback = std::function<void(const ScanProgress&)>;
using DetectionCallback = std::function<void(const EngineResult&)>;
using ScanCompleteCallback = std::function<void(const ScanStatistics&)>;
using ErrorCallback = std::function<void(const std::wstring& error, uint32_t errorCode)>;

// ============================================================================
// SCAN ENGINE CLASS
// ============================================================================

/**
 * @class ScanEngine
 * @brief The primary interface for all scanning logic.
 *
 * Implementation follows the Singleton pattern to manage the lifecycle
 * of heavy database connections (SignatureStore, WhitelistStore).
 */
class ScanEngine {
public:
    // ========================================================================
    // LIFECYCLE
    // ========================================================================

    [[nodiscard]] static ScanEngine& Instance();

    /**
     * @brief Initialize the engine and connect to all subsystems.
     * @param config Configuration parameters.
     * @return True if all critical databases loaded successfully.
     */
    [[nodiscard]] bool Initialize(const EngineConfig& config);

    /**
     * @brief Gracefully shutdown and release database handles.
     */
    void Shutdown();

    [[nodiscard]] bool IsInitialized() const;

    // ========================================================================
    // SINGLE FILE SCANNING
    // ========================================================================

    /**
     * @brief Scan a file on disk (synchronous).
     * Used by Real-Time Protection (Minifilter) and On-Demand Scanner.
     *
     * @param filePath Full path to the file.
     * @param context Contextual information (PID, ScanType).
     * @return EngineResult containing the verdict.
     */
    [[nodiscard]] EngineResult ScanFile(
        const std::wstring& filePath,
        const ScanContext& context
    );

    /**
     * @brief Scan a file asynchronously.
     * @return Future that will contain the result.
     */
    [[nodiscard]] std::future<EngineResult> ScanFileAsync(
        const std::wstring& filePath,
        const ScanContext& context,
        ScanProgressCallback progressCallback = nullptr
    );

    /**
     * @brief Quick scan - optimized for speed over thoroughness.
     */
    [[nodiscard]] EngineResult QuickScanFile(
        const std::wstring& filePath
    );

    // ========================================================================
    // BATCH SCANNING
    // ========================================================================

    /**
     * @brief Scan multiple files (multi-threaded).
     * @param request Batch scan request with file list.
     * @return Batch scan result with all individual results.
     */
    [[nodiscard]] BatchScanResult ScanBatch(
        const BatchScanRequest& request,
        ScanProgressCallback progressCallback = nullptr
    );

    /**
     * @brief Scan multiple files asynchronously.
     */
    [[nodiscard]] std::future<BatchScanResult> ScanBatchAsync(
        const BatchScanRequest& request,
        ScanProgressCallback progressCallback = nullptr
    );

    // ========================================================================
    // DIRECTORY SCANNING
    // ========================================================================

    /**
     * @brief Scan a directory (recursive, multi-threaded).
     * @param request Directory scan request.
     * @return Directory scan result.
     */
    [[nodiscard]] DirectoryScanResult ScanDirectory(
        const DirectoryScanRequest& request,
        ScanProgressCallback progressCallback = nullptr
    );

    /**
     * @brief Scan a directory asynchronously.
     */
    [[nodiscard]] std::future<DirectoryScanResult> ScanDirectoryAsync(
        const DirectoryScanRequest& request,
        ScanProgressCallback progressCallback = nullptr
    );

    /**
     * @brief Quick scan of critical system areas.
     */
    [[nodiscard]] DirectoryScanResult QuickScan(
        ScanProgressCallback progressCallback = nullptr
    );

    /**
     * @brief Full system scan.
     */
    [[nodiscard]] DirectoryScanResult FullScan(
        ScanProgressCallback progressCallback = nullptr
    );

    /**
     * @brief Custom scan with user-defined targets.
     */
    [[nodiscard]] DirectoryScanResult CustomScan(
        const std::vector<std::wstring>& targets,
        ScanProgressCallback progressCallback = nullptr
    );

    // ========================================================================
    // MEMORY SCANNING
    // ========================================================================

    /**
     * @brief Scan a memory buffer.
     * Used for network packets, unpacked payloads, or process memory.
     *
     * @param buffer Pointer to data.
     * @param context Contextual information.
     * @return EngineResult containing the verdict.
     */
    [[nodiscard]] EngineResult ScanMemory(
        std::span<const uint8_t> buffer,
        const ScanContext& context
    );

    /**
     * @brief Scan a running process (Memory + Loaded Modules).
     *
     * @param pid Process ID.
     * @return EngineResult.
     */
    [[nodiscard]] EngineResult ScanProcess(
        uint32_t pid,
        const ScanContext& context
    );

    /**
     * @brief Scan all running processes.
     */
    [[nodiscard]] std::vector<EngineResult> ScanAllProcesses(
        ScanProgressCallback progressCallback = nullptr
    );

    /**
     * @brief Deep scan of process memory for fileless malware.
     */
    [[nodiscard]] EngineResult ScanProcessMemoryDeep(
        uint32_t pid,
        const ScanContext& context
    );

    // ========================================================================
    // ARCHIVE SCANNING
    // ========================================================================

    /**
     * @brief Scan an archive file (ZIP/RAR/7z/etc).
     * @param archivePath Path to archive.
     * @param options Archive scan options.
     * @return Scan result for archive and contents.
     */
    [[nodiscard]] BatchScanResult ScanArchive(
        const std::wstring& archivePath,
        const ArchiveScanOptions& options,
        const ScanContext& context
    );

    /**
     * @brief Check if file is a supported archive format.
     */
    [[nodiscard]] bool IsArchive(const std::wstring& filePath) const;

    /**
     * @brief Get list of supported archive formats.
     */
    [[nodiscard]] std::vector<std::wstring> GetSupportedArchiveFormats() const;

    // ========================================================================
    // BOOT & ROOTKIT SCANNING
    // ========================================================================

    /**
     * @brief Scan boot sectors (MBR/GPT).
     */
    [[nodiscard]] EngineResult ScanBootSector();

    /**
     * @brief Scan for rootkits (kernel-mode).
     */
    [[nodiscard]] std::vector<EngineResult> ScanForRootkits(
        ScanProgressCallback progressCallback = nullptr
    );

    /**
     * @brief Scan UEFI firmware.
     */
    [[nodiscard]] EngineResult ScanUEFI();

    // ========================================================================
    // SCAN JOB MANAGEMENT
    // ========================================================================

    /**
     * @brief Create a scan job (queued execution).
     * @return Job ID for tracking.
     */
    [[nodiscard]] uint64_t CreateScanJob(
        const DirectoryScanRequest& request,
        ScanPriority priority = ScanPriority::Normal
    );

    /**
     * @brief Get scan job status.
     */
    [[nodiscard]] ScanJobState GetJobState(uint64_t jobId) const;

    /**
     * @brief Get scan job progress.
     */
    [[nodiscard]] std::optional<ScanProgress> GetJobProgress(uint64_t jobId) const;

    /**
     * @brief Pause a running scan job.
     */
    bool PauseJob(uint64_t jobId);

    /**
     * @brief Resume a paused scan job.
     */
    bool ResumeJob(uint64_t jobId);

    /**
     * @brief Cancel a scan job.
     */
    bool CancelJob(uint64_t jobId);

    /**
     * @brief Get result of completed job.
     */
    [[nodiscard]] std::optional<DirectoryScanResult> GetJobResult(uint64_t jobId) const;

    /**
     * @brief Get list of all scan jobs.
     */
    [[nodiscard]] std::vector<uint64_t> GetActiveJobs() const;

    /**
     * @brief Cancel all running jobs.
     */
    void CancelAllJobs();

    // ========================================================================
    // EXCLUSION MANAGEMENT
    // ========================================================================

    /**
     * @brief Add exclusion rule.
     */
    void AddExclusion(const ExclusionRule& rule);

    /**
     * @brief Remove exclusion rule.
     */
    bool RemoveExclusion(size_t index);

    /**
     * @brief Get all exclusion rules.
     */
    [[nodiscard]] std::vector<ExclusionRule> GetExclusions() const;

    /**
     * @brief Clear all exclusions.
     */
    void ClearExclusions();

    /**
     * @brief Check if path is excluded.
     */
    [[nodiscard]] bool IsExcluded(const std::wstring& path) const;

    // ========================================================================
    // CALLBACKS
    // ========================================================================

    /**
     * @brief Register detection callback.
     * @return Callback ID for unregistration.
     */
    [[nodiscard]] uint64_t RegisterDetectionCallback(DetectionCallback callback);

    /**
     * @brief Unregister detection callback.
     */
    bool UnregisterDetectionCallback(uint64_t callbackId);

    /**
     * @brief Register scan complete callback.
     */
    [[nodiscard]] uint64_t RegisterCompleteCallback(ScanCompleteCallback callback);

    /**
     * @brief Unregister scan complete callback.
     */
    bool UnregisterCompleteCallback(uint64_t callbackId);

    /**
     * @brief Register error callback.
     */
    [[nodiscard]] uint64_t RegisterErrorCallback(ErrorCallback callback);

    /**
     * @brief Unregister error callback.
     */
    bool UnregisterErrorCallback(uint64_t callbackId);

    // ========================================================================
    // MANAGEMENT API
    // ========================================================================

    /**
     * @brief Reload databases (hot-reload) without stopping the engine.
     * Called when new signatures are downloaded.
     */
    bool ReloadDatabases();

    /**
     * @brief Update configuration at runtime.
     */
    void UpdateConfig(const EngineConfig& newConfig);

    /**
     * @brief Get current configuration.
     */
    [[nodiscard]] EngineConfig GetConfig() const;

    /**
     * @brief Warm up cache by pre-scanning common files.
     */
    void WarmCache(const std::vector<std::wstring>& commonPaths);

    /**
     * @brief Clear result cache.
     */
    void ClearCache();

    /**
     * @brief Optimize engine for current workload.
     */
    void OptimizeForWorkload(ScanProfile profile);

    // ========================================================================
    // STATISTICS & DIAGNOSTICS
    // ========================================================================

    /**
     * @brief Get internal statistics.
     */
    struct Stats {
        uint64_t totalScans;
        uint64_t infectionsFound;
        uint64_t cacheHits;
        uint64_t whitelistHits;
        double averageScanTimeMs;

        // Extended stats
        uint64_t hashHits;
        uint64_t signatureHits;
        uint64_t heuristicHits;
        uint64_t behaviorHits;
        uint64_t mlHits;

        // Pipeline timing
        double avgWhitelistTimeUs;
        double avgHashTimeUs;
        double avgSignatureTimeMs;
        double avgHeuristicTimeMs;

        // Throughput
        uint64_t filesPerSecond;
        uint64_t bytesPerSecond;
    };

    [[nodiscard]] Stats GetStatistics() const;

    /**
     * @brief Reset statistics counters.
     */
    void ResetStatistics();

    /**
     * @brief Get detailed performance metrics.
     */
    struct PerformanceMetrics {
        std::chrono::microseconds avgScanTime;
        std::chrono::microseconds p50ScanTime;
        std::chrono::microseconds p95ScanTime;
        std::chrono::microseconds p99ScanTime;

        uint64_t activeThreads;
        uint64_t queuedJobs;
        uint64_t completedJobs;

        size_t cacheSize;
        double cacheHitRate;

        uint64_t memoryUsageBytes;
        uint64_t peakMemoryBytes;
    };

    [[nodiscard]] PerformanceMetrics GetPerformanceMetrics() const;

    /**
     * @brief Run engine self-test.
     * @return True if all subsystems pass.
     */
    [[nodiscard]] bool SelfTest();

    /**
     * @brief Get engine version information.
     */
    struct VersionInfo {
        std::string engineVersion;
        std::string signatureVersion;
        std::string yaraVersion;
        std::chrono::system_clock::time_point lastUpdate;
    };

    [[nodiscard]] VersionInfo GetVersionInfo() const;

    // ========================================================================
    // CLOUD INTEGRATION
    // ========================================================================

    /**
     * @brief Submit sample to cloud for analysis.
     * @return Submission ID for tracking.
     */
    [[nodiscard]] std::string SubmitSampleToCloud(
        const std::wstring& filePath,
        const EngineResult& localResult
    );

    /**
     * @brief Check cloud analysis result.
     */
    [[nodiscard]] std::optional<EngineResult> GetCloudResult(
        const std::string& submissionId
    );

    /**
     * @brief Query cloud reputation for hash.
     */
    [[nodiscard]] std::optional<EngineResult> QueryCloudReputation(
        const std::string& hash
    );

    // ========================================================================
    // REPORTING
    // ========================================================================

    /**
     * @brief Generate scan report.
     */
    [[nodiscard]] std::wstring GenerateReport(
        const DirectoryScanResult& result,
        bool includeDetails = true
    );

    /**
     * @brief Export scan report to file (JSON/XML/HTML).
     */
    bool ExportReport(
        const DirectoryScanResult& result,
        const std::wstring& outputPath,
        const std::string& format = "JSON"  // JSON, XML, HTML
    );

private:
    ScanEngine();
    ~ScanEngine();

    // Delete copy/move
    ScanEngine(const ScanEngine&) = delete;
    ScanEngine& operator=(const ScanEngine&) = delete;

    // ========================================================================
    // INTERNAL IMPLEMENTATION (PIMPL)
    // ========================================================================

    class Impl;
    std::unique_ptr<Impl> m_impl;
};

} // namespace Engine
} // namespace Core
} // namespace ShadowStrike
