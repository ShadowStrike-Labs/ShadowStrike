/**
 * ============================================================================
 * ShadowStrike Core Process - REFLECTIVE DLL DETECTOR (The Invisible Man)
 * ============================================================================
 *
 * @file ReflectiveDLLDetector.hpp
 * @brief Enterprise-grade detection of Reflective DLL Injection attacks.
 *
 * Reflective DLL Injection is an advanced code injection technique where a DLL
 * is loaded entirely from memory without using the standard Windows loader
 * (LoadLibrary). The technique was pioneered by Stephen Fewer and is now
 * commonly used by sophisticated malware and penetration testing frameworks.
 *
 * Key Characteristics:
 * - DLL is not registered in PEB's module list
 * - No file on disk (fileless execution)
 * - Custom PE loader implemented in the DLL itself
 * - Bootstrap code resolves imports manually
 * - Difficult to detect via standard module enumeration
 *
 * ============================================================================
 * REFLECTIVE INJECTION VARIANTS
 * ============================================================================
 *
 * | Variant                    | Detection Method                          |
 * |----------------------------|-------------------------------------------|
 * | Classic Reflective DLL     | PE headers in unbacked memory             |
 * | sRDI (shellcode RDI)       | Converted DLL to position-independent     |
 * | Cobalt Strike Beacon       | Malleable C2 profile patterns             |
 * | Metasploit Meterpreter     | Known loader signatures                   |
 * | PEzor / Donut              | Packed/encrypted PE detection             |
 * | Manual Mapping             | Section-by-section detection              |
 * | Module Overloading         | Module memory modification                |
 * | Transacted Hollowing       | TxF + reflective combination              |
 * | Memory Module              | MemoryModule library detection            |
 *
 * ============================================================================
 * DETECTION TECHNIQUES
 * ============================================================================
 *
 * 1. MEMORY SCANNING
 *    - MZ/PE headers in private memory regions
 *    - DOS/PE signature patterns in RWX memory
 *    - Section alignment anomalies
 *    - Export table in heap memory
 *
 * 2. PEB VALIDATION
 *    - Cross-reference loaded modules with PEB
 *    - Detect hidden (unlinked) modules
 *    - Find PE structures not in InLoadOrderModuleList
 *
 * 3. THREAD ANALYSIS
 *    - Thread start addresses in unbacked memory
 *    - Call stack analysis for unbacked frames
 *    - TLS callbacks in private memory
 *
 * 4. HEURISTIC DETECTION
 *    - RWX memory with PE characteristics
 *    - Entropy analysis (packed/encrypted regions)
 *    - Known reflective loader patterns
 *    - Import resolution behavior
 *
 * 5. BEHAVIORAL ANALYSIS
 *    - VirtualAlloc + WriteProcessMemory sequences
 *    - Manual GetProcAddress resolution patterns
 *    - Memory protection changes (RW->RX)
 *    - Suspicious memory allocation patterns
 *
 * ============================================================================
 * MITRE ATT&CK COVERAGE
 * ============================================================================
 *
 * | Technique ID | Technique Name              | Detection Method              |
 * |--------------|-----------------------------|-------------------------------|
 * | T1620        | Reflective Code Loading     | Core detection                |
 * | T1055.001    | DLL Injection               | Memory analysis               |
 * | T1055        | Process Injection           | Thread analysis               |
 * | T1027        | Obfuscated Files            | Entropy analysis              |
 * | T1140        | Deobfuscate/Decode          | Runtime unpacking detection   |
 * | T1106        | Native API                  | Syscall pattern detection     |
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
#include "MemoryScanner.hpp"
#include "ProcessMonitor.hpp"
#include "../../Utils/ProcessUtils.hpp"
#include "../../Utils/CryptoUtils.hpp"
#include "../../HashStore/HashStore.hpp"
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

class ReflectiveDLLDetectorImpl;

// ============================================================================
// CONSTANTS
// ============================================================================

namespace ReflectiveConstants {

    // Version information
    constexpr uint32_t VERSION_MAJOR = 4;
    constexpr uint32_t VERSION_MINOR = 0;
    constexpr uint32_t VERSION_PATCH = 0;

    // PE signatures
    constexpr uint16_t DOS_MAGIC = 0x5A4D;                    ///< MZ
    constexpr uint32_t PE_SIGNATURE = 0x00004550;             ///< PE\0\0
    constexpr uint16_t OPTIONAL_HEADER_MAGIC_32 = 0x10B;
    constexpr uint16_t OPTIONAL_HEADER_MAGIC_64 = 0x20B;

    // Scanning limits
    constexpr size_t MAX_MEMORY_REGIONS = 16384;
    constexpr size_t MAX_PE_CANDIDATES = 1024;
    constexpr size_t MIN_PE_SIZE = 4096;                      ///< Minimum valid PE
    constexpr size_t MAX_PE_HEADER_SCAN = 4096;
    constexpr size_t MAX_SECTION_SCAN = 1024 * 1024;          ///< 1MB per section
    constexpr uint32_t MAX_SECTIONS = 96;

    // Detection thresholds
    constexpr double HIGH_ENTROPY_THRESHOLD = 7.2;
    constexpr double PACKED_ENTROPY_THRESHOLD = 7.5;
    constexpr double ENCRYPTED_ENTROPY_THRESHOLD = 7.9;
    constexpr size_t MIN_EXPORT_TABLE_SIZE = 40;
    constexpr size_t MIN_IMPORT_TABLE_SIZE = 20;

    // Timeouts
    constexpr uint32_t SCAN_TIMEOUT_MS = 60000;
    constexpr uint32_t REGION_SCAN_TIMEOUT_MS = 5000;

    // Known reflective loader signatures (first bytes of common loaders)
    // These are simplified patterns - real implementation would have full YARA rules
    constexpr size_t MAX_LOADER_SIGNATURES = 64;
    constexpr size_t SIGNATURE_LENGTH = 32;

} // namespace ReflectiveConstants

// ============================================================================
// ENUMERATIONS
// ============================================================================

/**
 * @enum ReflectiveLoadType
 * @brief Type of reflective loading detected.
 */
enum class ReflectiveLoadType : uint8_t {
    Unknown = 0,
    ClassicReflective = 1,        ///< Stephen Fewer's original technique
    SRDI = 2,                     ///< Shellcode Reflective DLL Injection
    ManualMapping = 3,            ///< Manual PE mapping
    MemoryModule = 4,             ///< MemoryModule library
    CobaltStrikeBeacon = 5,       ///< Cobalt Strike
    MeterpreterStage = 6,         ///< Metasploit Meterpreter
    PELoader = 7,                 ///< Generic PE loader
    PackedReflective = 8,         ///< Packed/encrypted reflective
    ModuleOverloading = 9,        ///< Legitimate module overwritten
    DotNetAssembly = 10,          ///< Reflectively loaded .NET
    CustomLoader = 11             ///< Custom/unknown loader
};

/**
 * @enum DetectionConfidence
 * @brief Confidence level of detection.
 */
enum class DetectionConfidence : uint8_t {
    None = 0,
    Low = 1,              ///< Single weak indicator
    Medium = 2,           ///< Multiple indicators
    High = 3,             ///< Strong indicators
    Confirmed = 4         ///< Definitive evidence
};

/**
 * @enum PEValidationResult
 * @brief Result of PE structure validation.
 */
enum class PEValidationResult : uint8_t {
    Valid = 0,                    ///< Valid PE structure
    InvalidDosHeader = 1,
    InvalidPeSignature = 2,
    InvalidOptionalHeader = 3,
    InvalidSections = 4,
    TruncatedPE = 5,
    CorruptedHeaders = 6,
    SuspiciousCharacteristics = 7,
    Packed = 8,
    Encrypted = 9
};

/**
 * @enum MemoryCharacteristic
 * @brief Characteristics of suspicious memory region.
 */
enum class MemoryCharacteristic : uint8_t {
    None = 0,
    Executable = 1,
    Writable = 2,
    RWX = 3,
    Unbacked = 4,                 ///< Not backed by file
    HighEntropy = 5,
    ContainsPE = 6,
    ContainsCode = 7,
    HiddenFromPEB = 8,
    ModifiedProtection = 9,
    SuspiciousLocation = 10
};

/**
 * @enum ScanMode
 * @brief Scanning mode for reflective DLL detection.
 */
enum class ScanMode : uint8_t {
    Quick = 0,            ///< RWX regions only
    Standard = 1,         ///< All executable regions
    Deep = 2,             ///< Full memory scan
    Forensic = 3          ///< Complete analysis with extraction
};

// ============================================================================
// DATA STRUCTURES
// ============================================================================

/**
 * @struct PECandidate
 * @brief Potential PE structure found in memory.
 */
struct PECandidate {
    // Location
    uintptr_t baseAddress = 0;
    size_t regionSize = 0;
    uint32_t memoryProtection = 0;
    
    // PE Header info
    bool hasDosHeader = false;
    bool hasPeHeader = false;
    uint32_t peHeaderOffset = 0;
    bool is64Bit = false;
    
    // PE characteristics
    uint16_t machine = 0;
    uint16_t numberOfSections = 0;
    uint32_t timeDateStamp = 0;
    uint32_t characteristics = 0;
    uint32_t sizeOfImage = 0;
    uintptr_t entryPoint = 0;                 ///< RVA
    uintptr_t imageBase = 0;
    
    // Section info
    struct SectionInfo {
        std::array<char, 8> name{};
        uint32_t virtualAddress = 0;
        uint32_t virtualSize = 0;
        uint32_t rawSize = 0;
        uint32_t characteristics = 0;
        double entropy = 0.0;
    };
    std::vector<SectionInfo> sections;
    
    // Directory info
    bool hasExportTable = false;
    bool hasImportTable = false;
    bool hasRelocationTable = false;
    bool hasTLSDirectory = false;
    bool hasDebugDirectory = false;
    uint32_t exportCount = 0;
    uint32_t importCount = 0;
    
    // Validation
    PEValidationResult validationResult = PEValidationResult::Valid;
    bool isValidPE = false;
    std::wstring validationDetails;
    
    // Analysis
    double overallEntropy = 0.0;
    bool isPacked = false;
    bool isEncrypted = false;
    std::array<uint8_t, 32> sha256Hash{};
    
    // Detection context
    bool isInPEB = false;                     ///< Listed in process modules
    bool isFileBacked = false;                ///< Has file on disk
    std::wstring fileBackingPath;             ///< If file-backed
    bool matchesKnownLoader = false;
    std::wstring loaderName;
};

/**
 * @struct ReflectiveDetection
 * @brief Detection result for a reflectively loaded module.
 */
struct alignas(64) ReflectiveDetection {
    // Target process
    uint32_t processId = 0;
    std::wstring processName;
    std::wstring processPath;
    
    // Detection details
    PECandidate peCandidate;
    ReflectiveLoadType loadType = ReflectiveLoadType::Unknown;
    DetectionConfidence confidence = DetectionConfidence::None;
    std::chrono::system_clock::time_point detectionTime;
    
    // Memory characteristics
    std::vector<MemoryCharacteristic> characteristics;
    bool isRWX = false;
    bool isUnbacked = false;
    bool isHiddenFromPEB = false;
    
    // Thread analysis
    bool hasThreadStartingHere = false;
    uint32_t threadCount = 0;
    std::vector<uint32_t> associatedThreadIds;
    
    // Call stack analysis
    bool foundInCallStack = false;
    uint32_t callStackDepth = 0;
    
    // Known threat correlation
    bool correlatedWithKnownThreat = false;
    std::wstring threatName;
    std::string threatFamily;
    std::string mitreAttackId;
    
    // Risk assessment
    uint32_t riskScore = 0;                   ///< 0-100
    std::vector<std::wstring> riskFactors;
    
    // Extraction (if enabled)
    bool payloadExtracted = false;
    std::vector<uint8_t> extractedPayload;
    std::array<uint8_t, 32> payloadHash{};
    
    /**
     * @brief Calculate risk score from indicators.
     */
    void CalculateRiskScore() noexcept;
};

/**
 * @struct ScanResult
 * @brief Complete scan result for a process.
 */
struct ScanResult {
    uint32_t processId = 0;
    std::wstring processName;
    std::chrono::system_clock::time_point scanTime;
    ScanMode scanMode = ScanMode::Standard;
    
    // Scan statistics
    uint32_t regionsScanned = 0;
    uint32_t peCandidatesFound = 0;
    uint32_t reflectiveDLLsDetected = 0;
    
    // Detections
    std::vector<ReflectiveDetection> detections;
    
    // All PE candidates (including legitimate)
    std::vector<PECandidate> allPECandidates;
    
    // Summary
    bool hasReflectiveLoading = false;
    ReflectiveLoadType primaryThreatType = ReflectiveLoadType::Unknown;
    DetectionConfidence overallConfidence = DetectionConfidence::None;
    uint32_t highestRiskScore = 0;
    
    // Scan metadata
    uint32_t scanDurationMs = 0;
    bool scanComplete = false;
    std::wstring scanError;
};

/**
 * @struct LoaderSignature
 * @brief Signature for known reflective loader.
 */
struct LoaderSignature {
    std::string name;                         ///< Loader/tool name
    std::array<uint8_t, ReflectiveConstants::SIGNATURE_LENGTH> pattern{};
    std::array<uint8_t, ReflectiveConstants::SIGNATURE_LENGTH> mask{};
    uint32_t offset = 0;                      ///< Offset in PE
    ReflectiveLoadType type = ReflectiveLoadType::Unknown;
    std::string mitreId;
    std::wstring description;
};

/**
 * @struct ReflectiveConfig
 * @brief Configuration for the detector.
 */
struct ReflectiveConfig {
    // Scan settings
    ScanMode defaultScanMode = ScanMode::Standard;
    bool enableRealTimeMonitoring = true;
    bool enableOnDemandScanning = true;
    
    // Detection features
    bool scanRWXRegions = true;
    bool scanAllExecutableRegions = true;
    bool scanPrivateMemory = true;
    bool validatePEStructures = true;
    bool analyzeThreadStartAddresses = true;
    bool analyzeCallStacks = true;
    bool checkPEBConsistency = true;
    bool detectKnownLoaders = true;
    bool extractPayloads = false;             ///< Resource intensive
    
    // Sensitivity
    DetectionConfidence alertThreshold = DetectionConfidence::Medium;
    double entropyThreshold = ReflectiveConstants::HIGH_ENTROPY_THRESHOLD;
    bool alertOnHighEntropy = true;
    bool alertOnRWX = true;
    bool alertOnUnbackedPE = true;
    
    // Performance
    uint32_t scanTimeoutMs = ReflectiveConstants::SCAN_TIMEOUT_MS;
    size_t maxRegionsToScan = ReflectiveConstants::MAX_MEMORY_REGIONS;
    size_t maxPECandidates = ReflectiveConstants::MAX_PE_CANDIDATES;
    uint32_t maxConcurrentScans = 4;
    
    // Integration
    bool usePatternStore = true;
    bool useThreatIntel = true;
    bool useHashLookup = true;
    
    // Exclusions
    std::vector<std::wstring> excludedProcesses;
    std::vector<std::wstring> excludedPaths;
    
    /**
     * @brief Create default configuration.
     */
    static ReflectiveConfig CreateDefault() noexcept;
    
    /**
     * @brief Create high-sensitivity configuration.
     */
    static ReflectiveConfig CreateHighSensitivity() noexcept;
    
    /**
     * @brief Create performance-optimized configuration.
     */
    static ReflectiveConfig CreatePerformance() noexcept;
    
    /**
     * @brief Create forensic configuration (full extraction).
     */
    static ReflectiveConfig CreateForensic() noexcept;
};

/**
 * @struct ReflectiveStatistics
 * @brief Runtime statistics for the detector.
 */
struct alignas(64) ReflectiveStatistics {
    // Scan counts
    std::atomic<uint64_t> totalScans{0};
    std::atomic<uint64_t> quickScans{0};
    std::atomic<uint64_t> standardScans{0};
    std::atomic<uint64_t> deepScans{0};
    std::atomic<uint64_t> forensicScans{0};
    
    // Memory analysis
    std::atomic<uint64_t> regionsScanned{0};
    std::atomic<uint64_t> rwxRegionsFound{0};
    std::atomic<uint64_t> unbackedExecutableFound{0};
    std::atomic<uint64_t> peCandidatesAnalyzed{0};
    
    // Detection counts
    std::atomic<uint64_t> reflectiveDLLsDetected{0};
    std::atomic<uint64_t> classicReflectiveDetected{0};
    std::atomic<uint64_t> srdiDetected{0};
    std::atomic<uint64_t> cobaltStrikeDetected{0};
    std::atomic<uint64_t> meterpreterDetected{0};
    std::atomic<uint64_t> customLoadersDetected{0};
    
    // Confidence breakdown
    std::atomic<uint64_t> lowConfidenceDetections{0};
    std::atomic<uint64_t> mediumConfidenceDetections{0};
    std::atomic<uint64_t> highConfidenceDetections{0};
    std::atomic<uint64_t> confirmedDetections{0};
    
    // Extraction
    std::atomic<uint64_t> payloadsExtracted{0};
    std::atomic<uint64_t> extractionFailures{0};
    
    // Performance
    std::atomic<uint64_t> totalScanTimeMs{0};
    std::atomic<uint64_t> avgScanTimeMs{0};
    
    // Errors
    std::atomic<uint64_t> scanErrors{0};
    std::atomic<uint64_t> accessDeniedErrors{0};
    std::atomic<uint64_t> timeoutErrors{0};
    
    /**
     * @brief Reset all statistics.
     */
    void Reset() noexcept;
    
    /**
     * @brief Get detection rate.
     */
    [[nodiscard]] double GetDetectionRate() const noexcept;
};

// ============================================================================
// CALLBACK DEFINITIONS
// ============================================================================

/**
 * @brief Callback when reflective DLL is detected.
 * @param detection Detection details
 */
using ReflectiveDetectedCallback = std::function<void(
    const ReflectiveDetection& detection
)>;

/**
 * @brief Callback for scan progress.
 * @param pid Process ID
 * @param regionsScanned Regions scanned so far
 * @param totalRegions Total regions to scan
 */
using ScanProgressCallback = std::function<void(
    uint32_t pid,
    uint32_t regionsScanned,
    uint32_t totalRegions
)>;

/**
 * @brief Callback when PE candidate is found.
 * @param pid Process ID
 * @param candidate PE candidate information
 */
using PECandidateCallback = std::function<void(
    uint32_t pid,
    const PECandidate& candidate
)>;

// ============================================================================
// REFLECTIVE DLL DETECTOR CLASS
// ============================================================================

/**
 * @class ReflectiveDLLDetector
 * @brief Enterprise-grade reflective DLL injection detection engine.
 *
 * Thread-safety: All public methods are thread-safe.
 * Pattern: Singleton with PIMPL for ABI stability.
 *
 * Usage:
 * @code
 * auto& detector = ReflectiveDLLDetector::Instance();
 * 
 * // Scan specific process
 * auto result = detector.Scan(targetPid, ScanMode::Standard);
 * for (const auto& detection : result.detections) {
 *     std::wcout << L"Reflective DLL at 0x" << std::hex 
 *                << detection.peCandidate.baseAddress << std::endl;
 * }
 * 
 * // Enable real-time monitoring
 * detector.RegisterCallback([](const ReflectiveDetection& det) {
 *     // Handle detection...
 * });
 * detector.StartMonitoring();
 * @endcode
 */
class ReflectiveDLLDetector {
public:
    // ========================================================================
    // SINGLETON ACCESS
    // ========================================================================

    /**
     * @brief Get singleton instance.
     * @return Reference to the singleton instance.
     */
    [[nodiscard]] static ReflectiveDLLDetector& Instance();

    /**
     * @brief Delete copy constructor.
     */
    ReflectiveDLLDetector(const ReflectiveDLLDetector&) = delete;

    /**
     * @brief Delete copy assignment.
     */
    ReflectiveDLLDetector& operator=(const ReflectiveDLLDetector&) = delete;

    // ========================================================================
    // LIFECYCLE MANAGEMENT
    // ========================================================================

    /**
     * @brief Initialize the detector.
     * @param config Configuration settings.
     * @return True if initialization succeeded.
     */
    [[nodiscard]] bool Initialize(
        const ReflectiveConfig& config = ReflectiveConfig::CreateDefault()
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
    bool UpdateConfig(const ReflectiveConfig& config);

    /**
     * @brief Get current configuration.
     * @return Current configuration.
     */
    [[nodiscard]] ReflectiveConfig GetConfig() const;

    // ========================================================================
    // PROCESS SCANNING
    // ========================================================================

    /**
     * @brief Scan a process for reflective DLLs.
     * @param pid Process ID.
     * @param mode Scan mode.
     * @return Scan result.
     */
    [[nodiscard]] ScanResult Scan(
        uint32_t pid,
        ScanMode mode = ScanMode::Standard
    );

    /**
     * @brief Quick check if process has reflective DLLs.
     * @param pid Process ID.
     * @return True if reflective loading detected.
     */
    [[nodiscard]] bool HasReflectiveLoading(uint32_t pid);

    /**
     * @brief Scan multiple processes.
     * @param pids Process IDs.
     * @param mode Scan mode.
     * @return Scan results.
     */
    [[nodiscard]] std::vector<ScanResult> ScanMultiple(
        const std::vector<uint32_t>& pids,
        ScanMode mode = ScanMode::Standard
    );

    /**
     * @brief Scan all running processes.
     * @param mode Scan mode.
     * @return Scan results.
     */
    [[nodiscard]] std::vector<ScanResult> ScanAllProcesses(
        ScanMode mode = ScanMode::Quick
    );

    /**
     * @brief Scan processes by name.
     * @param processName Process name.
     * @param mode Scan mode.
     * @return Scan results.
     */
    [[nodiscard]] std::vector<ScanResult> ScanByName(
        const std::wstring& processName,
        ScanMode mode = ScanMode::Standard
    );

    // ========================================================================
    // MEMORY ANALYSIS
    // ========================================================================

    /**
     * @brief Scan process memory for PE structures.
     * @param pid Process ID.
     * @return Vector of PE candidates.
     */
    [[nodiscard]] std::vector<PECandidate> FindPECandidates(uint32_t pid);

    /**
     * @brief Validate a PE structure in memory.
     * @param pid Process ID.
     * @param baseAddress Base address of potential PE.
     * @return PE candidate with validation results.
     */
    [[nodiscard]] PECandidate ValidatePE(uint32_t pid, uintptr_t baseAddress);

    /**
     * @brief Check if a memory region contains PE structure.
     * @param pid Process ID.
     * @param address Memory address.
     * @param size Region size.
     * @return True if PE structure found.
     */
    [[nodiscard]] bool ContainsPE(
        uint32_t pid,
        uintptr_t address,
        size_t size
    );

    /**
     * @brief Find RWX (Read-Write-Execute) regions.
     * @param pid Process ID.
     * @return Vector of RWX region addresses and sizes.
     */
    [[nodiscard]] std::vector<std::pair<uintptr_t, size_t>> FindRWXRegions(
        uint32_t pid
    );

    /**
     * @brief Find unbacked executable memory.
     * @param pid Process ID.
     * @return Vector of unbacked executable regions.
     */
    [[nodiscard]] std::vector<std::pair<uintptr_t, size_t>> FindUnbackedExecutable(
        uint32_t pid
    );

    /**
     * @brief Calculate entropy of a memory region.
     * @param pid Process ID.
     * @param address Memory address.
     * @param size Region size.
     * @return Entropy value (0-8).
     */
    [[nodiscard]] double CalculateEntropy(
        uint32_t pid,
        uintptr_t address,
        size_t size
    );

    // ========================================================================
    // PEB ANALYSIS
    // ========================================================================

    /**
     * @brief Check PEB consistency (find hidden modules).
     * @param pid Process ID.
     * @return PE candidates not in PEB.
     */
    [[nodiscard]] std::vector<PECandidate> FindHiddenModules(uint32_t pid);

    /**
     * @brief Check if a PE is listed in PEB.
     * @param pid Process ID.
     * @param baseAddress PE base address.
     * @return True if in PEB module list.
     */
    [[nodiscard]] bool IsInPEB(uint32_t pid, uintptr_t baseAddress);

    /**
     * @brief Get all modules from PEB.
     * @param pid Process ID.
     * @return Module base addresses from PEB.
     */
    [[nodiscard]] std::vector<uintptr_t> GetPEBModules(uint32_t pid);

    // ========================================================================
    // THREAD ANALYSIS
    // ========================================================================

    /**
     * @brief Find threads with start addresses in suspicious memory.
     * @param pid Process ID.
     * @return Thread IDs and their start addresses.
     */
    [[nodiscard]] std::vector<std::pair<uint32_t, uintptr_t>> FindSuspiciousThreads(
        uint32_t pid
    );

    /**
     * @brief Check if thread start address is in unbacked memory.
     * @param tid Thread ID.
     * @return True if unbacked.
     */
    [[nodiscard]] bool IsThreadStartUnbacked(uint32_t tid);

    /**
     * @brief Analyze call stack for unbacked frames.
     * @param tid Thread ID.
     * @return Number of unbacked frames.
     */
    [[nodiscard]] uint32_t CountUnbackedCallStackFrames(uint32_t tid);

    // ========================================================================
    // LOADER DETECTION
    // ========================================================================

    /**
     * @brief Detect known reflective loader signatures.
     * @param pid Process ID.
     * @param candidate PE candidate to check.
     * @return Loader information if detected.
     */
    [[nodiscard]] std::optional<LoaderSignature> DetectKnownLoader(
        uint32_t pid,
        const PECandidate& candidate
    );

    /**
     * @brief Add custom loader signature.
     * @param signature Loader signature to add.
     */
    void AddLoaderSignature(const LoaderSignature& signature);

    /**
     * @brief Get all registered loader signatures.
     * @return Vector of signatures.
     */
    [[nodiscard]] std::vector<LoaderSignature> GetLoaderSignatures() const;

    // ========================================================================
    // PAYLOAD EXTRACTION
    // ========================================================================

    /**
     * @brief Extract reflective DLL from memory.
     * @param pid Process ID.
     * @param detection Detection to extract.
     * @return Extracted payload bytes.
     */
    [[nodiscard]] std::vector<uint8_t> ExtractPayload(
        uint32_t pid,
        const ReflectiveDetection& detection
    );

    /**
     * @brief Dump PE from memory to file.
     * @param pid Process ID.
     * @param baseAddress PE base address.
     * @param outputPath Output file path.
     * @return True if extraction succeeded.
     */
    bool DumpPE(
        uint32_t pid,
        uintptr_t baseAddress,
        const std::wstring& outputPath
    );

    /**
     * @brief Reconstruct PE from memory (fix headers).
     * @param pid Process ID.
     * @param baseAddress PE base address.
     * @return Reconstructed PE bytes.
     */
    [[nodiscard]] std::vector<uint8_t> ReconstructPE(
        uint32_t pid,
        uintptr_t baseAddress
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
     * @brief Notify of memory allocation (for monitoring).
     * @param pid Process ID.
     * @param address Allocated address.
     * @param size Allocation size.
     * @param protection Memory protection.
     */
    void OnMemoryAllocation(
        uint32_t pid,
        uintptr_t address,
        size_t size,
        uint32_t protection
    );

    /**
     * @brief Notify of memory protection change.
     * @param pid Process ID.
     * @param address Memory address.
     * @param oldProtection Old protection.
     * @param newProtection New protection.
     */
    void OnProtectionChange(
        uint32_t pid,
        uintptr_t address,
        uint32_t oldProtection,
        uint32_t newProtection
    );

    // ========================================================================
    // CALLBACK REGISTRATION
    // ========================================================================

    /**
     * @brief Register callback for detections.
     * @param callback Detection callback.
     * @return Callback ID.
     */
    uint64_t RegisterCallback(ReflectiveDetectedCallback callback);

    /**
     * @brief Register callback for scan progress.
     * @param callback Progress callback.
     * @return Callback ID.
     */
    uint64_t RegisterProgressCallback(ScanProgressCallback callback);

    /**
     * @brief Register callback for PE candidates.
     * @param callback Candidate callback.
     * @return Callback ID.
     */
    uint64_t RegisterCandidateCallback(PECandidateCallback callback);

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
    [[nodiscard]] ReflectiveStatistics GetStatistics() const;

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
     * @brief Convert load type to string.
     * @param type Load type.
     * @return String representation.
     */
    [[nodiscard]] static std::wstring LoadTypeToString(
        ReflectiveLoadType type
    ) noexcept;

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

    ReflectiveDLLDetector();
    ~ReflectiveDLLDetector();

    // ========================================================================
    // IMPLEMENTATION
    // ========================================================================

    std::unique_ptr<ReflectiveDLLDetectorImpl> m_impl;
};

} // namespace Process
} // namespace Core
} // namespace ShadowStrike
