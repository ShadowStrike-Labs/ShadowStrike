/**
 * ============================================================================
 * ShadowStrike Core FileSystem - EXECUTABLE ANALYZER (The Deep Parser)
 * ============================================================================
 *
 * @file ExecutableAnalyzer.hpp
 * @brief Enterprise-grade PE/ELF/Mach-O binary analysis engine.
 *
 * This module provides comprehensive binary executable analysis for threat
 * detection, including PE header parsing, import/export analysis, signature
 * verification, and anomaly detection.
 *
 * Key Capabilities:
 * =================
 * 1. PE HEADER ANALYSIS
 *    - DOS/NT/Optional headers
 *    - Section characteristics
 *    - Data directories
 *    - Rich header
 *
 * 2. IMPORT/EXPORT ANALYSIS
 *    - IAT parsing
 *    - Delay-load imports
 *    - Forwarded exports
 *    - API categorization
 *
 * 3. RESOURCE ANALYSIS
 *    - Version info extraction
 *    - Embedded resources
 *    - Icon/manifest parsing
 *    - String table analysis
 *
 * 4. CODE SIGNING
 *    - Authenticode verification
 *    - Certificate chain validation
 *    - Catalog signing
 *    - Timestamp verification
 *
 * 5. ANOMALY DETECTION
 *    - Packers/crypters
 *    - Anti-analysis tricks
 *    - Suspicious characteristics
 *    - Section abnormalities
 *
 * PE Analysis Architecture:
 * =========================
 *   ┌─────────────────────────────────────────────────────────────────────┐
 *   │                       ExecutableAnalyzer                            │
 *   ├─────────────────────────────────────────────────────────────────────┤
 *   │  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────────┐  │
 *   │  │ HeaderParser │  │ImportAnalyzer│  │    ResourceExtractor     │  │
 *   │  │              │  │              │  │                          │  │
 *   │  │ - DOS/NT     │  │ - IAT        │  │ - Version                │  │
 *   │  │ - Sections   │  │ - API risk   │  │ - Manifest               │  │
 *   │  │ - Rich       │  │ - Delay      │  │ - Strings                │  │
 *   │  └──────────────┘  └──────────────┘  └──────────────────────────┘  │
 *   │                                                                     │
 *   │  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────────┐  │
 *   │  │SignatureVerif│  │ AnomalyDetect│  │    MetadataCollector     │  │
 *   │  │              │  │              │  │                          │  │
 *   │  │ - Authenticde│  │ - Packers    │  │ - Timestamps             │  │
 *   │  │ - Catalog    │  │ - Anti-debug │  │ - Entropy                │  │
 *   │  │ - Chain      │  │ - Sections   │  │ - Hashes                 │  │
 *   │  └──────────────┘  └──────────────┘  └──────────────────────────┘  │
 *   └─────────────────────────────────────────────────────────────────────┘
 *
 * Integration Points:
 * ===================
 * - HeuristicAnalyzer: Receives extracted features
 * - PatternStore: Pattern matching on code
 * - HashStore: Hash lookups
 * - ThreatIntel: Known malware signatures
 *
 * MITRE ATT&CK Coverage:
 * ======================
 * - T1027: Obfuscated Files (packers)
 * - T1036: Masquerading (spoofed metadata)
 * - T1055: Process Injection (suspicious imports)
 * - T1497: Virtualization/Sandbox Evasion
 *
 * Thread Safety:
 * ==============
 * - All public methods are thread-safe
 * - Concurrent analysis supported
 * - File access is read-only
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @date 2026
 * @copyright 2026 ShadowStrike Security Suite
 *
 * @see FileReputation.hpp for reputation checking
 * @see FileHasher.hpp for hash computation
 */

#pragma once

// ============================================================================
// INFRASTRUCTURE INCLUDES
// ============================================================================
#include "../../Utils/FileUtils.hpp"          // File operations, memory mapping
#include "../../Utils/CertUtils.hpp"          // Authenticode verification
#include "../../Utils/HashUtils.hpp"          // Hash computation
#include "../../Utils/PE_sig_verf.hpp"        // PE signature verification
#include "../../HashStore/HashStore.hpp"      // Known hash lookups
#include "../../PatternStore/PatternStore.hpp" // Pattern matching
#include "../../ThreatIntel/ThreatIntelLookup.hpp"  // Threat intelligence
#include "../../Whitelist/WhiteListStore.hpp" // Trusted executables

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
namespace FileSystem {

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================
class ExecutableAnalyzerImpl;  // PIMPL implementation

// ============================================================================
// NAMESPACE CONSTANTS
// ============================================================================
namespace ExecutableAnalyzerConstants {

    // Version
    constexpr uint32_t VERSION_MAJOR = 3;
    constexpr uint32_t VERSION_MINOR = 0;
    constexpr uint32_t VERSION_PATCH = 0;

    // PE Constants
    constexpr uint16_t DOS_SIGNATURE = 0x5A4D;       // MZ
    constexpr uint32_t NT_SIGNATURE = 0x00004550;    // PE\0\0
    constexpr uint16_t PE32_MAGIC = 0x10B;
    constexpr uint16_t PE64_MAGIC = 0x20B;

    // ELF Constants
    constexpr uint32_t ELF_MAGIC = 0x464C457F;       // \x7FELF

    // Limits
    constexpr size_t MAX_SECTIONS = 96;
    constexpr size_t MAX_IMPORTS = 10000;
    constexpr size_t MAX_EXPORTS = 50000;
    constexpr size_t MAX_RESOURCES = 1000;
    constexpr size_t MAX_FILE_SIZE = 500 * 1024 * 1024;  // 500 MB

    // Analysis thresholds
    constexpr double HIGH_ENTROPY_THRESHOLD = 7.2;
    constexpr double SUSPICIOUS_ENTROPY_THRESHOLD = 6.8;
    constexpr uint32_t SUSPICIOUS_SECTION_SIZE = 10 * 1024 * 1024;

}  // namespace ExecutableAnalyzerConstants

// ============================================================================
// ENUMERATIONS
// ============================================================================

/**
 * @enum ExecutableType
 * @brief Type of executable binary.
 */
enum class ExecutableType : uint8_t {
    Unknown = 0,
    PE32 = 1,                      // 32-bit Windows PE
    PE64 = 2,                      // 64-bit Windows PE
    ELF32 = 3,                     // 32-bit Linux ELF
    ELF64 = 4,                     // 64-bit Linux ELF
    MachO32 = 5,                   // 32-bit macOS
    MachO64 = 6,                   // 64-bit macOS
    MachOUniversal = 7,            // Universal binary
    MSDOS = 8,                     // DOS executable
    CLR = 9,                       // .NET assembly
    Script = 10                    // Script file (not binary)
};

/**
 * @enum SubsystemType
 * @brief Windows subsystem type.
 */
enum class SubsystemType : uint16_t {
    Unknown = 0,
    Native = 1,
    WindowsGUI = 2,
    WindowsCUI = 3,
    OS2CUI = 5,
    POSIXCUI = 7,
    NativeWindows = 8,
    WindowsCEGUI = 9,
    EFIApplication = 10,
    EFIBootServiceDriver = 11,
    EFIRuntimeDriver = 12,
    EFIROM = 13,
    XBOX = 14,
    WindowsBootApplication = 16
};

/**
 * @enum MachineType
 * @brief Target machine architecture.
 */
enum class MachineType : uint16_t {
    Unknown = 0x0000,
    I386 = 0x014C,
    AMD64 = 0x8664,
    ARM = 0x01C0,
    ARM64 = 0xAA64,
    IA64 = 0x0200,
    MIPS16 = 0x0266,
    MIPSFPU = 0x0366,
    MIPSFPU16 = 0x0466,
    POWERPC = 0x01F0,
    R4000 = 0x0166
};

/**
 * @enum SectionCharacteristics
 * @brief PE section characteristics.
 */
enum class SectionCharacteristics : uint32_t {
    None = 0,
    Code = 0x00000020,
    InitializedData = 0x00000040,
    UninitializedData = 0x00000080,
    MemoryDiscardable = 0x02000000,
    MemoryNotCached = 0x04000000,
    MemoryNotPaged = 0x08000000,
    MemoryShared = 0x10000000,
    MemoryExecute = 0x20000000,
    MemoryRead = 0x40000000,
    MemoryWrite = 0x80000000
};

/**
 * @enum SignatureStatus
 * @brief Code signing verification status.
 */
enum class SignatureStatus : uint8_t {
    NotSigned = 0,
    Valid = 1,
    Invalid = 2,
    Expired = 3,
    Revoked = 4,
    UntrustedRoot = 5,
    TimestampInvalid = 6,
    CatalogSigned = 7,
    HashMismatch = 8
};

/**
 * @enum PackerType
 * @brief Detected packer/crypter type.
 */
enum class PackerType : uint16_t {
    None = 0,
    UPX = 1,
    ASPack = 2,
    PECompact = 3,
    Themida = 4,
    VMProtect = 5,
    Armadillo = 6,
    Obsidium = 7,
    MPress = 8,
    PETITE = 9,
    NsPack = 10,
    FSG = 11,
    Morphine = 12,
    Enigma = 13,
    Custom = 100,
    Unknown = 255
};

/**
 * @enum ImportRiskLevel
 * @brief Risk level of imported API.
 */
enum class ImportRiskLevel : uint8_t {
    Safe = 0,
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4
};

/**
 * @enum AnomalyType
 * @brief Type of detected anomaly.
 */
enum class AnomalyType : uint16_t {
    None = 0,

    // Header anomalies
    InvalidDOSHeader = 1,
    InvalidNTHeader = 2,
    InvalidOptionalHeader = 3,
    SuspiciousChecksum = 4,
    InvalidTimestamp = 5,
    FutureTimestamp = 6,

    // Section anomalies
    ExecutableData = 10,
    WritableCode = 11,
    ZeroSizeSection = 12,
    OverlappingSections = 13,
    SectionOutsideFile = 14,
    HighEntropySections = 15,
    SuspiciousSectionNames = 16,
    TooManySections = 17,

    // Import anomalies
    NoImports = 20,
    SuspiciousImports = 21,
    APIHashing = 22,
    ImportForwarding = 23,

    // Export anomalies
    SuspiciousExports = 30,
    ExportForwarding = 31,

    // Resource anomalies
    HiddenExecutable = 40,
    EncryptedResources = 41,
    SuspiciousManifest = 42,

    // Signature anomalies
    InvalidSignature = 50,
    SpoofedSignature = 51,
    RevokedCertificate = 52,

    // Packing anomalies
    PackedBinary = 60,
    MultiLayerPacking = 61,
    CustomPacker = 62,
    AntiUnpacking = 63,

    // Anti-analysis
    AntiDebug = 70,
    AntiVM = 71,
    AntiSandbox = 72,
    ControlFlowObfuscation = 73,

    // Overlay
    LargeOverlay = 80,
    SuspiciousOverlay = 81
};

// ============================================================================
// DATA STRUCTURES
// ============================================================================

/**
 * @struct PESection
 * @brief PE section information.
 */
struct alignas(64) PESection {
    std::string name;
    std::string nameRaw;               // May contain nulls

    uint32_t virtualAddress{ 0 };
    uint32_t virtualSize{ 0 };
    uint32_t rawDataOffset{ 0 };
    uint32_t rawDataSize{ 0 };
    uint32_t characteristics{ 0 };

    // Analysis
    double entropy{ 0.0 };
    bool isExecutable{ false };
    bool isWritable{ false };
    bool isReadable{ false };
    bool isEmpty{ false };
    bool isPacked{ false };

    // Hashes
    std::array<uint8_t, 32> sha256{ 0 };
    std::string sha256Hex;
};

/**
 * @struct ImportedFunction
 * @brief Single imported function.
 */
struct alignas(32) ImportedFunction {
    std::string name;
    uint16_t ordinal{ 0 };
    bool byOrdinal{ false };
    uint64_t thunkRVA{ 0 };

    // Risk assessment
    ImportRiskLevel riskLevel{ ImportRiskLevel::Safe };
    std::string riskReason;
};

/**
 * @struct ImportedDLL
 * @brief Imported DLL information.
 */
struct alignas(64) ImportedDLL {
    std::string name;
    std::vector<ImportedFunction> functions;

    bool isDelayLoad{ false };
    bool isKnownSystem{ false };
    bool isSuspicious{ false };

    // Aggregated risk
    ImportRiskLevel highestRisk{ ImportRiskLevel::Safe };
    uint32_t criticalAPIs{ 0 };
    uint32_t highRiskAPIs{ 0 };
};

/**
 * @struct ExportedFunction
 * @brief Exported function information.
 */
struct alignas(32) ExportedFunction {
    std::string name;
    uint16_t ordinal{ 0 };
    uint32_t rva{ 0 };

    bool isForwarded{ false };
    std::string forwardedTo;

    bool isSuspicious{ false };
};

/**
 * @struct ResourceEntry
 * @brief PE resource information.
 */
struct alignas(64) ResourceEntry {
    uint32_t type{ 0 };
    std::string typeName;
    uint32_t id{ 0 };
    std::string name;
    uint32_t language{ 0 };

    uint32_t offset{ 0 };
    uint32_t size{ 0 };
    double entropy{ 0.0 };

    bool isPE{ false };
    bool isScript{ false };
    bool isEncrypted{ false };
};

/**
 * @struct VersionInfo
 * @brief File version information.
 */
struct alignas(128) VersionInfo {
    bool hasVersionInfo{ false };

    uint16_t fileMajor{ 0 };
    uint16_t fileMinor{ 0 };
    uint16_t fileBuild{ 0 };
    uint16_t fileRevision{ 0 };

    uint16_t productMajor{ 0 };
    uint16_t productMinor{ 0 };
    uint16_t productBuild{ 0 };
    uint16_t productRevision{ 0 };

    std::wstring companyName;
    std::wstring fileDescription;
    std::wstring fileVersion;
    std::wstring internalName;
    std::wstring legalCopyright;
    std::wstring originalFilename;
    std::wstring productName;
    std::wstring productVersion;
    std::wstring comments;
    std::wstring privateBuild;
    std::wstring specialBuild;
};

/**
 * @struct RichHeaderEntry
 * @brief Rich header entry (compiler info).
 */
struct alignas(16) RichHeaderEntry {
    uint16_t buildId{ 0 };
    uint16_t productId{ 0 };
    uint32_t count{ 0 };

    std::string productName;
};

/**
 * @struct RichHeader
 * @brief Rich header information.
 */
struct alignas(64) RichHeader {
    bool present{ false };
    bool valid{ false };
    uint32_t checksum{ 0 };
    std::vector<RichHeaderEntry> entries;

    std::string linkerVersion;
    bool isPossibleFake{ false };
};

/**
 * @struct SignatureInfo
 * @brief Code signing information.
 */
struct alignas(128) SignatureInfo {
    SignatureStatus status{ SignatureStatus::NotSigned };

    bool isSigned{ false };
    bool isValid{ false };
    bool isTrusted{ false };
    bool isMicrosoftSigned{ false };
    bool isCatalogSigned{ false };

    std::wstring signerName;
    std::wstring issuerName;
    std::wstring subjectName;
    std::wstring thumbprint;

    std::chrono::system_clock::time_point signatureTime;
    std::chrono::system_clock::time_point certValidFrom;
    std::chrono::system_clock::time_point certValidTo;

    std::vector<std::wstring> certificateChain;

    bool hasTimestamp{ false };
    std::wstring timestampSigner;
    std::chrono::system_clock::time_point timestampTime;
};

/**
 * @struct DotNetMetadata
 * @brief .NET CLR metadata.
 */
struct alignas(64) DotNetMetadata {
    bool isDotNet{ false };

    uint16_t majorRuntimeVersion{ 0 };
    uint16_t minorRuntimeVersion{ 0 };
    uint32_t flags{ 0 };

    std::string targetFramework;
    bool isNativeImage{ false };
    bool isMixedMode{ false };

    std::vector<std::string> assemblies;
    std::vector<std::string> typeNames;
};

/**
 * @struct DetectedAnomaly
 * @brief Detected binary anomaly.
 */
struct alignas(64) DetectedAnomaly {
    AnomalyType type{ AnomalyType::None };
    std::string description;
    std::string section;               // If section-specific
    uint32_t offset{ 0 };              // File offset
    uint8_t severity{ 0 };             // 0-100

    std::string mitreId;
};

/**
 * @struct PackerInfo
 * @brief Packer detection information.
 */
struct alignas(64) PackerInfo {
    bool isPacked{ false };
    PackerType type{ PackerType::None };
    std::string name;
    std::string version;

    double confidence{ 0.0 };
    std::vector<std::string> indicators;
};

/**
 * @struct ExecutableInfo
 * @brief Complete executable analysis result.
 */
struct alignas(256) ExecutableInfo {
    // Basic info
    bool isValid{ false };
    ExecutableType type{ ExecutableType::Unknown };
    MachineType machine{ MachineType::Unknown };
    SubsystemType subsystem{ SubsystemType::Unknown };

    bool is64Bit{ false };
    bool isDLL{ false };
    bool isDriver{ false };
    bool isConsole{ false };
    bool isGUI{ false };

    // Addresses
    uint64_t entryPoint{ 0 };
    uint64_t imageBase{ 0 };
    uint32_t imageSize{ 0 };

    // Headers
    uint32_t timestamp{ 0 };
    std::chrono::system_clock::time_point compilationTime;
    uint32_t checksum{ 0 };
    uint32_t calculatedChecksum{ 0 };
    bool checksumValid{ false };

    // DLL characteristics
    bool hasDEP{ false };
    bool hasASLR{ false };
    bool hasSEH{ false };
    bool hasCFG{ false };
    bool hasHighEntropyVA{ false };

    // Sections
    std::vector<PESection> sections;
    double averageEntropy{ 0.0 };
    double overallEntropy{ 0.0 };

    // Imports/Exports
    std::vector<ImportedDLL> imports;
    std::vector<ExportedFunction> exports;

    uint32_t totalImports{ 0 };
    uint32_t criticalImports{ 0 };
    uint32_t suspiciousImports{ 0 };

    // Resources
    std::vector<ResourceEntry> resources;
    VersionInfo versionInfo;

    // Rich header
    RichHeader richHeader;

    // Signature
    SignatureInfo signature;

    // .NET
    DotNetMetadata dotNet;

    // Packer detection
    PackerInfo packer;

    // Anomalies
    std::vector<DetectedAnomaly> anomalies;
    uint8_t riskScore{ 0 };            // 0-100

    // Hashes
    std::array<uint8_t, 16> md5{ 0 };
    std::array<uint8_t, 20> sha1{ 0 };
    std::array<uint8_t, 32> sha256{ 0 };
    std::string md5Hex;
    std::string sha1Hex;
    std::string sha256Hex;
    std::string imphash;
    std::string fuzzyHash;

    // File metadata
    uint64_t fileSize{ 0 };
    uint32_t overlayOffset{ 0 };
    uint32_t overlaySize{ 0 };

    std::chrono::system_clock::time_point analysisTime;
};

/**
 * @struct AnalysisOptions
 * @brief Options for executable analysis.
 */
struct alignas(32) AnalysisOptions {
    bool parseHeaders{ true };
    bool parseImports{ true };
    bool parseExports{ true };
    bool parseResources{ true };
    bool parseRichHeader{ true };
    bool parseSignature{ true };
    bool parseDotNet{ true };

    bool detectPackers{ true };
    bool detectAnomalies{ true };
    bool calculateHashes{ true };
    bool calculateEntropy{ true };

    bool extractStrings{ false };
    uint32_t minStringLength{ 4 };

    size_t maxResourceSize{ 10 * 1024 * 1024 };  // 10 MB

    static AnalysisOptions CreateFull() noexcept;
    static AnalysisOptions CreateQuick() noexcept;
    static AnalysisOptions CreateMinimal() noexcept;
};

/**
 * @struct ExecutableAnalyzerStatistics
 * @brief Runtime statistics.
 */
struct alignas(128) ExecutableAnalyzerStatistics {
    std::atomic<uint64_t> filesAnalyzed{ 0 };
    std::atomic<uint64_t> buffersAnalyzed{ 0 };
    std::atomic<uint64_t> pe32Files{ 0 };
    std::atomic<uint64_t> pe64Files{ 0 };
    std::atomic<uint64_t> dotNetFiles{ 0 };
    std::atomic<uint64_t> packedFiles{ 0 };
    std::atomic<uint64_t> signedFiles{ 0 };
    std::atomic<uint64_t> invalidFiles{ 0 };

    std::atomic<uint64_t> anomaliesDetected{ 0 };
    std::atomic<uint64_t> bytesProcessed{ 0 };
    std::atomic<uint64_t> averageAnalysisTimeUs{ 0 };

    void Reset() noexcept;
};

// ============================================================================
// MAIN CLASS DEFINITION
// ============================================================================

/**
 * @class ExecutableAnalyzer
 * @brief Enterprise-grade PE/ELF binary analysis engine.
 *
 * Thread Safety:
 * All public methods are thread-safe.
 *
 * Usage Example:
 * @code
 * auto& analyzer = ExecutableAnalyzer::Instance();
 * 
 * // Full analysis
 * auto info = analyzer.Analyze(L"C:\\suspicious.exe");
 * 
 * // Check results
 * if (info.packer.isPacked) {
 *     LOG_WARNING << "File is packed with: " << info.packer.name;
 * }
 * 
 * if (info.signature.status != SignatureStatus::Valid) {
 *     LOG_WARNING << "Invalid or missing signature";
 * }
 * 
 * for (const auto& anomaly : info.anomalies) {
 *     if (anomaly.severity >= 70) {
 *         LOG_ALERT << "High severity anomaly: " << anomaly.description;
 *     }
 * }
 * 
 * // Check risky imports
 * for (const auto& dll : info.imports) {
 *     for (const auto& func : dll.functions) {
 *         if (func.riskLevel == ImportRiskLevel::Critical) {
 *             LOG_WARNING << "Critical API: " << func.name;
 *         }
 *     }
 * }
 * @endcode
 */
class ExecutableAnalyzer {
public:
    // ========================================================================
    // SINGLETON ACCESS
    // ========================================================================

    static ExecutableAnalyzer& Instance();

    // ========================================================================
    // LIFECYCLE MANAGEMENT
    // ========================================================================

    /**
     * @brief Initializes the analyzer.
     * @return True if successful.
     */
    bool Initialize();

    /**
     * @brief Shuts down and releases resources.
     */
    void Shutdown() noexcept;

    // ========================================================================
    // FILE ANALYSIS
    // ========================================================================

    /**
     * @brief Analyzes file on disk.
     * @param filePath Path to file.
     * @param options Analysis options.
     * @return Executable information.
     */
    [[nodiscard]] ExecutableInfo Analyze(
        const std::wstring& filePath,
        const AnalysisOptions& options = AnalysisOptions::CreateFull());

    /**
     * @brief Analyzes memory buffer.
     * @param buffer Binary data.
     * @param options Analysis options.
     * @return Executable information.
     */
    [[nodiscard]] ExecutableInfo AnalyzeBuffer(
        std::span<const uint8_t> buffer,
        const AnalysisOptions& options = AnalysisOptions::CreateFull());

    /**
     * @brief Quick check if file is PE.
     * @param filePath Path to file.
     * @return True if valid PE.
     */
    [[nodiscard]] bool IsPE(const std::wstring& filePath) const;

    /**
     * @brief Quick check if buffer is PE.
     * @param buffer Binary data.
     * @return True if valid PE.
     */
    [[nodiscard]] bool IsPE(std::span<const uint8_t> buffer) const;

    /**
     * @brief Gets executable type from buffer.
     * @param buffer Binary data (first 4KB).
     * @return Executable type.
     */
    [[nodiscard]] ExecutableType GetExecutableType(std::span<const uint8_t> buffer) const;

    // ========================================================================
    // SPECIFIC ANALYSIS
    // ========================================================================

    /**
     * @brief Parses PE headers only.
     * @param filePath Path to file.
     * @return Partial info with headers.
     */
    [[nodiscard]] ExecutableInfo ParseHeaders(const std::wstring& filePath) const;

    /**
     * @brief Parses imports only.
     * @param filePath Path to file.
     * @return Vector of imported DLLs.
     */
    [[nodiscard]] std::vector<ImportedDLL> ParseImports(const std::wstring& filePath) const;

    /**
     * @brief Parses exports only.
     * @param filePath Path to file.
     * @return Vector of exports.
     */
    [[nodiscard]] std::vector<ExportedFunction> ParseExports(const std::wstring& filePath) const;

    /**
     * @brief Extracts resources.
     * @param filePath Path to file.
     * @return Vector of resources.
     */
    [[nodiscard]] std::vector<ResourceEntry> ExtractResources(const std::wstring& filePath) const;

    /**
     * @brief Extracts version info.
     * @param filePath Path to file.
     * @return Version information.
     */
    [[nodiscard]] VersionInfo GetVersionInfo(const std::wstring& filePath) const;

    /**
     * @brief Verifies code signature.
     * @param filePath Path to file.
     * @return Signature information.
     */
    [[nodiscard]] SignatureInfo VerifySignature(const std::wstring& filePath) const;

    // ========================================================================
    // DETECTION
    // ========================================================================

    /**
     * @brief Detects packers.
     * @param filePath Path to file.
     * @return Packer information.
     */
    [[nodiscard]] PackerInfo DetectPacker(const std::wstring& filePath) const;

    /**
     * @brief Detects anomalies.
     * @param info Previously analyzed info.
     * @return Vector of anomalies.
     */
    [[nodiscard]] std::vector<DetectedAnomaly> DetectAnomalies(const ExecutableInfo& info) const;

    /**
     * @brief Calculates risk score.
     * @param info Previously analyzed info.
     * @return Risk score 0-100.
     */
    [[nodiscard]] uint8_t CalculateRiskScore(const ExecutableInfo& info) const;

    // ========================================================================
    // HASH COMPUTATION
    // ========================================================================

    /**
     * @brief Computes ImpHash.
     * @param imports Import table.
     * @return Import hash.
     */
    [[nodiscard]] std::string ComputeImpHash(const std::vector<ImportedDLL>& imports) const;

    /**
     * @brief Computes section hashes.
     * @param filePath Path to file.
     * @return Map of section name to SHA256.
     */
    [[nodiscard]] std::unordered_map<std::string, std::string> ComputeSectionHashes(
        const std::wstring& filePath) const;

    // ========================================================================
    // STATISTICS
    // ========================================================================

    [[nodiscard]] const ExecutableAnalyzerStatistics& GetStatistics() const noexcept;
    void ResetStatistics() noexcept;

private:
    ExecutableAnalyzer();
    ~ExecutableAnalyzer();

    ExecutableAnalyzer(const ExecutableAnalyzer&) = delete;
    ExecutableAnalyzer& operator=(const ExecutableAnalyzer&) = delete;

    std::unique_ptr<ExecutableAnalyzerImpl> m_impl;
};

}  // namespace FileSystem
}  // namespace Core
}  // namespace ShadowStrike
