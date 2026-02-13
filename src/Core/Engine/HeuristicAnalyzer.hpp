/**
 * ============================================================================
 * ShadowStrike Core Engine - HEURISTIC ANALYZER (The Static Analyst)
 * ============================================================================
 *
 * @file HeuristicAnalyzer.hpp
 * @brief Enterprise-grade static analysis engine for detecting unknown threats.
 *
 * Unlike signature-based detection which looks for *known* patterns, the Heuristic
 * Analyzer examines *characteristics* and *anomalies* that indicate malicious intent.
 * This enables detection of zero-day malware and novel variants.
 *
 * =============================================================================
 * CORE CAPABILITIES
 * =============================================================================
 *
 * 1. **PE/ELF Structure Analysis**
 *    - Section analysis (entropy, permissions, sizes)
 *    - Header anomaly detection
 *    - Entry point analysis
 *    - Rich header analysis
 *    - Overlay detection
 *    - Resource analysis
 *
 * 2. **Entropy Analysis**
 *    - Shannon entropy per section
 *    - Chi-square distribution test
 *    - Encryption/packing detection
 *    - SIMD-optimized calculation
 *
 * 3. **Import Analysis**
 *    - Import hash (ImpHash) calculation
 *    - Suspicious API detection
 *    - API category scoring
 *    - Delayed import analysis
 *    - Bound import analysis
 *
 * 4. **Export Analysis**
 *    - Export name anomalies
 *    - Forward chain analysis
 *    - Ordinal-only exports
 *
 * 5. **Packer Detection**
 *    - 200+ packer signatures
 *    - Generic packer heuristics
 *    - Protector identification
 *    - Crypter detection
 *
 * 6. **Code Analysis**
 *    - Opcode frequency analysis
 *    - Code obfuscation detection
 *    - Anti-disassembly patterns
 *    - Shellcode detection
 *
 * 7. **String Analysis**
 *    - Suspicious string patterns
 *    - URL/IP extraction
 *    - Base64/encoded strings
 *    - Ransomware note patterns
 *
 * 8. **Certificate Analysis**
 *    - Authenticode validation
 *    - Certificate chain verification
 *    - Known stolen certificate detection
 *    - Self-signed detection
 *
 * 9. **Fuzzy Matching**
 *    - Fuzzy hash similarity
 *    - TLSH locality hashing
 *    - ImpHash matching
 *    - Section hash matching
 *
 * 10. **Script Analysis**
 *     - PowerShell analysis
 *     - VBScript analysis
 *     - JavaScript analysis
 *     - Batch/CMD analysis
 *     - Office macro analysis
 *
 * =============================================================================
 * ARCHITECTURE
 * =============================================================================
 *
 * ┌─────────────────────────────────────────────────────────────────────────┐
 * │                        HeuristicAnalyzer                                 │
 * ├─────────────────────────────────────────────────────────────────────────┤
 * │                                                                          │
 * │  ┌─────────────────────────────────────────────────────────────────┐   │
 * │  │                    File Type Detection                           │   │
 * │  │  ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌─────────┐             │   │
 * │  │  │   PE    │  │   ELF   │  │  Mach-O │  │ Scripts │             │   │
 * │  │  │ Parser  │  │ Parser  │  │ Parser  │  │ Parser  │             │   │
 * │  │  └────┬────┘  └────┬────┘  └────┬────┘  └────┬────┘             │   │
 * │  │       └────────────┴──────────────┴──────────────┘               │   │
 * │  └────────────────────────────────┬──────────────────────────────┘   │
 * │                                   ▼                                   │
 * │  ┌─────────────────────────────────────────────────────────────────┐   │
 * │  │                    Analysis Engines                              │   │
 * │  │                                                                   │   │
 * │  │  ┌─────────────────────────────────────────────────────────┐    │   │
 * │  │  │                  Structure Analysis                     │    │   │
 * │  │  │  - Header validation      - Section analysis            │    │   │
 * │  │  │  - Entry point check      - Overlay detection           │    │   │
 * │  │  │  - Resource analysis      - Debug info analysis         │    │   │
 * │  │  └─────────────────────────────────────────────────────────┘    │   │
 * │  │                                                                   │   │
 * │  │  ┌─────────────────────────────────────────────────────────┐    │   │
 * │  │  │                  Import/Export Analysis                 │    │   │
 * │  │  │  - ImpHash calculation    - API categorization          │    │   │
 * │  │  │  - Suspicious API detect  - Delayed import analysis     │    │   │
 * │  │  └─────────────────────────────────────────────────────────┘    │   │
 * │  │                                                                   │   │
 * │  │  ┌─────────────────────────────────────────────────────────┐    │   │
 * │  │  │                  Entropy Analysis                       │    │   │
 * │  │  │  - Shannon entropy        - Chi-square test             │    │   │
 * │  │  │  - Per-section entropy    - Packing detection           │    │   │
 * │  │  └─────────────────────────────────────────────────────────┘    │   │
 * │  │                                                                   │   │
 * │  │  ┌─────────────────────────────────────────────────────────┐    │   │
 * │  │  │                  Code Analysis                          │    │   │
 * │  │  │  - Opcode statistics      - Obfuscation detection       │    │   │
 * │  │  │  - Shellcode patterns     - Anti-analysis tricks        │    │   │
 * │  │  └─────────────────────────────────────────────────────────┘    │   │
 * │  │                                                                   │   │
 * │  │  ┌─────────────────────────────────────────────────────────┐    │   │
 * │  │  │                  String Analysis                        │    │   │
 * │  │  │  - Suspicious patterns    - URL extraction              │    │   │
 * │  │  │  - Encoded strings        - Ransom note detection       │    │   │
 * │  │  └─────────────────────────────────────────────────────────┘    │   │
 * │  │                                                                   │   │
 * │  └────────────────────────────────┬──────────────────────────────┘   │
 * │                                   ▼                                   │
 * │  ┌─────────────────────────────────────────────────────────────────┐   │
 * │  │                    Score Aggregation                             │   │
 * │  │  - Weighted indicator scoring                                    │   │
 * │  │  - Confidence calculation                                        │   │
 * │  │  - Category-based scoring                                        │   │
 * │  └────────────────────────────────┬──────────────────────────────┘   │
 * │                                   ▼                                   │
 * │  ┌─────────────────────────────────────────────────────────────────┐   │
 * │  │                    Fuzzy Matching (HashStore)                    │   │
 * │  │  - Fuzzy hash similarity                                             │   │
 * │  │  - TLSH matching                                                 │   │
 * │  │  - ImpHash correlation                                           │   │
 * │  └─────────────────────────────────────────────────────────────────┘   │
 * └─────────────────────────────────────────────────────────────────────────┘
 *
 * =============================================================================
 * INTEGRATION POINTS
 * =============================================================================
 *
 * - **HashStore**: CTPH/TLSH fuzzy matching, ImpHash database
 * - **SignatureStore**: YARA rules for packer detection
 * - **PatternStore**: String patterns, shellcode signatures
 * - **ThreatIntel**: Certificate reputation, known stolen certs
 * - **Utils::CryptoUtils**: Entropy calculation, hash computation
 * - **Utils::FileUtils**: File parsing, PE/ELF parsing
 *
 * =============================================================================
 * SCORING METHODOLOGY
 * =============================================================================
 *
 * | Category              | Weight | Max Score | Description                  |
 * |-----------------------|--------|-----------|------------------------------|
 * | PE Anomalies          | 2.0    | 30        | Header/structure issues      |
 * | High Entropy          | 1.5    | 20        | Packed/encrypted content     |
 * | Suspicious Imports    | 2.5    | 25        | Dangerous API usage          |
 * | Code Obfuscation      | 1.8    | 15        | Anti-analysis code           |
 * | String Indicators     | 1.2    | 15        | Malicious strings            |
 * | Certificate Issues    | 2.0    | 20        | Signing problems             |
 * | Packer Detection      | 1.5    | 15        | Known packer identified      |
 * | Fuzzy Match           | 3.0    | 40        | Similar to known malware     |
 *
 * Final Score = min(100, Σ(category_score * weight))
 *
 * @note Thread-safe for all public methods
 * @note SIMD-optimized entropy calculation
 *
 * @see HashStore for fuzzy matching
 * @see SignatureStore for YARA integration
 * @see PatternStore for string patterns
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @copyright (c) 2026 ShadowStrike Security Suite. All rights reserved.
 */

#pragma once

// ============================================================================
// INFRASTRUCTURE INCLUDES
// ============================================================================
#include "../../Utils/FileUtils.hpp"          // PE/ELF parsing
#include "../../Utils/HashUtils.hpp"          // ImpHash calculation
#include "../../Utils/StringUtils.hpp"        // String extraction
#include "../../HashStore/HashStore.hpp"      // CTPH/TLSH fuzzy matching
#include "../../PatternStore/PatternStore.hpp" // String/shellcode patterns
#include "../../SignatureStore/SignatureStore.hpp" // YARA rules
#include "../../ThreatIntel/ThreatIntelLookup.hpp"  // Cert reputation

// ============================================================================
// STANDARD LIBRARY INCLUDES
// ============================================================================
#include <atomic>
#include <array>
#include <bitset>
#include <chrono>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <set>
#include <shared_mutex>
#include <span>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <variant>
#include <vector>

#ifdef _WIN32
#  ifndef NOMINMAX
#    define NOMINMAX
#  endif
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include <Windows.h>
#endif

// Forward declarations
namespace ShadowStrike {
    namespace Utils {
        class ThreadPool;
    }
    namespace HashStore {
        class HashStore;
    }
    namespace SignatureStore {
        class SignatureStore;
    }
    namespace PatternStore {
        class PatternStore;
    }
    namespace ThreatIntel {
        class ThreatIntelIndex;
    }
}

namespace ShadowStrike {
namespace Core {
namespace Engine {

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

class HeuristicAnalyzer;
struct HeuristicResult;
struct PEAnalysis;
struct ELFAnalysis;
struct ScriptAnalysis;

// ============================================================================
// CONSTANTS
// ============================================================================

namespace HeuristicConstants {
    // -------------------------------------------------------------------------
    // Entropy Thresholds
    // -------------------------------------------------------------------------
    
    /// @brief High entropy threshold (likely packed/encrypted)
    constexpr double HIGH_ENTROPY_THRESHOLD = 7.0;
    
    /// @brief Very high entropy threshold (definitely encrypted)
    constexpr double VERY_HIGH_ENTROPY_THRESHOLD = 7.8;
    
    /// @brief Low entropy threshold (possibly data/resources)
    constexpr double LOW_ENTROPY_THRESHOLD = 1.0;
    
    /// @brief Maximum Shannon entropy (log2(256))
    constexpr double MAX_ENTROPY = 8.0;
    
    /// @brief Chi-square threshold for randomness
    constexpr double CHI_SQUARE_RANDOM_THRESHOLD = 293.25;  // p=0.01, df=255
    
    // -------------------------------------------------------------------------
    // Risk Score Thresholds
    // -------------------------------------------------------------------------
    
    /// @brief Clean threshold
    constexpr double CLEAN_THRESHOLD = 10.0;
    
    /// @brief Suspicious threshold
    constexpr double SUSPICIOUS_THRESHOLD = 30.0;
    
    /// @brief Likely malicious threshold
    constexpr double LIKELY_MALICIOUS_THRESHOLD = 50.0;
    
    /// @brief Malicious threshold
    constexpr double MALICIOUS_THRESHOLD = 70.0;
    
    /// @brief Confirmed malicious threshold
    constexpr double CONFIRMED_MALICIOUS_THRESHOLD = 90.0;
    
    /// @brief Maximum risk score
    constexpr double MAX_RISK_SCORE = 100.0;
    
    // -------------------------------------------------------------------------
    // Category Weights
    // -------------------------------------------------------------------------
    
    /// @brief PE anomaly weight
    constexpr double PE_ANOMALY_WEIGHT = 2.0;
    
    /// @brief Entropy weight
    constexpr double ENTROPY_WEIGHT = 1.5;
    
    /// @brief Import analysis weight
    constexpr double IMPORT_WEIGHT = 2.5;
    
    /// @brief Code obfuscation weight
    constexpr double OBFUSCATION_WEIGHT = 1.8;
    
    /// @brief String indicator weight
    constexpr double STRING_WEIGHT = 1.2;
    
    /// @brief Certificate weight
    constexpr double CERTIFICATE_WEIGHT = 2.0;
    
    /// @brief Packer detection weight
    constexpr double PACKER_WEIGHT = 1.5;
    
    /// @brief Fuzzy match weight
    constexpr double FUZZY_MATCH_WEIGHT = 3.0;
    
    // -------------------------------------------------------------------------
    // Category Max Scores
    // -------------------------------------------------------------------------
    
    /// @brief Max PE anomaly score
    constexpr double MAX_PE_ANOMALY_SCORE = 30.0;
    
    /// @brief Max entropy score
    constexpr double MAX_ENTROPY_SCORE = 20.0;
    
    /// @brief Max import score
    constexpr double MAX_IMPORT_SCORE = 25.0;
    
    /// @brief Max obfuscation score
    constexpr double MAX_OBFUSCATION_SCORE = 15.0;
    
    /// @brief Max string score
    constexpr double MAX_STRING_SCORE = 15.0;
    
    /// @brief Max certificate score
    constexpr double MAX_CERTIFICATE_SCORE = 20.0;
    
    /// @brief Max packer score
    constexpr double MAX_PACKER_SCORE = 15.0;
    
    /// @brief Max fuzzy match score
    constexpr double MAX_FUZZY_MATCH_SCORE = 40.0;
    
    // -------------------------------------------------------------------------
    // Fuzzy Matching
    // -------------------------------------------------------------------------
    
    /// @brief Fuzzy hash minimum similarity for match
    constexpr int FUZZY_MIN_SIMILARITY = 40;
    
    /// @brief TLSH maximum distance for match
    constexpr int TLSH_MAX_DISTANCE = 100;
    
    /// @brief High similarity threshold for fuzzy hash
    constexpr int FUZZY_HIGH_SIMILARITY = 80;
    
    // -------------------------------------------------------------------------
    // PE Analysis
    // -------------------------------------------------------------------------
    
    /// @brief Maximum sections for normal PE
    constexpr uint32_t MAX_NORMAL_SECTIONS = 10;
    
    /// @brief Maximum imports for normal PE
    constexpr uint32_t MAX_NORMAL_IMPORTS = 500;
    
    /// @brief Minimum image size
    constexpr uint64_t MIN_IMAGE_SIZE = 1024;
    
    /// @brief Maximum file to image size ratio
    constexpr double MAX_FILE_IMAGE_RATIO = 100.0;
    
    // -------------------------------------------------------------------------
    // Resource Limits
    // -------------------------------------------------------------------------
    
    /// @brief Maximum file size for full analysis
    constexpr uint64_t MAX_FILE_SIZE = 256 * 1024 * 1024;  // 256 MB
    
    /// @brief Maximum strings to extract
    constexpr size_t MAX_STRINGS = 10000;
    
    /// @brief Minimum string length
    constexpr size_t MIN_STRING_LENGTH = 6;
    
    /// @brief Maximum string length
    constexpr size_t MAX_STRING_LENGTH = 2048;
    
    /// @brief Analysis timeout (seconds)
    constexpr uint32_t ANALYSIS_TIMEOUT_SECONDS = 60;
}

// ============================================================================
// ENUMERATIONS
// ============================================================================

/**
 * @brief Type of file being analyzed.
 */
enum class FileType : uint8_t {
    Unknown = 0,
    PE32 = 1,
    PE64 = 2,
    ELF32 = 3,
    ELF64 = 4,
    MachO32 = 5,
    MachO64 = 6,
    MachOFat = 7,
    PDF = 8,
    Office = 9,         // DOC, DOCX, XLS, XLSX, PPT, PPTX
    RTF = 10,
    Script = 11,        // PS1, VBS, JS, BAT, CMD
    Archive = 12,       // ZIP, RAR, 7z
    JAR = 13,
    DEX = 14,           // Android
    APK = 15,
    MSI = 16,
    DLL = 17,
    SYS = 18,           // Driver
    LNK = 19,
    HTML = 20,
    XML = 21,
    ISO = 22,
    VHD = 23
};

/**
 * @brief Subsystem of PE file.
 */
enum class PESubsystem : uint16_t {
    Unknown = 0,
    Native = 1,
    WindowsGUI = 2,
    WindowsCUI = 3,
    OS2CUI = 5,
    PosixCUI = 7,
    NativeWindows = 8,
    WindowsCEGUI = 9,
    EFIApplication = 10,
    EFIBootDriver = 11,
    EFIRuntimeDriver = 12,
    EFIROM = 13,
    Xbox = 14,
    WindowsBootApp = 16
};

/**
 * @brief Type of packer/protector detected.
 */
enum class PackerType : uint16_t {
    None = 0,
    
    // -------------------------------------------------------------------------
    // Common Packers (1-49)
    // -------------------------------------------------------------------------
    UPX = 1,
    ASPack = 2,
    FSG = 3,
    PECompact = 4,
    MPRESS = 5,
    MEW = 6,
    NsPack = 7,
    Petite = 8,
    RLPack = 9,
    WinUpack = 10,
    
    // -------------------------------------------------------------------------
    // Commercial Protectors (50-99)
    // -------------------------------------------------------------------------
    Themida = 50,
    VMProtect = 51,
    Obsidium = 52,
    Enigma = 53,
    Armadillo = 54,
    ASProtect = 55,
    ExeCryptor = 56,
    EXECstealth = 57,
    MoleBox = 58,
    PELock = 59,
    
    // -------------------------------------------------------------------------
    // Crypters (100-149)
    // -------------------------------------------------------------------------
    CrypterGeneric = 100,
    XOR_Crypter = 101,
    AES_Crypter = 102,
    RC4_Crypter = 103,
    
    // -------------------------------------------------------------------------
    // Malware-Specific (150-199)
    // -------------------------------------------------------------------------
    MalwarePacker = 150,
    CustomPacker = 151,
    ConfuserEx = 152,
    SmartAssembly = 153,
    Dotfuscator = 154,
    
    // -------------------------------------------------------------------------
    // Installers/SFX (200-249)
    // -------------------------------------------------------------------------
    NSIS = 200,
    InnoSetup = 201,
    InstallShield = 202,
    WinRAR_SFX = 203,
    SevenZip_SFX = 204,
    AutoIt = 205,
    PyInstaller = 206,
    
    // -------------------------------------------------------------------------
    // .NET Obfuscators (250-299)
    // -------------------------------------------------------------------------
    DotNET_Obfuscator = 250,
    Agile_NET = 251,
    Babel_NET = 252,
    Crypto_Obfuscator = 253,
    
    /// @brief Generic/unknown packer
    Generic = 999
};

/**
 * @brief Category of suspicious API.
 */
enum class SuspiciousAPICategory : uint8_t {
    None = 0,
    
    /// @brief Process manipulation
    ProcessManipulation = 1,
    
    /// @brief Memory operations
    MemoryOperations = 2,
    
    /// @brief Code injection
    CodeInjection = 3,
    
    /// @brief Anti-debugging
    AntiDebug = 4,
    
    /// @brief Registry operations
    RegistryOperations = 5,
    
    /// @brief File operations
    FileOperations = 6,
    
    /// @brief Network operations
    NetworkOperations = 7,
    
    /// @brief Crypto operations
    CryptoOperations = 8,
    
    /// @brief Service operations
    ServiceOperations = 9,
    
    /// @brief Privilege escalation
    PrivilegeEscalation = 10,
    
    /// @brief Credential access
    CredentialAccess = 11,
    
    /// @brief Information gathering
    InfoGathering = 12,
    
    /// @brief Evasion techniques
    Evasion = 13,
    
    /// @brief Keylogging/Input capture
    InputCapture = 14,
    
    /// @brief Screen capture
    ScreenCapture = 15,
    
    /// @brief Clipboard access
    ClipboardAccess = 16,
    
    /// @brief WMI operations
    WMI = 17,
    
    /// @brief COM operations
    COM = 18,
    
    /// @brief Shell operations
    Shell = 19,
    
    /// @brief Dynamic code loading
    DynamicCode = 20
};

/**
 * @brief Severity of heuristic indicator.
 */
enum class IndicatorSeverity : uint8_t {
    Info = 0,
    Low = 25,
    Medium = 50,
    High = 75,
    Critical = 100
};

/**
 * @brief PE anomaly type.
 */
enum class PEAnomaly : uint16_t {
    None = 0,
    
    // -------------------------------------------------------------------------
    // Header Anomalies (1-49)
    // -------------------------------------------------------------------------
    
    /// @brief Invalid DOS signature
    InvalidDOSSignature = 1,
    
    /// @brief Invalid PE signature
    InvalidPESignature = 2,
    
    /// @brief Invalid optional header magic
    InvalidOptionalMagic = 3,
    
    /// @brief Invalid machine type
    InvalidMachine = 4,
    
    /// @brief Zero sections
    ZeroSections = 5,
    
    /// @brief Too many sections
    TooManySections = 6,
    
    /// @brief Invalid timestamp
    InvalidTimestamp = 7,
    
    /// @brief Future timestamp
    FutureTimestamp = 8,
    
    /// @brief Zeroed timestamp
    ZeroedTimestamp = 9,
    
    /// @brief Invalid entry point
    InvalidEntryPoint = 10,
    
    /// @brief Entry point in header
    EntryPointInHeader = 11,
    
    /// @brief Entry point in overlay
    EntryPointInOverlay = 12,
    
    /// @brief Entry point outside sections
    EntryPointOutsideSections = 13,
    
    /// @brief Invalid size of optional header
    InvalidOptionalHeaderSize = 14,
    
    /// @brief Zero image base
    ZeroImageBase = 15,
    
    /// @brief Invalid section alignment
    InvalidSectionAlignment = 16,
    
    /// @brief Invalid file alignment
    InvalidFileAlignment = 17,
    
    /// @brief Checksum mismatch
    ChecksumMismatch = 18,
    
    /// @brief Zero subsystem
    ZeroSubsystem = 19,
    
    /// @brief Invalid subsystem
    InvalidSubsystem = 20,
    
    // -------------------------------------------------------------------------
    // Section Anomalies (50-99)
    // -------------------------------------------------------------------------
    
    /// @brief Section name is empty
    EmptySectionName = 50,
    
    /// @brief Section name is non-ASCII
    NonASCIISectionName = 51,
    
    /// @brief Suspicious section name
    SuspiciousSectionName = 52,
    
    /// @brief UPX section detected
    UPXSection = 53,
    
    /// @brief Section is RWX (read/write/execute)
    RWXSection = 54,
    
    /// @brief Multiple RWX sections
    MultipleRWXSections = 55,
    
    /// @brief Section with zero raw size but non-zero virtual size
    ZeroRawSize = 56,
    
    /// @brief Virtual size much larger than raw size
    VirtualLargerThanRaw = 57,
    
    /// @brief Section overlaps header
    SectionOverlapsHeader = 58,
    
    /// @brief Sections overlap each other
    SectionsOverlap = 59,
    
    /// @brief Last section is executable
    LastSectionExecutable = 60,
    
    /// @brief Section at end of file
    SectionAtEOF = 61,
    
    // -------------------------------------------------------------------------
    // Resource Anomalies (100-149)
    // -------------------------------------------------------------------------
    
    /// @brief No resources
    NoResources = 100,
    
    /// @brief Invalid resource directory
    InvalidResourceDir = 101,
    
    /// @brief Resource with high entropy
    HighEntropyResource = 102,
    
    /// @brief Executable in resources
    ExecutableInResources = 103,
    
    /// @brief PE in resources
    PEInResources = 104,
    
    /// @brief Large icon resource (hiding data)
    LargeIconResource = 105,
    
    /// @brief Suspicious version info
    SuspiciousVersionInfo = 106,
    
    // -------------------------------------------------------------------------
    // Import/Export Anomalies (150-199)
    // -------------------------------------------------------------------------
    
    /// @brief No imports
    NoImports = 150,
    
    /// @brief Only kernel32.dll imports
    OnlyKernel32 = 151,
    
    /// @brief Dynamic import loading (LoadLibrary/GetProcAddress only)
    DynamicImportLoading = 152,
    
    /// @brief Suspicious import DLL
    SuspiciousImportDLL = 153,
    
    /// @brief Ordinal imports only
    OrdinalImportsOnly = 154,
    
    /// @brief Invalid import directory
    InvalidImportDir = 155,
    
    /// @brief No exports (for DLL)
    NoExportsForDLL = 156,
    
    /// @brief Invalid export directory
    InvalidExportDir = 157,
    
    /// @brief Export name mismatch
    ExportNameMismatch = 158,
    
    // -------------------------------------------------------------------------
    // Certificate/Signature Anomalies (200-249)
    // -------------------------------------------------------------------------
    
    /// @brief No signature
    NotSigned = 200,
    
    /// @brief Invalid signature
    InvalidSignature = 201,
    
    /// @brief Expired certificate
    ExpiredCertificate = 202,
    
    /// @brief Revoked certificate
    RevokedCertificate = 203,
    
    /// @brief Self-signed certificate
    SelfSigned = 204,
    
    /// @brief Known stolen certificate
    StolenCertificate = 205,
    
    /// @brief Certificate chain incomplete
    IncompleteChain = 206,
    
    /// @brief Weak hash algorithm
    WeakHashAlgorithm = 207,
    
    // -------------------------------------------------------------------------
    // Debug/Rich Header Anomalies (250-299)
    // -------------------------------------------------------------------------
    
    /// @brief Debug directory present
    DebugDirectory = 250,
    
    /// @brief PDB path present
    PDBPathPresent = 251,
    
    /// @brief Suspicious PDB path
    SuspiciousPDBPath = 252,
    
    /// @brief Rich header stripped
    RichHeaderStripped = 253,
    
    /// @brief Rich header tampered
    RichHeaderTampered = 254,
    
    // -------------------------------------------------------------------------
    // Overlay/Misc Anomalies (300-349)
    // -------------------------------------------------------------------------
    
    /// @brief Overlay detected
    HasOverlay = 300,
    
    /// @brief Large overlay
    LargeOverlay = 301,
    
    /// @brief Executable overlay
    ExecutableOverlay = 302,
    
    /// @brief .NET file but no CLR header
    DotNetMissingCLR = 303,
    
    /// @brief CLR header but not .NET
    CLRButNotDotNet = 304
};

/**
 * @brief String indicator type.
 */
enum class StringIndicatorType : uint8_t {
    None = 0,
    
    /// @brief URL pattern
    URL = 1,
    
    /// @brief IP address
    IPAddress = 2,
    
    /// @brief Domain name
    Domain = 3,
    
    /// @brief File path
    FilePath = 4,
    
    /// @brief Registry key
    RegistryKey = 5,
    
    /// @brief Base64 encoded
    Base64 = 6,
    
    /// @brief Hex encoded
    HexEncoded = 7,
    
    /// @brief Email address
    Email = 8,
    
    /// @brief Cryptocurrency address
    CryptoAddress = 9,
    
    /// @brief Ransom note phrase
    RansomNote = 10,
    
    /// @brief Suspicious API name
    SuspiciousAPI = 11,
    
    /// @brief Debug string
    DebugString = 12,
    
    /// @brief Error message
    ErrorMessage = 13,
    
    /// @brief Password/credential
    Credential = 14,
    
    /// @brief Command line
    CommandLine = 15,
    
    /// @brief Script content
    ScriptContent = 16,
    
    /// @brief SQL injection
    SQLInjection = 17,
    
    /// @brief Shell command
    ShellCommand = 18
};

/**
 * @brief Get string name for FileType.
 */
[[nodiscard]] constexpr const char* FileTypeToString(FileType type) noexcept;

/**
 * @brief Get string name for PackerType.
 */
[[nodiscard]] constexpr const char* PackerTypeToString(PackerType type) noexcept;

/**
 * @brief Get string name for PEAnomaly.
 */
[[nodiscard]] constexpr const char* PEAnomalyToString(PEAnomaly anomaly) noexcept;

// ============================================================================
// DATA STRUCTURES
// ============================================================================

/**
 * @brief Analysis of a PE/ELF section.
 */
struct SectionAnalysis {
    /// @brief Section name (may be empty)
    std::string name;
    
    /// @brief Section index
    uint16_t index = 0;
    
    /// @brief Virtual address
    uint64_t virtualAddress = 0;
    
    /// @brief Virtual size
    uint64_t virtualSize = 0;
    
    /// @brief Raw data offset
    uint64_t rawOffset = 0;
    
    /// @brief Raw data size
    uint64_t rawSize = 0;
    
    /// @brief Section characteristics/flags
    uint32_t characteristics = 0;
    
    /// @brief Shannon entropy (0.0 - 8.0)
    double entropy = 0.0;
    
    /// @brief Chi-square statistic
    double chiSquare = 0.0;
    
    /// @brief Is readable
    bool isReadable = false;
    
    /// @brief Is writable
    bool isWritable = false;
    
    /// @brief Is executable
    bool isExecutable = false;
    
    /// @brief Is code section
    bool isCode = false;
    
    /// @brief Is initialized data
    bool isInitializedData = false;
    
    /// @brief Is uninitialized data
    bool isUninitializedData = false;
    
    /// @brief Has high entropy
    bool hasHighEntropy = false;
    
    /// @brief Contains entry point
    bool containsEntryPoint = false;
    
    /// @brief Is empty section
    bool isEmpty = false;
    
    /// @brief MD5 hash of section content
    std::string md5;
    
    /// @brief SHA256 hash of section content
    std::string sha256;
    
    /**
     * @brief Check if section is RWX.
     */
    [[nodiscard]] bool IsRWX() const noexcept {
        return isReadable && isWritable && isExecutable;
    }
};

/**
 * @brief Imported function information.
 */
struct ImportedFunction {
    /// @brief DLL name
    std::string dllName;
    
    /// @brief Function name (empty if ordinal)
    std::string functionName;
    
    /// @brief Ordinal (0 if by name)
    uint16_t ordinal = 0;
    
    /// @brief Import by ordinal
    bool byOrdinal = false;
    
    /// @brief Suspicious API category
    SuspiciousAPICategory category = SuspiciousAPICategory::None;
    
    /// @brief Risk score contribution
    double riskScore = 0.0;
};

/**
 * @brief Import analysis results.
 */
struct ImportAnalysis {
    /// @brief Import hash (ImpHash)
    std::string impHash;
    
    /// @brief Number of imported DLLs
    uint32_t dllCount = 0;
    
    /// @brief Total imported functions
    uint32_t functionCount = 0;
    
    /// @brief Ordinal imports count
    uint32_t ordinalCount = 0;
    
    /// @brief Suspicious imports count
    uint32_t suspiciousCount = 0;
    
    /// @brief All imported functions
    std::vector<ImportedFunction> functions;
    
    /// @brief Suspicious functions only
    std::vector<ImportedFunction> suspiciousFunctions;
    
    /// @brief Risk score from imports
    double riskScore = 0.0;
    
    /// @brief Has dynamic loading pattern (LoadLibrary/GetProcAddress)
    bool hasDynamicLoading = false;
    
    /// @brief Has no imports (suspicious)
    bool hasNoImports = false;
    
    /// @brief API categories detected
    std::set<SuspiciousAPICategory> detectedCategories;
};

/**
 * @brief Exported function information.
 */
struct ExportedFunction {
    /// @brief Function name
    std::string name;
    
    /// @brief Ordinal
    uint16_t ordinal = 0;
    
    /// @brief RVA
    uint32_t rva = 0;
    
    /// @brief Is forwarded
    bool isForwarded = false;
    
    /// @brief Forward target
    std::string forwardTarget;
};

/**
 * @brief Export analysis results.
 */
struct ExportAnalysis {
    /// @brief DLL name
    std::string dllName;
    
    /// @brief Number of exports
    uint32_t exportCount = 0;
    
    /// @brief Number of forwarded exports
    uint32_t forwardedCount = 0;
    
    /// @brief All exported functions
    std::vector<ExportedFunction> functions;
    
    /// @brief Has suspicious export names
    bool hasSuspiciousNames = false;
    
    /// @brief Has ordinal-only exports
    bool hasOrdinalOnlyExports = false;
};

/**
 * @brief Resource entry.
 */
struct ResourceEntry {
    /// @brief Resource type
    uint32_t type = 0;
    
    /// @brief Resource type name
    std::string typeName;
    
    /// @brief Resource name
    std::string name;
    
    /// @brief Language ID
    uint32_t languageId = 0;
    
    /// @brief Offset
    uint64_t offset = 0;
    
    /// @brief Size
    uint64_t size = 0;
    
    /// @brief Entropy
    double entropy = 0.0;
    
    /// @brief Is executable
    bool isExecutable = false;
    
    /// @brief Contains PE
    bool containsPE = false;
    
    /// @brief MD5 hash
    std::string md5;
};

/**
 * @brief Resource analysis results.
 */
struct ResourceAnalysis {
    /// @brief Total resources
    uint32_t totalResources = 0;
    
    /// @brief Total resource size
    uint64_t totalSize = 0;
    
    /// @brief Resources with high entropy
    uint32_t highEntropyCount = 0;
    
    /// @brief Embedded executables count
    uint32_t embeddedExecutables = 0;
    
    /// @brief Resource entries
    std::vector<ResourceEntry> entries;
    
    /// @brief Version info (if present)
    std::map<std::wstring, std::wstring> versionInfo;
    
    /// @brief Company name from version
    std::wstring companyName;
    
    /// @brief Product name from version
    std::wstring productName;
    
    /// @brief Original filename from version
    std::wstring originalFilename;
    
    /// @brief Internal name from version
    std::wstring internalName;
    
    /// @brief File version
    std::wstring fileVersion;
    
    /// @brief Product version
    std::wstring productVersion;
    
    /// @brief File description
    std::wstring fileDescription;
    
    /// @brief Legal copyright
    std::wstring legalCopyright;
};

/**
 * @brief Certificate/signature information.
 */
struct CertificateInfo {
    /// @brief Is file signed
    bool isSigned = false;
    
    /// @brief Is signature valid
    bool isSignatureValid = false;
    
    /// @brief Is certificate valid
    bool isCertificateValid = false;
    
    /// @brief Is self-signed
    bool isSelfSigned = false;
    
    /// @brief Is certificate expired
    bool isExpired = false;
    
    /// @brief Is certificate revoked
    bool isRevoked = false;
    
    /// @brief Is countersigned (timestamped)
    bool isCountersigned = false;
    
    /// @brief Is known stolen certificate
    bool isKnownStolen = false;
    
    /// @brief Is certificate chain complete
    bool isChainComplete = false;
    
    /// @brief Subject name
    std::wstring subjectName;
    
    /// @brief Issuer name
    std::wstring issuerName;
    
    /// @brief Serial number
    std::string serialNumber;
    
    /// @brief Thumbprint (SHA1)
    std::string thumbprint;
    
    /// @brief Signature algorithm
    std::string signatureAlgorithm;
    
    /// @brief Digest algorithm
    std::string digestAlgorithm;
    
    /// @brief Not before
    std::chrono::system_clock::time_point notBefore{};
    
    /// @brief Not after
    std::chrono::system_clock::time_point notAfter{};
    
    /// @brief Timestamp (if countersigned)
    std::chrono::system_clock::time_point timestamp{};
    
    /// @brief Certificate chain
    std::vector<std::wstring> certificateChain;
    
    /// @brief Risk score contribution
    double riskScore = 0.0;
};

/**
 * @brief Extracted string with analysis.
 */
struct ExtractedString {
    /// @brief String value
    std::string value;
    
    /// @brief Offset in file
    uint64_t offset = 0;
    
    /// @brief Is Unicode
    bool isUnicode = false;
    
    /// @brief Indicator type
    StringIndicatorType indicatorType = StringIndicatorType::None;
    
    /// @brief Risk score contribution
    double riskScore = 0.0;
    
    /// @brief Additional context
    std::string context;
};

/**
 * @brief String analysis results.
 */
struct StringAnalysis {
    /// @brief Total strings extracted
    uint32_t totalStrings = 0;
    
    /// @brief ASCII strings count
    uint32_t asciiCount = 0;
    
    /// @brief Unicode strings count
    uint32_t unicodeCount = 0;
    
    /// @brief Suspicious strings count
    uint32_t suspiciousCount = 0;
    
    /// @brief URLs found
    std::vector<std::string> urls;
    
    /// @brief IP addresses found
    std::vector<std::string> ipAddresses;
    
    /// @brief Domains found
    std::vector<std::string> domains;
    
    /// @brief Registry paths found
    std::vector<std::string> registryPaths;
    
    /// @brief File paths found
    std::vector<std::wstring> filePaths;
    
    /// @brief Suspicious API names
    std::vector<std::string> suspiciousAPIs;
    
    /// @brief All extracted strings with indicators
    std::vector<ExtractedString> indicatorStrings;
    
    /// @brief Risk score from strings
    double riskScore = 0.0;
    
    /// @brief Has ransom note patterns
    bool hasRansomNotePatterns = false;
    
    /// @brief Has cryptocurrency addresses
    bool hasCryptoAddresses = false;
    
    /// @brief Has encoded payloads
    bool hasEncodedPayloads = false;
};

/**
 * @brief Code analysis results.
 */
struct CodeAnalysis {
    /// @brief Total code size
    uint64_t codeSize = 0;
    
    /// @brief Estimated instruction count
    uint64_t instructionCount = 0;
    
    /// @brief Opcode frequency distribution
    std::array<uint32_t, 256> opcodeFrequency{};
    
    /// @brief Has anti-disassembly patterns
    bool hasAntiDisassembly = false;
    
    /// @brief Has code obfuscation
    bool hasObfuscation = false;
    
    /// @brief Has shellcode patterns
    bool hasShellcodePatterns = false;
    
    /// @brief Has ROP gadgets
    bool hasROPGadgets = false;
    
    /// @brief Has API hashing
    bool hasAPIHashing = false;
    
    /// @brief Obfuscation techniques detected
    std::vector<std::string> obfuscationTechniques;
    
    /// @brief Risk score from code analysis
    double riskScore = 0.0;
};

/**
 * @brief Packer/protector detection result.
 */
struct PackerDetection {
    /// @brief Is packed
    bool isPacked = false;
    
    /// @brief Packer type
    PackerType packerType = PackerType::None;
    
    /// @brief Packer name
    std::string packerName;
    
    /// @brief Packer version (if detected)
    std::string packerVersion;
    
    /// @brief Confidence (0.0 - 1.0)
    double confidence = 0.0;
    
    /// @brief Is crypter
    bool isCrypter = false;
    
    /// @brief Is protector
    bool isProtector = false;
    
    /// @brief Is installer/SFX
    bool isInstaller = false;
    
    /// @brief Original entry point (if detected)
    uint64_t originalEntryPoint = 0;
    
    /// @brief Multiple packers detected
    std::vector<PackerType> additionalPackers;
    
    /// @brief Detection method
    std::string detectionMethod;
    
    /// @brief Risk score contribution
    double riskScore = 0.0;
};

/**
 * @brief Fuzzy hash matching result.
 */
struct FuzzyMatchResult {
    /// @brief Fuzzy hash
    std::string fuzzyHash;
    
    /// @brief TLSH hash
    std::string tlsh;
    
    /// @brief ImpHash
    std::string impHash;
    
    /// @brief Best fuzzy hash similarity (0-100)
    int fuzzySimilarity = 0;
    
    /// @brief Best TLSH distance (0 = identical)
    int tlshDistance = 256;
    
    /// @brief Matched threat name
    std::wstring matchedThreatName;
    
    /// @brief Matched family
    std::wstring matchedFamily;
    
    /// @brief Has significant match
    bool hasMatch = false;
    
    /// @brief Match confidence
    double matchConfidence = 0.0;
    
    /// @brief Risk score from fuzzy matching
    double riskScore = 0.0;
};

/**
 * @brief Detailed PE file analysis.
 */
struct PEAnalysis {
    /// @brief Is valid PE
    bool isValidPE = false;
    
    /// @brief Is 64-bit
    bool is64Bit = false;
    
    /// @brief Is DLL
    bool isDLL = false;
    
    /// @brief Is driver
    bool isDriver = false;
    
    /// @brief Is .NET assembly
    bool isDotNet = false;
    
    /// @brief Machine type
    uint16_t machine = 0;
    
    /// @brief Subsystem
    PESubsystem subsystem = PESubsystem::Unknown;
    
    /// @brief Number of sections
    uint16_t numberOfSections = 0;
    
    /// @brief Timestamp
    uint32_t timestamp = 0;
    
    /// @brief Timestamp as datetime
    std::chrono::system_clock::time_point timestampDate{};
    
    /// @brief Entry point RVA
    uint64_t entryPoint = 0;
    
    /// @brief Image base
    uint64_t imageBase = 0;
    
    /// @brief Section alignment
    uint32_t sectionAlignment = 0;
    
    /// @brief File alignment
    uint32_t fileAlignment = 0;
    
    /// @brief Size of image
    uint64_t sizeOfImage = 0;
    
    /// @brief Size of headers
    uint32_t sizeOfHeaders = 0;
    
    /// @brief Checksum
    uint32_t checksum = 0;
    
    /// @brief Calculated checksum
    uint32_t calculatedChecksum = 0;
    
    /// @brief Characteristics
    uint16_t characteristics = 0;
    
    /// @brief DLL characteristics
    uint16_t dllCharacteristics = 0;
    
    /// @brief Has ASLR
    bool hasASLR = false;
    
    /// @brief Has DEP/NX
    bool hasDEP = false;
    
    /// @brief Has CFG
    bool hasCFG = false;
    
    /// @brief Has SEH
    bool hasSEH = false;
    
    /// @brief Has SafeSEH
    bool hasSafeSEH = false;
    
    /// @brief Has high entropy VA
    bool hasHighEntropyVA = false;
    
    /// @brief Has overlay
    bool hasOverlay = false;
    
    /// @brief Overlay offset
    uint64_t overlayOffset = 0;
    
    /// @brief Overlay size
    uint64_t overlaySize = 0;
    
    /// @brief Overlay entropy
    double overlayEntropy = 0.0;
    
    /// @brief Has rich header
    bool hasRichHeader = false;
    
    /// @brief Rich header info
    std::vector<std::pair<uint32_t, uint32_t>> richEntries;
    
    /// @brief Debug directory type
    std::string debugType;
    
    /// @brief PDB path
    std::string pdbPath;
    
    /// @brief Detected anomalies
    std::vector<PEAnomaly> anomalies;
    
    /// @brief Section analyses
    std::vector<SectionAnalysis> sections;
    
    /// @brief Import analysis
    ImportAnalysis imports;
    
    /// @brief Export analysis
    ExportAnalysis exports;
    
    /// @brief Resource analysis
    ResourceAnalysis resources;
    
    /// @brief Certificate info
    CertificateInfo certificate;
    
    /// @brief Entry point section name
    std::string entryPointSection;
    
    /// @brief Overall entropy
    double overallEntropy = 0.0;
    
    /// @brief Code entropy
    double codeEntropy = 0.0;
    
    /// @brief Data entropy
    double dataEntropy = 0.0;
    
    /// @brief Risk score from PE analysis
    double riskScore = 0.0;
};

/**
 * @brief Script file analysis.
 */
struct ScriptAnalysis {
    /// @brief Script type
    std::string scriptType;  // "PowerShell", "VBScript", "JavaScript", etc.
    
    /// @brief Is obfuscated
    bool isObfuscated = false;
    
    /// @brief Has encoded content
    bool hasEncodedContent = false;
    
    /// @brief Has download capability
    bool hasDownloadCapability = false;
    
    /// @brief Has execution capability
    bool hasExecutionCapability = false;
    
    /// @brief Has file operations
    bool hasFileOperations = false;
    
    /// @brief Has registry operations
    bool hasRegistryOperations = false;
    
    /// @brief Has network operations
    bool hasNetworkOperations = false;
    
    /// @brief Has WMI operations
    bool hasWMIOperations = false;
    
    /// @brief Has COM operations
    bool hasCOMOperations = false;
    
    /// @brief Has process operations
    bool hasProcessOperations = false;
    
    /// @brief Detected techniques
    std::vector<std::string> detectedTechniques;
    
    /// @brief Extracted URLs
    std::vector<std::string> urls;
    
    /// @brief Extracted IPs
    std::vector<std::string> ips;
    
    /// @brief Extracted domains
    std::vector<std::string> domains;
    
    /// @brief Extracted file paths
    std::vector<std::wstring> filePaths;
    
    /// @brief Extracted registry paths
    std::vector<std::wstring> registryPaths;
    
    /// @brief Base64 encoded blocks
    std::vector<std::string> base64Blocks;
    
    /// @brief Risk score from script analysis
    double riskScore = 0.0;
    
    /// @brief MITRE techniques detected
    std::vector<std::string> mitreTechniques;
};

/**
 * @brief Heuristic indicator.
 */
struct HeuristicIndicator {
    /// @brief Indicator ID
    std::string id;
    
    /// @brief Description
    std::string description;
    
    /// @brief Category
    std::string category;
    
    /// @brief Severity
    IndicatorSeverity severity = IndicatorSeverity::Info;
    
    /// @brief Score contribution
    double score = 0.0;
    
    /// @brief MITRE technique (if applicable)
    std::string mitreTechnique;
    
    /// @brief Additional details
    std::vector<std::string> details;
};

/**
 * @brief Complete heuristic analysis result.
 */
struct HeuristicResult {
    // -------------------------------------------------------------------------
    // File Information
    // -------------------------------------------------------------------------
    
    /// @brief File path
    std::wstring filePath;
    
    /// @brief File size
    uint64_t fileSize = 0;
    
    /// @brief File type
    FileType fileType = FileType::Unknown;
    
    /// @brief File type name
    std::string fileTypeName;
    
    /// @brief MD5 hash
    std::string md5;
    
    /// @brief SHA1 hash
    std::string sha1;
    
    /// @brief SHA256 hash
    std::string sha256;
    
    // -------------------------------------------------------------------------
    // Scoring
    // -------------------------------------------------------------------------
    
    /// @brief Overall risk score (0.0 - 100.0)
    double riskScore = 0.0;
    
    /// @brief Confidence (0.0 - 1.0)
    double confidence = 0.0;
    
    /// @brief Category scores
    std::map<std::string, double> categoryScores;
    
    // -------------------------------------------------------------------------
    // Verdict
    // -------------------------------------------------------------------------
    
    /// @brief Is clean
    bool isClean = true;
    
    /// @brief Is suspicious
    bool isSuspicious = false;
    
    /// @brief Is likely malicious
    bool isLikelyMalicious = false;
    
    /// @brief Is malicious
    bool isMalicious = false;
    
    /// @brief Threat name (if malicious)
    std::wstring threatName;
    
    /// @brief Threat family
    std::wstring threatFamily;
    
    // -------------------------------------------------------------------------
    // Detailed Analysis Results
    // -------------------------------------------------------------------------
    
    /// @brief PE analysis (if PE file)
    std::optional<PEAnalysis> peAnalysis;
    
    /// @brief Script analysis (if script)
    std::optional<ScriptAnalysis> scriptAnalysis;
    
    /// @brief Packer detection
    PackerDetection packerDetection;
    
    /// @brief String analysis
    StringAnalysis stringAnalysis;
    
    /// @brief Code analysis
    CodeAnalysis codeAnalysis;
    
    /// @brief Fuzzy matching results
    FuzzyMatchResult fuzzyMatch;
    
    // -------------------------------------------------------------------------
    // Indicators
    // -------------------------------------------------------------------------
    
    /// @brief All triggered indicators
    std::vector<HeuristicIndicator> indicators;
    
    /// @brief High severity indicators only
    std::vector<HeuristicIndicator> highSeverityIndicators;
    
    /// @brief MITRE ATT&CK techniques
    std::vector<std::string> mitreTechniques;
    
    // -------------------------------------------------------------------------
    // Summary
    // -------------------------------------------------------------------------
    
    /// @brief Summary description
    std::wstring summary;
    
    /// @brief Analysis duration
    std::chrono::milliseconds analysisDuration{};
    
    /// @brief Analysis timestamp
    std::chrono::system_clock::time_point timestamp{};
    
    /// @brief Was analysis complete
    bool analysisComplete = false;
    
    /// @brief Error message (if any)
    std::string errorMessage;
    
    // -------------------------------------------------------------------------
    // Utility Methods
    // -------------------------------------------------------------------------
    
    /**
     * @brief Get severity string.
     */
    [[nodiscard]] std::string GetSeverityString() const noexcept {
        if (riskScore >= HeuristicConstants::CONFIRMED_MALICIOUS_THRESHOLD) return "Critical";
        if (riskScore >= HeuristicConstants::MALICIOUS_THRESHOLD) return "High";
        if (riskScore >= HeuristicConstants::LIKELY_MALICIOUS_THRESHOLD) return "Medium";
        if (riskScore >= HeuristicConstants::SUSPICIOUS_THRESHOLD) return "Low";
        return "Clean";
    }
    
    /**
     * @brief Check if immediate action is required.
     */
    [[nodiscard]] bool RequiresImmediateAction() const noexcept {
        return riskScore >= HeuristicConstants::MALICIOUS_THRESHOLD;
    }
};

/**
 * @brief Configuration for heuristic analyzer.
 */
struct HeuristicAnalyzerConfig {
    // -------------------------------------------------------------------------
    // General Settings
    // -------------------------------------------------------------------------
    
    /// @brief Enable heuristic analysis
    bool enabled = true;
    
    /// @brief Analysis timeout (seconds)
    uint32_t timeoutSeconds = HeuristicConstants::ANALYSIS_TIMEOUT_SECONDS;
    
    /// @brief Maximum file size to analyze
    uint64_t maxFileSize = HeuristicConstants::MAX_FILE_SIZE;
    
    // -------------------------------------------------------------------------
    // Analysis Modules
    // -------------------------------------------------------------------------
    
    /// @brief Enable PE analysis
    bool enablePEAnalysis = true;
    
    /// @brief Enable ELF analysis
    bool enableELFAnalysis = true;
    
    /// @brief Enable script analysis
    bool enableScriptAnalysis = true;
    
    /// @brief Enable import analysis
    bool enableImportAnalysis = true;
    
    /// @brief Enable export analysis
    bool enableExportAnalysis = true;
    
    /// @brief Enable resource analysis
    bool enableResourceAnalysis = true;
    
    /// @brief Enable string analysis
    bool enableStringAnalysis = true;
    
    /// @brief Enable code analysis
    bool enableCodeAnalysis = true;
    
    /// @brief Enable packer detection
    bool enablePackerDetection = true;
    
    /// @brief Enable certificate analysis
    bool enableCertificateAnalysis = true;
    
    /// @brief Enable fuzzy matching
    bool enableFuzzyMatching = true;
    
    // -------------------------------------------------------------------------
    // Threshold Settings
    // -------------------------------------------------------------------------
    
    /// @brief High entropy threshold
    double highEntropyThreshold = HeuristicConstants::HIGH_ENTROPY_THRESHOLD;
    
    /// @brief Suspicious threshold
    double suspiciousThreshold = HeuristicConstants::SUSPICIOUS_THRESHOLD;
    
    /// @brief Malicious threshold
    double maliciousThreshold = HeuristicConstants::MALICIOUS_THRESHOLD;
    
    /// @brief Fuzzy hash minimum similarity
    int fuzzyMinSimilarity = HeuristicConstants::FUZZY_MIN_SIMILARITY;
    
    /// @brief TLSH maximum distance
    int tlshMaxDistance = HeuristicConstants::TLSH_MAX_DISTANCE;
    
    // -------------------------------------------------------------------------
    // Weight Settings
    // -------------------------------------------------------------------------
    
    /// @brief PE anomaly weight
    double peAnomalyWeight = HeuristicConstants::PE_ANOMALY_WEIGHT;
    
    /// @brief Entropy weight
    double entropyWeight = HeuristicConstants::ENTROPY_WEIGHT;
    
    /// @brief Import weight
    double importWeight = HeuristicConstants::IMPORT_WEIGHT;
    
    /// @brief Obfuscation weight
    double obfuscationWeight = HeuristicConstants::OBFUSCATION_WEIGHT;
    
    /// @brief String weight
    double stringWeight = HeuristicConstants::STRING_WEIGHT;
    
    /// @brief Certificate weight
    double certificateWeight = HeuristicConstants::CERTIFICATE_WEIGHT;
    
    /// @brief Packer weight
    double packerWeight = HeuristicConstants::PACKER_WEIGHT;
    
    /// @brief Fuzzy match weight
    double fuzzyMatchWeight = HeuristicConstants::FUZZY_MATCH_WEIGHT;
    
    // -------------------------------------------------------------------------
    // Resource Limits
    // -------------------------------------------------------------------------
    
    /// @brief Maximum strings to extract
    size_t maxStrings = HeuristicConstants::MAX_STRINGS;
    
    /// @brief Minimum string length
    size_t minStringLength = HeuristicConstants::MIN_STRING_LENGTH;
    
    /// @brief Maximum string length
    size_t maxStringLength = HeuristicConstants::MAX_STRING_LENGTH;
    
    // -------------------------------------------------------------------------
    // Trust Settings
    // -------------------------------------------------------------------------
    
    /// @brief Trust Microsoft signatures
    bool trustMicrosoftSignatures = true;
    
    /// @brief Trust known vendor signatures
    bool trustVendorSignatures = true;
    
    // -------------------------------------------------------------------------
    // Factory Methods
    // -------------------------------------------------------------------------
    
    /**
     * @brief Create default configuration.
     */
    [[nodiscard]] static HeuristicAnalyzerConfig CreateDefault() noexcept {
        return HeuristicAnalyzerConfig{};
    }
    
    /**
     * @brief Create high-sensitivity configuration.
     */
    [[nodiscard]] static HeuristicAnalyzerConfig CreateHighSensitivity() noexcept {
        HeuristicAnalyzerConfig config;
        config.highEntropyThreshold = 6.5;
        config.suspiciousThreshold = 20.0;
        config.maliciousThreshold = 50.0;
        config.fuzzyMinSimilarity = 30;
        return config;
    }
    
    /**
     * @brief Create fast-scan configuration.
     */
    [[nodiscard]] static HeuristicAnalyzerConfig CreateFastScan() noexcept {
        HeuristicAnalyzerConfig config;
        config.enableCodeAnalysis = false;
        config.enableStringAnalysis = false;
        config.enableResourceAnalysis = false;
        config.timeoutSeconds = 10;
        return config;
    }
};

/**
 * @brief Statistics for heuristic analyzer.
 */
struct HeuristicAnalyzerStats {
    /// @brief Total files analyzed
    std::atomic<uint64_t> totalFilesAnalyzed{ 0 };
    
    /// @brief Files by type
    std::array<std::atomic<uint64_t>, 32> filesByType{};
    
    /// @brief Clean files
    std::atomic<uint64_t> cleanFiles{ 0 };
    
    /// @brief Suspicious files
    std::atomic<uint64_t> suspiciousFiles{ 0 };
    
    /// @brief Malicious files
    std::atomic<uint64_t> maliciousFiles{ 0 };
    
    /// @brief Packed files detected
    std::atomic<uint64_t> packedFiles{ 0 };
    
    /// @brief Fuzzy matches found
    std::atomic<uint64_t> fuzzyMatches{ 0 };
    
    /// @brief Analysis failures
    std::atomic<uint64_t> analysisFailures{ 0 };
    
    /// @brief Timeouts
    std::atomic<uint64_t> timeouts{ 0 };
    
    /// @brief Average analysis time (microseconds)
    std::atomic<uint64_t> avgAnalysisTimeUs{ 0 };
    
    /// @brief Total bytes analyzed
    std::atomic<uint64_t> totalBytesAnalyzed{ 0 };
    
    /**
     * @brief Reset all statistics.
     */
    void Reset() noexcept {
        totalFilesAnalyzed.store(0, std::memory_order_relaxed);
        for (auto& t : filesByType) t.store(0, std::memory_order_relaxed);
        cleanFiles.store(0, std::memory_order_relaxed);
        suspiciousFiles.store(0, std::memory_order_relaxed);
        maliciousFiles.store(0, std::memory_order_relaxed);
        packedFiles.store(0, std::memory_order_relaxed);
        fuzzyMatches.store(0, std::memory_order_relaxed);
        analysisFailures.store(0, std::memory_order_relaxed);
        timeouts.store(0, std::memory_order_relaxed);
        avgAnalysisTimeUs.store(0, std::memory_order_relaxed);
        totalBytesAnalyzed.store(0, std::memory_order_relaxed);
    }
};

/**
 * @brief Callback for analysis completion.
 */
using HeuristicResultCallback = std::function<void(const HeuristicResult&)>;

// ============================================================================
// MAIN HEURISTIC ANALYZER CLASS
// ============================================================================

/**
 * @brief Enterprise-grade static heuristic analysis engine.
 *
 * Performs deep static analysis of files to detect unknown/zero-day threats
 * by examining structural anomalies, behavioral indicators, and similarity
 * to known malware families.
 *
 * Thread Safety: All public methods are thread-safe.
 *
 * Usage Example:
 * @code
 * auto& analyzer = HeuristicAnalyzer::Instance();
 * 
 * // Initialize
 * HeuristicAnalyzerConfig config = HeuristicAnalyzerConfig::CreateDefault();
 * analyzer.Initialize(threadPool, config);
 * 
 * // Connect to HashStore for fuzzy matching
 * analyzer.SetHashStore(&HashStore::HashStore::Instance());
 * 
 * // Analyze file
 * HeuristicResult result = analyzer.AnalyzeFile(L"C:\\suspicious.exe");
 * 
 * if (result.isMalicious) {
 *     LOG_ALERT(L"Threat detected: {} (Score: {})", 
 *               result.threatName, result.riskScore);
 *     
 *     // Print indicators
 *     for (const auto& indicator : result.highSeverityIndicators) {
 *         LOG_INFO("  - {}: {}", indicator.id, indicator.description);
 *     }
 * }
 * 
 * // Async analysis
 * analyzer.AnalyzeFileAsync(L"C:\\another.exe", [](const HeuristicResult& r) {
 *     // Handle result
 * });
 * 
 * analyzer.Shutdown();
 * @endcode
 */
class HeuristicAnalyzer {
public:
    // =========================================================================
    // Singleton Access
    // =========================================================================

    /**
     * @brief Get the singleton instance.
     * @return Reference to the global HeuristicAnalyzer instance.
     * @note Thread-safe (Meyers' singleton).
     */
    [[nodiscard]] static HeuristicAnalyzer& Instance();

    // Non-copyable, non-movable
    HeuristicAnalyzer(const HeuristicAnalyzer&) = delete;
    HeuristicAnalyzer& operator=(const HeuristicAnalyzer&) = delete;
    HeuristicAnalyzer(HeuristicAnalyzer&&) = delete;
    HeuristicAnalyzer& operator=(HeuristicAnalyzer&&) = delete;

    // =========================================================================
    // Lifecycle Management
    // =========================================================================

    /**
     * @brief Initialize the analyzer.
     * @return true on success.
     */
    [[nodiscard]] bool Initialize();

    /**
     * @brief Initialize with thread pool.
     * @param threadPool Thread pool for async operations.
     * @return true on success.
     */
    [[nodiscard]] bool Initialize(std::shared_ptr<Utils::ThreadPool> threadPool);

    /**
     * @brief Initialize with configuration.
     * @param threadPool Thread pool.
     * @param config Analyzer configuration.
     * @return true on success.
     */
    [[nodiscard]] bool Initialize(
        std::shared_ptr<Utils::ThreadPool> threadPool,
        const HeuristicAnalyzerConfig& config
    );

    /**
     * @brief Shutdown the analyzer.
     */
    void Shutdown();

    /**
     * @brief Check if analyzer is initialized.
     */
    [[nodiscard]] bool IsInitialized() const noexcept;

    /**
     * @brief Update configuration at runtime.
     */
    void UpdateConfig(const HeuristicAnalyzerConfig& config);

    /**
     * @brief Get current configuration.
     */
    [[nodiscard]] HeuristicAnalyzerConfig GetConfig() const;

    // =========================================================================
    // File Analysis
    // =========================================================================

    /**
     * @brief Analyze file by path.
     * @param filePath Path to file.
     * @return Complete heuristic analysis result.
     */
    [[nodiscard]] HeuristicResult AnalyzeFile(const std::wstring& filePath);

    /**
     * @brief Analyze file from memory buffer.
     * @param data File data buffer.
     * @param fileName Optional filename for context.
     * @return Complete heuristic analysis result.
     */
    [[nodiscard]] HeuristicResult AnalyzeBuffer(
        std::span<const uint8_t> data,
        const std::wstring& fileName = L""
    );

    /**
     * @brief Analyze file with pre-loaded data.
     * @param filePath File path.
     * @param data Pre-loaded file data.
     * @return Complete heuristic analysis result.
     */
    [[nodiscard]] HeuristicResult AnalyzeFile(
        const std::wstring& filePath,
        std::span<const uint8_t> data
    );

    /**
     * @brief Analyze file asynchronously.
     * @param filePath Path to file.
     * @param callback Callback for result.
     * @return true if analysis was queued.
     */
    bool AnalyzeFileAsync(
        const std::wstring& filePath,
        HeuristicResultCallback callback
    );

    /**
     * @brief Quick scan (reduced analysis).
     * @param filePath Path to file.
     * @return Quick analysis result.
     */
    [[nodiscard]] HeuristicResult QuickScan(const std::wstring& filePath);

    // =========================================================================
    // Specific Analysis Methods
    // =========================================================================

    /**
     * @brief Analyze PE file structure.
     * @param data File data.
     * @return PE analysis result.
     */
    [[nodiscard]] PEAnalysis AnalyzePE(std::span<const uint8_t> data);

    /**
     * @brief Analyze script file.
     * @param data File data.
     * @param scriptType Type hint (PowerShell, VBS, etc.)
     * @return Script analysis result.
     */
    [[nodiscard]] ScriptAnalysis AnalyzeScript(
        std::span<const uint8_t> data,
        const std::string& scriptType = ""
    );

    /**
     * @brief Detect packer/protector.
     * @param data File data.
     * @return Packer detection result.
     */
    [[nodiscard]] PackerDetection DetectPacker(std::span<const uint8_t> data);

    /**
     * @brief Extract and analyze strings.
     * @param data File data.
     * @return String analysis result.
     */
    [[nodiscard]] StringAnalysis AnalyzeStrings(std::span<const uint8_t> data);

    /**
     * @brief Analyze imports.
     * @param data PE file data.
     * @return Import analysis result.
     */
    [[nodiscard]] ImportAnalysis AnalyzeImports(std::span<const uint8_t> data);

    /**
     * @brief Verify digital signature.
     * @param filePath Path to file.
     * @return Certificate info.
     */
    [[nodiscard]] CertificateInfo VerifySignature(const std::wstring& filePath);

    // =========================================================================
    // Entropy Calculation
    // =========================================================================

    /**
     * @brief Calculate Shannon entropy.
     * @param data Data buffer.
     * @return Entropy value (0.0 - 8.0).
     */
    [[nodiscard]] double CalculateEntropy(std::span<const uint8_t> data) const;

    /**
     * @brief Calculate chi-square statistic.
     * @param data Data buffer.
     * @return Chi-square value.
     */
    [[nodiscard]] double CalculateChiSquare(std::span<const uint8_t> data) const;

    /**
     * @brief Check if data appears random/encrypted.
     * @param data Data buffer.
     * @return true if likely random/encrypted.
     */
    [[nodiscard]] bool IsLikelyEncrypted(std::span<const uint8_t> data) const;

    // =========================================================================
    // Hash Calculation
    // =========================================================================

    /**
     * @brief Calculate import hash.
     * @param data PE file data.
     * @return ImpHash string.
     */
    [[nodiscard]] std::string CalculateImpHash(std::span<const uint8_t> data) const;

    /**
     * @brief Calculate fuzzy hash.
     * @param data File data.
     * @return Fuzzy hash string.
     */
    [[nodiscard]] std::string CalculateFuzzyHash(std::span<const uint8_t> data) const;

    /**
     * @brief Calculate TLSH hash.
     * @param data File data.
     * @return TLSH hash string.
     */
    [[nodiscard]] std::string CalculateTLSH(std::span<const uint8_t> data) const;

    // =========================================================================
    // File Type Detection
    // =========================================================================

    /**
     * @brief Detect file type.
     * @param data File data.
     * @return Detected file type.
     */
    [[nodiscard]] FileType DetectFileType(std::span<const uint8_t> data) const;

    /**
     * @brief Detect file type from path.
     * @param filePath File path.
     * @return Detected file type.
     */
    [[nodiscard]] FileType DetectFileType(const std::wstring& filePath) const;

    // =========================================================================
    // Fuzzy Matching
    // =========================================================================

    /**
     * @brief Compare fuzzy hashes.
     * @param hash1 First hash.
     * @param hash2 Second hash.
     * @return Similarity (0-100).
     */
    [[nodiscard]] int CompareFuzzyHash(
        const std::string& hash1,
        const std::string& hash2
    ) const;

    /**
     * @brief Compare TLSH hashes.
     * @param hash1 First hash.
     * @param hash2 Second hash.
     * @return Distance (0 = identical).
     */
    [[nodiscard]] int CompareTLSH(
        const std::string& hash1,
        const std::string& hash2
    ) const;

    /**
     * @brief Query HashStore for fuzzy matches.
     * @param fuzzyHash Fuzzy hash.
     * @param tlsh TLSH hash.
     * @param impHash ImpHash.
     * @return Fuzzy match result.
     */
    [[nodiscard]] FuzzyMatchResult QueryFuzzyMatch(
        const std::string& fuzzyHash,
        const std::string& tlsh,
        const std::string& impHash
    );

    // =========================================================================
    // Statistics
    // =========================================================================

    /**
     * @brief Get analyzer statistics.
     */
    [[nodiscard]] HeuristicAnalyzerStats GetStats() const;

    /**
     * @brief Reset statistics.
     */
    void ResetStats();

    // =========================================================================
    // External Store Integration
    // =========================================================================

    /**
     * @brief Set HashStore for fuzzy matching.
     */
    void SetHashStore(HashStore::HashStore* store);

    /**
     * @brief Set SignatureStore for YARA rules.
     */
    void SetSignatureStore(SignatureStore::SignatureStore* store);

    /**
     * @brief Set PatternStore for string patterns.
     */
    void SetPatternStore(PatternStore::PatternStore* store);

    /**
     * @brief Set ThreatIntel for certificate reputation.
     */
    void SetThreatIntelIndex(ThreatIntel::ThreatIntelIndex* index);

private:
    // =========================================================================
    // Private Constructor (Singleton)
    // =========================================================================

    HeuristicAnalyzer();
    ~HeuristicAnalyzer();

    // =========================================================================
    // Internal Analysis Methods
    // =========================================================================

    /**
     * @brief Parse DOS header.
     */
    bool ParseDOSHeader(std::span<const uint8_t> data, PEAnalysis& pe);

    /**
     * @brief Parse PE headers.
     */
    bool ParsePEHeaders(std::span<const uint8_t> data, PEAnalysis& pe);

    /**
     * @brief Parse sections.
     */
    void ParseSections(std::span<const uint8_t> data, PEAnalysis& pe);

    /**
     * @brief Parse imports.
     */
    void ParseImports(std::span<const uint8_t> data, PEAnalysis& pe);

    /**
     * @brief Parse exports.
     */
    void ParseExports(std::span<const uint8_t> data, PEAnalysis& pe);

    /**
     * @brief Parse resources.
     */
    void ParseResources(std::span<const uint8_t> data, PEAnalysis& pe);

    /**
     * @brief Analyze rich header.
     */
    void AnalyzeRichHeader(std::span<const uint8_t> data, PEAnalysis& pe);

    /**
     * @brief Detect PE anomalies.
     */
    void DetectPEAnomalies(std::span<const uint8_t> data, PEAnalysis& pe);

    /**
     * @brief Analyze code section.
     */
    void AnalyzeCode(std::span<const uint8_t> data, CodeAnalysis& code);

    /**
     * @brief Calculate section hashes.
     */
    void CalculateSectionHashes(std::span<const uint8_t> data, SectionAnalysis& section);

    /**
     * @brief Classify imported function.
     */
    void ClassifyImport(ImportedFunction& func);

    /**
     * @brief Aggregate scores into final result.
     */
    void AggregateScores(HeuristicResult& result);

    /**
     * @brief Generate threat name from indicators.
     */
    void GenerateThreatName(HeuristicResult& result);

    // =========================================================================
    // Internal Data (PIMPL)
    // =========================================================================

    struct Impl;
    std::unique_ptr<Impl> m_impl;
};

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

/**
 * @brief Calculate file entropy.
 */
[[nodiscard]] double CalculateFileEntropy(const std::wstring& filePath) noexcept;

/**
 * @brief Check if section name is suspicious.
 */
[[nodiscard]] bool IsSuspiciousSectionName(const std::string& name) noexcept;

/**
 * @brief Check if import is suspicious.
 */
[[nodiscard]] bool IsSuspiciousImport(const std::string& dllName, const std::string& funcName) noexcept;

/**
 * @brief Get suspicious API category.
 */
[[nodiscard]] SuspiciousAPICategory GetAPICategory(const std::string& funcName) noexcept;

/**
 * @brief Check if string is potential IOC.
 */
[[nodiscard]] bool IsPotentialIOC(const std::string& str) noexcept;

/**
 * @brief Extract URLs from string.
 */
[[nodiscard]] std::vector<std::string> ExtractURLs(const std::string& str) noexcept;

/**
 * @brief Extract IP addresses from string.
 */
[[nodiscard]] std::vector<std::string> ExtractIPs(const std::string& str) noexcept;

/**
 * @brief Check if buffer contains PE signature.
 */
[[nodiscard]] bool ContainsPE(std::span<const uint8_t> data) noexcept;

/**
 * @brief Check if buffer looks like shellcode.
 */
[[nodiscard]] bool LooksLikeShellcode(std::span<const uint8_t> data) noexcept;

} // namespace Engine
} // namespace Core
} // namespace ShadowStrike
