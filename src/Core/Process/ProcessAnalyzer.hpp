/**
 * ============================================================================
 * ShadowStrike Core Process - PROCESS ANALYZER (The Investigator)
 * ============================================================================
 *
 * @file ProcessAnalyzer.hpp
 * @brief Comprehensive static and dynamic process analysis engine.
 *
 * While ProcessMonitor tracks *who* is running, ProcessAnalyzer determines *what*
 * they are doing, how they're doing it, and whether it's suspicious. This module
 * provides deep on-demand inspection capabilities for forensic analysis, threat
 * hunting, and real-time threat assessment.
 *
 * ============================================================================
 * ENTERPRISE CAPABILITIES
 * ============================================================================
 *
 * 1. MODULE ANALYSIS (Loaded DLL Inspection)
 *    - Complete module enumeration with metadata
 *    - Signature verification for each module
 *    - Module load order anomaly detection
 *    - Side-loaded DLL detection
 *    - Phantom DLL detection (unlisted in PEB)
 *    - Import/Export table analysis
 *    - Module tampering detection (hook detection)
 *
 * 2. HANDLE INSPECTION (Resource Access Analysis)
 *    - File handle enumeration and classification
 *    - Registry key handle analysis
 *    - Token handle inspection (privilege analysis)
 *    - Named pipe access monitoring
 *    - Section (shared memory) mapping analysis
 *    - Synchronization object enumeration
 *    - Handle inheritance tracking
 *
 * 3. DIGITAL SIGNATURE VERIFICATION
 *    - Authenticode signature validation
 *    - Catalog-based signature verification
 *    - Certificate chain validation
 *    - Certificate revocation checking (CRL/OCSP)
 *    - Timestamp verification
 *    - Publisher trust level assessment
 *    - Known compromised certificate detection
 *
 * 4. PARENT-CHILD RELATIONSHIP ANALYSIS
 *    - Expected parent validation (EPROCESS relationships)
 *    - Anomalous spawn detection (e.g., Excel spawning cmd.exe)
 *    - PPID spoofing detection
 *    - Process tree reconstruction
 *    - Orphan process detection
 *    - Session isolation validation
 *
 * 5. MEMORY ANALYSIS
 *    - Memory region classification
 *    - Executable memory mapping
 *    - RWX region detection
 *    - Unbacked executable memory detection
 *    - Memory protection anomalies
 *    - Working set analysis
 *    - Heap analysis
 *
 * 6. THREAD ANALYSIS
 *    - Thread enumeration with metadata
 *    - Thread start address validation
 *    - Orphan thread detection (no module backing)
 *    - Thread context analysis
 *    - APC queue inspection
 *    - Thread creation time correlation
 *
 * 7. SECURITY CONTEXT ANALYSIS
 *    - Token analysis (privileges, groups, integrity)
 *    - Impersonation detection
 *    - Privilege escalation indicators
 *    - Security descriptor analysis
 *    - UAC bypass indicators
 *    - Protected process verification
 *
 * 8. NETWORK FOOTPRINT ANALYSIS
 *    - Active connection enumeration
 *    - Listening port analysis
 *    - DNS cache correlation
 *    - Network module detection (ws2_32, wininet, winhttp)
 *
 * 9. BEHAVIORAL INDICATORS
 *    - API call pattern analysis (via hooks/ETW)
 *    - Code injection indicators
 *    - Persistence mechanism setup
 *    - Defense evasion indicators
 *    - Data exfiltration patterns
 *
 * ============================================================================
 * MITRE ATT&CK COVERAGE
 * ============================================================================
 *
 * | Technique ID | Technique Name              | Detection Method              |
 * |--------------|-----------------------------|-------------------------------|
 * | T1055        | Process Injection           | Memory/Thread analysis        |
 * | T1134        | Access Token Manipulation   | Token analysis                |
 * | T1036        | Masquerading                | Path/signature validation     |
 * | T1574        | Hijack Execution Flow       | Module load order analysis    |
 * | T1574.001    | DLL Search Order Hijacking  | Side-load detection           |
 * | T1574.002    | DLL Side-Loading            | Known side-load pairs         |
 * | T1548        | Abuse Elevation Control     | UAC bypass indicators         |
 * | T1140        | Deobfuscate/Decode Files    | Memory pattern analysis       |
 * | T1027        | Obfuscated Files            | Entropy analysis              |
 * | T1106        | Native API                  | Direct syscall detection      |
 * | T1562        | Impair Defenses             | AV/EDR tampering detection    |
 * | T1564        | Hide Artifacts              | Hidden process/thread detect  |
 *
 * ============================================================================
 * INTEGRATION ARCHITECTURE
 * ============================================================================
 *
 * ┌─────────────────────────────────────────────────────────────────────────┐
 * │                          ProcessAnalyzer                                │
 * │                       (Deep Process Inspection)                         │
 * └───────────────┬─────────────────────────────────────────────────────────┘
 *                 │
 *     ┌───────────┼───────────┬────────────────┬─────────────────┐
 *     ▼           ▼           ▼                ▼                 ▼
 * ┌────────┐ ┌────────┐ ┌──────────┐    ┌───────────┐    ┌────────────┐
 * │Process │ │HashStore│ │Signature │    │ThreatIntel│    │ Whitelist  │
 * │Monitor │ │         │ │  Store   │    │           │    │   Store    │
 * └────────┘ └────────┘ └──────────┘    └───────────┘    └────────────┘
 *     │           │           │                │                 │
 *     │    ┌──────┴──────┐    │         ┌──────┴──────┐         │
 *     │    │ Hash-based  │    │         │ Reputation/ │         │
 *     │    │ IOC Lookup  │    │         │ IOC Lookup  │         │
 *     │    └─────────────┘    │         └─────────────┘         │
 *     │                       │                                  │
 *     └─────────────────┬─────┴───────────────┬─────────────────┘
 *                       ▼                     ▼
 *              ┌─────────────────┐   ┌─────────────────┐
 *              │  ProcessUtils   │   │   FileUtils     │
 *              │ (Enumeration)   │   │ (Path Analysis) │
 *              └─────────────────┘   └─────────────────┘
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
#include "../../Utils/FileUtils.hpp"
#include "../../Utils/CryptoUtils.hpp"
#include "../../Utils/ErrorUtils.hpp"
#include "../../HashStore/HashStore.hpp"
#include "../../SignatureStore/SignatureStore.hpp"
#include "../../ThreatIntel/ThreatIntelManager.hpp"
#include "../../Whitelist/WhitelistStore.hpp"

// Standard library
#include <string>
#include <string_view>
#include <vector>
#include <map>
#include <unordered_map>
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
#include <array>
#include <bitset>
#include <cstdint>

namespace ShadowStrike {
namespace Core {
namespace Process {

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

class ProcessAnalyzerImpl;

// ============================================================================
// CONSTANTS
// ============================================================================

namespace AnalyzerConstants {

    // Version information
    constexpr uint32_t VERSION_MAJOR = 4;
    constexpr uint32_t VERSION_MINOR = 0;
    constexpr uint32_t VERSION_PATCH = 0;

    // Analysis limits
    constexpr size_t MAX_MODULES_TO_ANALYZE = 2048;
    constexpr size_t MAX_HANDLES_TO_ENUMERATE = 65536;
    constexpr size_t MAX_THREADS_TO_ANALYZE = 4096;
    constexpr size_t MAX_MEMORY_REGIONS = 16384;
    constexpr size_t MAX_NETWORK_CONNECTIONS = 8192;
    constexpr size_t MAX_ANCESTRY_DEPTH = 64;
    constexpr size_t MAX_CHILDREN_TO_TRACK = 1024;

    // Timeouts
    constexpr uint32_t SIGNATURE_CHECK_TIMEOUT_MS = 5000;
    constexpr uint32_t NETWORK_ENUM_TIMEOUT_MS = 3000;
    constexpr uint32_t HANDLE_ENUM_TIMEOUT_MS = 10000;
    constexpr uint32_t MEMORY_SCAN_TIMEOUT_MS = 30000;

    // Thresholds
    constexpr double HIGH_ENTROPY_THRESHOLD = 7.2;
    constexpr double PACKED_ENTROPY_THRESHOLD = 7.5;
    constexpr uint32_t SUSPICIOUS_HANDLE_COUNT_THRESHOLD = 10000;
    constexpr uint32_t SUSPICIOUS_THREAD_COUNT_THRESHOLD = 500;
    constexpr size_t MIN_SHELLCODE_SIZE = 16;
    constexpr size_t MAX_LEGITIMATE_IMPORT_COUNT = 5000;

    // Risk scoring weights
    constexpr uint32_t RISK_WEIGHT_UNSIGNED = 15;
    constexpr uint32_t RISK_WEIGHT_UNKNOWN_PUBLISHER = 10;
    constexpr uint32_t RISK_WEIGHT_REVOKED_CERT = 50;
    constexpr uint32_t RISK_WEIGHT_PARENT_ANOMALY = 25;
    constexpr uint32_t RISK_WEIGHT_PPID_SPOOFING = 40;
    constexpr uint32_t RISK_WEIGHT_RWX_MEMORY = 20;
    constexpr uint32_t RISK_WEIGHT_UNBACKED_EXEC = 35;
    constexpr uint32_t RISK_WEIGHT_PHANTOM_DLL = 30;
    constexpr uint32_t RISK_WEIGHT_ORPHAN_THREAD = 25;
    constexpr uint32_t RISK_WEIGHT_HIGH_ENTROPY = 15;
    constexpr uint32_t RISK_WEIGHT_KNOWN_MALICIOUS = 100;
    constexpr uint32_t RISK_WEIGHT_BAD_REPUTATION = 40;

    // Cache configuration
    constexpr size_t ANALYSIS_CACHE_SIZE = 4096;
    constexpr uint32_t ANALYSIS_CACHE_TTL_SECONDS = 300;
    constexpr size_t SIGNATURE_CACHE_SIZE = 16384;
    constexpr uint32_t SIGNATURE_CACHE_TTL_SECONDS = 3600;

    // Known Windows system process names (case-insensitive)
    constexpr std::wstring_view SYSTEM_PROCESSES[] = {
        L"System", L"smss.exe", L"csrss.exe", L"wininit.exe",
        L"winlogon.exe", L"services.exe", L"lsass.exe", L"svchost.exe",
        L"fontdrvhost.exe", L"dwm.exe", L"spoolsv.exe", L"taskhost.exe",
        L"taskhostw.exe", L"sihost.exe", L"ctfmon.exe", L"conhost.exe",
        L"RuntimeBroker.exe", L"SearchIndexer.exe", L"SearchProtocolHost.exe",
        L"WmiPrvSE.exe", L"dllhost.exe", L"msiexec.exe", L"TrustedInstaller.exe",
        L"audiodg.exe", L"MsMpEng.exe", L"NisSrv.exe", L"SecurityHealthService.exe"
    };

} // namespace AnalyzerConstants

// ============================================================================
// ENUMERATIONS
// ============================================================================

/**
 * @enum ProcessRiskLevel
 * @brief Overall risk assessment level for a process.
 */
enum class ProcessRiskLevel : uint8_t {
    Trusted = 0,          ///< Whitelisted or Microsoft-signed
    Safe = 1,             ///< Properly signed, good reputation
    Unknown = 2,          ///< No reputation data available
    LowRisk = 3,          ///< Minor anomalies detected
    MediumRisk = 4,       ///< Multiple suspicious indicators
    HighRisk = 5,         ///< Significant threat indicators
    Suspicious = 6,       ///< Strong malicious indicators
    Malicious = 7,        ///< Confirmed malicious (hash match, signature)
    Critical = 8          ///< Active exploitation/injection detected
};

/**
 * @enum AnalysisDepth
 * @brief Depth of analysis to perform (performance vs thoroughness trade-off).
 */
enum class AnalysisDepth : uint8_t {
    Quick = 0,            ///< Basic checks only (signature, whitelist)
    Standard = 1,         ///< Normal analysis (modules, handles, memory summary)
    Deep = 2,             ///< Comprehensive (full memory scan, all threads)
    Forensic = 3          ///< Complete forensic analysis (for incident response)
};

/**
 * @enum ModuleLoadReason
 * @brief Why a module was loaded into the process.
 */
enum class ModuleLoadReason : uint8_t {
    Unknown = 0,
    StaticImport = 1,         ///< Listed in import table
    DelayLoad = 2,            ///< Delay-loaded DLL
    LoadLibrary = 3,          ///< Explicit LoadLibrary call
    LoadLibraryEx = 4,        ///< LoadLibraryEx with flags
    Forwarded = 5,            ///< Forwarded from another DLL
    Injected = 6,             ///< Detected as injected
    ShimLoaded = 7,           ///< Loaded via application shim
    HookLoaded = 8,           ///< Loaded via SetWindowsHookEx
    AppInitLoaded = 9,        ///< AppInit_DLLs registry
    KnownDLLsOverride = 10,   ///< KnownDLLs override
    SideLoaded = 11,          ///< Suspicious side-loading
    ManifestLoaded = 12,      ///< Via SxS manifest
    CLRLoaded = 13,           ///< .NET CLR loaded assembly
    COMLoaded = 14,           ///< COM/OLE loaded
    Reflective = 15           ///< Reflectively loaded (no PEB entry)
};

/**
 * @enum ModuleSuspicionLevel
 * @brief Suspicion level for a loaded module.
 */
enum class ModuleSuspicionLevel : uint8_t {
    Trusted = 0,          ///< Microsoft-signed or whitelisted
    Normal = 1,           ///< Properly signed third-party
    Unknown = 2,          ///< No signature or reputation
    Suspicious = 3,       ///< Anomalies detected
    HighlySupicious = 4,  ///< Multiple red flags
    Malicious = 5         ///< Known malicious
};

/**
 * @enum HandleType
 * @brief Types of handles that can be enumerated.
 */
enum class HandleType : uint8_t {
    Unknown = 0,
    File = 1,
    Directory = 2,
    Key = 3,              ///< Registry key
    Mutant = 4,           ///< Mutex
    Event = 5,
    Semaphore = 6,
    Timer = 7,
    Section = 8,          ///< Memory-mapped file
    Port = 9,             ///< ALPC port
    Process = 10,
    Thread = 11,
    Token = 12,
    Job = 13,
    Desktop = 14,
    WindowStation = 15,
    IoCompletion = 16,
    TpWorkerFactory = 17,
    SymbolicLink = 18,
    FilterConnectionPort = 19,
    FilterCommunicationPort = 20,
    WaitCompletionPacket = 21,
    IRTimer = 22,
    DxgkSharedResource = 23,
    DxgkSharedSyncObject = 24,
    EtwRegistration = 25,
    DebugObject = 26,
    Callback = 27,
    Composition = 28,
    CoreMessaging = 29,
    RawInputManager = 30
};

/**
 * @enum HandleAccessPattern
 * @brief Suspicious patterns in handle access.
 */
enum class HandleAccessPattern : uint8_t {
    Normal = 0,
    ExcessiveFileHandles = 1,
    SensitiveFileAccess = 2,         ///< SAM, SECURITY, etc.
    SystemDirWriteAccess = 3,
    CrossProcessAccess = 4,           ///< PROCESS_ALL_ACCESS to other processes
    TokenManipulation = 5,
    PipeHijackRisk = 6,
    DebugObjectAccess = 7,
    DriverObjectAccess = 8,
    LsassAccess = 9,
    RegistryRunKeyAccess = 10,
    CredentialFileAccess = 11,
    EventLogAccess = 12,
    AVProcessAccess = 13,
    SecurityToolAccess = 14
};

/**
 * @enum MemoryRegionType
 * @brief Classification of memory regions.
 */
enum class MemoryRegionType : uint8_t {
    Unknown = 0,
    ImageMain = 1,            ///< Main executable image
    ImageModule = 2,          ///< Loaded DLL
    Stack = 3,
    Heap = 4,
    PrivateData = 5,
    MappedFile = 6,
    MappedImage = 7,
    SharedMemory = 8,
    PEB = 9,
    TEB = 10,
    KnownDLLsSection = 11,
    RuntimeGenerated = 12,    ///< JIT compiled code
    Suspicious = 13
};

/**
 * @enum MemoryProtectionAnomaly
 * @brief Types of memory protection anomalies.
 */
enum class MemoryProtectionAnomaly : uint8_t {
    None = 0,
    RWX = 1,                          ///< Read-Write-Execute (rarely legitimate)
    UnbackedExecutable = 2,           ///< Executable without file backing
    ExecutableHeap = 3,               ///< Heap memory marked executable
    ExecutableStack = 4,              ///< Stack marked executable
    ModifiedImageSection = 5,         ///< Image section with unexpected protection
    HiddenExecutable = 6,             ///< Executable region hidden from queries
    GuardPageExecutable = 7,          ///< Guard page with execute permission
    ExecutableInTempPath = 8,         ///< Mapped executable from temp path
    ProtectionChanged = 9,            ///< VirtualProtect changed protection
    SuspiciousVADFlags = 10           ///< Unusual VAD flags
};

/**
 * @enum ThreadSuspicion
 * @brief Suspicion indicators for threads.
 */
enum class ThreadSuspicion : uint8_t {
    Normal = 0,
    UnbackedStartAddress = 1,         ///< Start address not in any module
    StartInRWX = 2,                   ///< Start address in RWX region
    SuspiciousCallStack = 3,          ///< Unbacked addresses in call stack
    APCQueued = 4,                    ///< Has queued APCs from other process
    HiddenThread = 5,                 ///< Thread hidden from enumeration
    AnomalousContext = 6,             ///< Suspicious thread context
    StartAtShellcode = 7,             ///< Start address matches shellcode pattern
    StartAtExportedFunction = 8,      ///< RemoteThread at LoadLibrary, etc.
    CrossSessionThread = 9,           ///< Thread in different session
    SuspiciousTiming = 10             ///< Created at suspicious time relative to process
};

/**
 * @enum SignatureStatus
 * @brief Digital signature validation status.
 */
enum class SignatureStatus : uint8_t {
    Unknown = 0,
    Valid = 1,                        ///< Valid Authenticode signature
    ValidCatalog = 2,                 ///< Valid via catalog signature
    Invalid = 3,                      ///< Signature present but invalid
    Expired = 4,                      ///< Certificate expired
    Revoked = 5,                      ///< Certificate revoked
    UntrustedRoot = 6,                ///< Untrusted root CA
    Unsigned = 7,                     ///< No signature present
    HashMismatch = 8,                 ///< File modified after signing
    SignatureNotVerified = 9,         ///< Could not verify (network error)
    TestSigned = 10,                  ///< Test signature only
    SelfSigned = 11,                  ///< Self-signed certificate
    TimestampInvalid = 12,
    WeakAlgorithm = 13                ///< MD5/SHA1 (deprecated)
};

/**
 * @enum CertificateTrust
 * @brief Trust level of the signing certificate.
 */
enum class CertificateTrust : uint8_t {
    Unknown = 0,
    Microsoft = 1,                    ///< Microsoft signed
    MicrosoftPartner = 2,             ///< Microsoft partner program
    KnownPublisher = 3,               ///< Well-known software publisher
    ExtendedValidation = 4,           ///< EV certificate
    StandardPublisher = 5,            ///< Standard code signing
    SelfSigned = 6,
    CompromisedIssuer = 7,            ///< Known compromised CA
    MalwareAssociated = 8             ///< Certificate used to sign malware
};

/**
 * @enum ParentChildAnomaly
 * @brief Types of parent-child relationship anomalies.
 */
enum class ParentChildAnomaly : uint8_t {
    Normal = 0,
    UnexpectedParent = 1,             ///< Process has wrong parent
    PPIDSpoofing = 2,                 ///< Parent PID was spoofed
    OrphanProcess = 3,                ///< Parent doesn't exist (not from boot)
    SessionMismatch = 4,              ///< Different session than parent
    IntegrityEscalation = 5,          ///< Higher integrity than parent
    CrossUserSpawn = 6,               ///< Spawned by different user
    DoubleExtension = 7,              ///< notepad.exe.exe pattern
    SuspiciousOfficeChild = 8,        ///< Office spawning cmd/powershell
    SuspiciousBrowserChild = 9,       ///< Browser spawning unexpected child
    SuspiciousScriptHost = 10,        ///< cscript/wscript spawning suspicious
    SuspiciousJavaChild = 11,
    SuspiciousPdfReaderChild = 12,
    LateralMovementIndicator = 13,    ///< Remote service starting process
    WMISpawnedProcess = 14,           ///< WMI provider spawning suspicious
    ScheduledTaskSpawn = 15           ///< Task scheduler unusual spawn
};

/**
 * @enum PrivilegeRisk
 * @brief Risk level associated with process privileges.
 */
enum class PrivilegeRisk : uint8_t {
    Normal = 0,
    Elevated = 1,                     ///< Running elevated (UAC)
    SystemAccount = 2,                ///< Running as SYSTEM
    DebugPrivilege = 3,               ///< SeDebugPrivilege enabled
    TcbPrivilege = 4,                 ///< SeTcbPrivilege (act as OS)
    AssignPrimaryToken = 5,           ///< Can assign tokens
    LoadDriver = 6,                   ///< Can load kernel drivers
    TakeOwnership = 7,                ///< Can take ownership of objects
    CreateToken = 8,                  ///< Can create tokens
    BackupRestore = 9,                ///< Backup/Restore privileges
    Impersonation = 10,               ///< Impersonating another user
    DelegationEnabled = 11            ///< Delegation token
};

/**
 * @enum AntiAnalysisIndicator
 * @brief Indicators of anti-analysis/anti-debugging behavior.
 */
enum class AntiAnalysisIndicator : uint8_t {
    None = 0,
    IsDebuggerPresent = 1,
    CheckRemoteDebugger = 2,
    NtQueryInformationProcess = 3,    ///< ProcessDebugPort query
    TimingCheck = 4,                  ///< RDTSC-based timing
    ExceptionHandlerCheck = 5,        ///< VEH/SEH debugging detection
    ParentProcessCheck = 6,           ///< Checking parent name
    HardwareBreakpointDetect = 7,     ///< DR register checks
    VMDetection = 8,                  ///< VM detection artifacts
    SandboxDetection = 9,             ///< Sandbox fingerprinting
    SleepAcceleration = 10,           ///< Detecting sleep patching
    HookDetection = 11,               ///< Checking for API hooks
    IntegrityCheck = 12,              ///< Self-integrity verification
    EnvironmentCheck = 13,            ///< Checking environment variables
    FilesystemArtifacts = 14          ///< Looking for analysis files
};

/**
 * @enum ProcessCategory
 * @brief Categorization of process type/purpose.
 */
enum class ProcessCategory : uint8_t {
    Unknown = 0,
    SystemCore = 1,               ///< Critical Windows process
    SystemService = 2,            ///< Windows service
    SecuritySoftware = 3,         ///< AV/EDR/Firewall
    Browser = 4,
    EmailClient = 5,
    Office = 6,
    Developer = 7,                ///< IDE, compiler, etc.
    SystemUtility = 8,            ///< certutil, bitsadmin, etc.
    ScriptHost = 9,               ///< powershell, cscript, python
    RemoteAccess = 10,            ///< RDP, SSH, remote tools
    NetworkTool = 11,             ///< ftp, curl, netcat
    ArchiveTool = 12,
    GameApplication = 13,
    MediaPlayer = 14,
    Installer = 15,
    UserApplication = 16,
    LOLBin = 17,                  ///< Living-off-the-land binary
    Malware = 18
};

/**
 * @enum NetworkBehavior
 * @brief Network-related behavioral indicators.
 */
enum class NetworkBehavior : uint8_t {
    None = 0,
    NoNetwork = 1,                ///< No network modules loaded
    BasicNetwork = 2,             ///< Standard network usage
    RawSocket = 3,                ///< Raw socket access
    DNSOverHttps = 4,             ///< DoH/DoT usage
    TorNetwork = 5,               ///< Tor connection indicators
    ProxyChaining = 6,            ///< Multiple proxy hops
    PortScanning = 7,             ///< Port scan behavior
    C2Beaconing = 8,              ///< C2 beacon pattern
    DataExfiltration = 9,         ///< Large outbound transfers
    UnusualPorts = 10,            ///< Non-standard ports
    EncryptedTraffic = 11,        ///< SSL/TLS to unusual hosts
    DNSTunneling = 12,
    ICMPTunneling = 13
};

// ============================================================================
// DATA STRUCTURES
// ============================================================================

/**
 * @struct ModuleInfo
 * @brief Comprehensive information about a loaded module.
 */
struct alignas(64) ModuleInfo {
    // Basic identification
    std::wstring moduleName;                          ///< DLL name (e.g., "kernel32.dll")
    std::wstring modulePath;                          ///< Full path
    std::wstring moduleDescription;                   ///< From version info
    std::wstring modulePublisher;                     ///< Signing publisher
    std::wstring moduleVersion;                       ///< File version
    std::wstring moduleProductName;                   ///< Product name

    // Memory layout
    uintptr_t baseAddress = 0;                        ///< Load address
    uintptr_t entryPoint = 0;                         ///< Entry point RVA
    uint32_t sizeOfImage = 0;                         ///< Size in memory
    uint32_t sizeOnDisk = 0;                          ///< File size
    uint32_t checksum = 0;                            ///< PE checksum
    uint32_t timeDateStamp = 0;                       ///< PE timestamp

    // Load information
    uint32_t loadOrderIndex = 0;                      ///< Order in load list
    std::chrono::system_clock::time_point loadTime;   ///< When loaded
    ModuleLoadReason loadReason = ModuleLoadReason::Unknown;
    bool isInitialized = false;                       ///< DLL_PROCESS_ATTACH completed

    // Security assessment
    SignatureStatus signatureStatus = SignatureStatus::Unknown;
    CertificateTrust certificateTrust = CertificateTrust::Unknown;
    ModuleSuspicionLevel suspicionLevel = ModuleSuspicionLevel::Unknown;
    uint32_t riskScore = 0;

    // Hashes for lookup
    std::array<uint8_t, 32> sha256Hash{};
    std::array<uint8_t, 16> md5Hash{};
    std::string imphash;                              ///< Import hash
    std::string fuzzyHash;                            ///< Fuzzy hash

    // Import/Export analysis
    uint32_t importCount = 0;
    uint32_t exportCount = 0;
    std::vector<std::string> suspiciousImports;       ///< Flagged imports
    std::vector<std::string> suspiciousExports;       ///< Flagged exports
    bool hasDelayLoads = false;
    bool hasTLSCallbacks = false;

    // Anomaly detection
    bool isPhantom = false;                           ///< Not in PEB but loaded
    bool isHidden = false;                            ///< Hidden from enumeration
    bool isTampered = false;                          ///< Headers modified
    bool hasUnlinkedExports = false;                  ///< Export table tampering
    bool hasSuspiciousRelocations = false;
    bool isInSuspiciousPath = false;                  ///< Temp, AppData, etc.
    bool isPotentialSideLoad = false;                 ///< Side-loading candidate
    bool hasHooks = false;                            ///< IAT/EAT hooks detected
    double sectionEntropy = 0.0;                      ///< Code section entropy

    // Threat intelligence
    bool isKnownMalicious = false;
    std::wstring threatName;                          ///< If malicious
    uint32_t threatIntelReputationScore = 0;          ///< 0-100

    // Comparison operators for sorting
    bool operator<(const ModuleInfo& other) const noexcept {
        return baseAddress < other.baseAddress;
    }
};

/**
 * @struct HandleInfo
 * @brief Information about an open handle.
 */
struct HandleInfo {
    uint64_t handleValue = 0;                         ///< Handle value
    HandleType type = HandleType::Unknown;
    std::wstring typeName;                            ///< NT object type name
    std::wstring objectName;                          ///< Object name/path
    uint32_t grantedAccess = 0;                       ///< Access mask
    uint32_t attributes = 0;                          ///< Handle attributes
    bool isInheritable = false;
    bool isProtectedFromClose = false;

    // For process/thread handles
    uint32_t targetPid = 0;
    uint32_t targetTid = 0;

    // Risk assessment
    HandleAccessPattern accessPattern = HandleAccessPattern::Normal;
    bool isSuspicious = false;
    std::wstring suspicionReason;
};

/**
 * @struct HandleSummary
 * @brief Summary of all handles for a process.
 */
struct HandleSummary {
    uint32_t totalHandles = 0;
    std::unordered_map<HandleType, uint32_t> countByType;
    std::vector<HandleInfo> suspiciousHandles;
    std::vector<HandleInfo> sensitiveFileAccess;
    std::vector<HandleInfo> crossProcessHandles;
    std::vector<HandleInfo> debugHandles;
    bool hasLsassAccess = false;
    bool hasSystemDirWrite = false;
    bool hasSensitiveRegAccess = false;
    bool hasAVProcessAccess = false;
};

/**
 * @struct MemoryRegionInfo
 * @brief Information about a memory region.
 */
struct MemoryRegionInfo {
    uintptr_t baseAddress = 0;
    size_t regionSize = 0;
    uint32_t protection = 0;                          ///< PAGE_* constants
    uint32_t initialProtection = 0;                   ///< Original protection
    uint32_t state = 0;                               ///< MEM_COMMIT, etc.
    uint32_t type = 0;                                ///< MEM_IMAGE, etc.

    MemoryRegionType regionType = MemoryRegionType::Unknown;
    std::wstring mappedFile;                          ///< If file-backed
    std::wstring moduleName;                          ///< If part of module

    // Anomaly detection
    std::vector<MemoryProtectionAnomaly> anomalies;
    bool isExecutable = false;
    bool isWritable = false;
    bool isRWX = false;
    bool isUnbacked = false;
    bool hasShellcodePatterns = false;
    bool hasPEHeader = false;
    double entropy = 0.0;

    // For suspicious regions
    std::array<uint8_t, 64> headerBytes{};            ///< First 64 bytes
    uint32_t riskScore = 0;
};

/**
 * @struct MemorySummary
 * @brief Summary of process memory layout.
 */
struct MemorySummary {
    size_t totalVirtualSize = 0;
    size_t totalCommittedSize = 0;
    size_t privateBytes = 0;
    size_t workingSetSize = 0;
    uint32_t regionCount = 0;

    // Executable regions
    uint32_t executableRegionCount = 0;
    uint32_t rwxRegionCount = 0;
    uint32_t unbackedExecRegionCount = 0;
    size_t totalExecutableSize = 0;

    // Detailed region info
    std::vector<MemoryRegionInfo> suspiciousRegions;
    std::vector<MemoryRegionInfo> rwxRegions;
    std::vector<MemoryRegionInfo> unbackedExecutable;
    std::vector<MemoryRegionInfo> highEntropyRegions;

    // Overall assessment
    uint32_t memoryRiskScore = 0;
    std::vector<std::wstring> anomalyDescriptions;
};

/**
 * @struct ThreadInfo
 * @brief Information about a thread.
 */
struct ThreadInfo {
    uint32_t threadId = 0;
    uint32_t ownerPid = 0;
    uintptr_t startAddress = 0;
    uintptr_t currentIP = 0;                          ///< Current instruction pointer
    uintptr_t stackBase = 0;
    uintptr_t stackLimit = 0;
    uintptr_t tebAddress = 0;

    // State
    uint32_t state = 0;                               ///< THREAD_STATE
    uint32_t waitReason = 0;
    int32_t priority = 0;
    int32_t basePriority = 0;
    uint64_t kernelTime = 0;
    uint64_t userTime = 0;
    std::chrono::system_clock::time_point createTime;

    // Module context
    std::wstring startAddressModule;                  ///< Module containing start address
    std::wstring startAddressSymbol;                  ///< Symbol name if available
    bool isStartAddressBacked = true;                 ///< In a known module

    // Suspicion assessment
    ThreadSuspicion suspicion = ThreadSuspicion::Normal;
    uint32_t riskScore = 0;
    std::wstring suspicionReason;

    // Call stack (optional, expensive)
    std::vector<uintptr_t> callStack;
    std::vector<std::wstring> callStackSymbols;
    uint32_t unbackedCallStackFrames = 0;
};

/**
 * @struct ThreadSummary
 * @brief Summary of all threads in a process.
 */
struct ThreadSummary {
    uint32_t totalThreads = 0;
    uint32_t runningThreads = 0;
    uint32_t waitingThreads = 0;
    uint32_t suspendedThreads = 0;
    std::vector<ThreadInfo> allThreads;
    std::vector<ThreadInfo> suspiciousThreads;
    uint32_t unbackedStartCount = 0;
    uint32_t rwxStartCount = 0;
    uint32_t threadRiskScore = 0;
};

/**
 * @struct SignatureInfo
 * @brief Digital signature information.
 */
struct SignatureInfo {
    SignatureStatus status = SignatureStatus::Unknown;
    CertificateTrust trustLevel = CertificateTrust::Unknown;

    // Signer information
    std::wstring signerName;
    std::wstring issuerName;
    std::wstring subjectName;
    std::string serialNumber;
    std::string thumbprint;
    std::chrono::system_clock::time_point validFrom;
    std::chrono::system_clock::time_point validTo;
    std::chrono::system_clock::time_point signatureTime;

    // Certificate chain
    std::vector<std::wstring> certificateChain;
    bool isChainComplete = false;
    bool isChainTrusted = false;

    // Validation details
    bool isTimestamped = false;
    bool isCounterSigned = false;
    std::wstring hashAlgorithm;                       ///< SHA256, SHA1, etc.
    uint32_t signatureHashAlgorithm = 0;

    // Threat intel
    bool isCompromisedCert = false;
    bool isKnownMalwareSigner = false;
    std::wstring compromiseReason;
};

/**
 * @struct SecurityContext
 * @brief Security context information for a process.
 */
struct SecurityContext {
    // Token information
    std::wstring userName;
    std::wstring domainName;
    std::wstring fullUserName;
    std::array<uint8_t, 68> userSid{};                ///< Raw SID
    std::wstring sidString;
    uint32_t sessionId = 0;
    bool isElevated = false;
    uint32_t integrityLevel = 0;                      ///< SECURITY_MANDATORY_*
    std::wstring integrityLevelName;

    // Token type
    bool isPrimaryToken = true;
    bool isImpersonating = false;
    uint32_t impersonationLevel = 0;
    bool isDelegation = false;

    // Privileges
    std::vector<std::pair<std::wstring, bool>> privileges; ///< name, enabled
    std::vector<std::wstring> enabledPrivileges;
    std::vector<std::wstring> dangerousPrivileges;
    PrivilegeRisk privilegeRisk = PrivilegeRisk::Normal;

    // Groups
    std::vector<std::wstring> groupMemberships;
    bool isAdministrator = false;
    bool isSystem = false;
    bool isService = false;
    bool isNetworkService = false;
    bool isLocalService = false;

    // Security flags
    bool isProtectedProcess = false;
    bool isProtectedProcessLight = false;
    bool isAppContainer = false;
    std::wstring appContainerSid;
    bool hasSecurityTokenRestrictions = false;

    // Risk assessment
    uint32_t securityRiskScore = 0;
};

/**
 * @struct ParentChildAnalysis
 * @brief Analysis of parent-child relationship.
 */
struct ParentChildAnalysis {
    // Parent information
    uint32_t parentPid = 0;
    std::wstring parentPath;
    std::wstring parentName;
    std::wstring parentCommandLine;
    std::chrono::system_clock::time_point parentStartTime;
    bool parentExists = false;

    // Relationship validation
    ParentChildAnomaly anomaly = ParentChildAnomaly::Normal;
    bool isExpectedParent = true;
    std::wstring expectedParentName;                  ///< What parent should be
    bool isPPIDSpoofed = false;
    uint32_t realParentPid = 0;                       ///< If spoofed

    // Creation context
    uint32_t creatorPid = 0;                          ///< May differ from parent
    std::wstring creatorName;
    bool isRemotelyCreated = false;                   ///< Created by remote thread
    bool isWMICreated = false;                        ///< WMI provider spawned
    bool isServiceCreated = false;                    ///< Service control manager
    bool isScheduledTaskCreated = false;

    // Ancestry chain (for behavioral context)
    std::vector<Utils::ProcessUtils::ProcessBasicInfo> ancestry;
    uint32_t ancestryDepth = 0;
    std::vector<std::wstring> ancestryNames;

    // Risk assessment
    uint32_t relationshipRiskScore = 0;
    std::vector<std::wstring> anomalyReasons;
};

/**
 * @struct NetworkFootprint
 * @brief Network-related process information.
 */
struct NetworkFootprint {
    // Network modules
    bool hasNetworkModules = false;
    bool hasWs2_32 = false;
    bool hasWinInet = false;
    bool hasWinHttp = false;
    bool hasWinsock = false;
    bool hasRawSocket = false;

    // Active connections
    uint32_t tcpConnectionCount = 0;
    uint32_t udpEndpointCount = 0;
    uint32_t listeningPortCount = 0;

    struct ConnectionInfo {
        std::wstring localAddress;
        uint16_t localPort = 0;
        std::wstring remoteAddress;
        uint16_t remotePort = 0;
        std::wstring state;
        std::chrono::system_clock::time_point createTime;
    };
    std::vector<ConnectionInfo> activeConnections;
    std::vector<uint16_t> listeningPorts;

    // DNS activity (from cache correlation)
    std::vector<std::wstring> resolvedDomains;

    // Behavioral assessment
    NetworkBehavior behavior = NetworkBehavior::None;
    bool hasExternalConnections = false;
    bool hasUnusualPorts = false;
    bool hasSuspiciousDestinations = false;
    std::vector<std::wstring> suspiciousDestinations;
    uint32_t networkRiskScore = 0;
};

/**
 * @struct BehavioralIndicators
 * @brief Runtime behavioral indicators.
 */
struct BehavioralIndicators {
    // Anti-analysis
    std::vector<AntiAnalysisIndicator> antiAnalysis;
    bool hasDebuggerDetection = false;
    bool hasVMDetection = false;
    bool hasSandboxDetection = false;

    // Code injection indicators
    bool hasRemoteThreads = false;
    bool hasAPCsQueued = false;
    bool hasModifiedOtherProcesses = false;
    bool hasSuspiciousMemoryOperations = false;

    // Persistence indicators
    bool hasRegistryPersistence = false;
    bool hasScheduledTask = false;
    bool hasServiceInstall = false;
    bool hasStartupModification = false;
    bool hasWMIPersistence = false;

    // Defense evasion
    bool hasProcessHollowing = false;
    bool hasUnhooking = false;
    bool hasNtdllRemapping = false;
    bool hasDirectSyscalls = false;
    bool hasAMSIBypass = false;
    bool hasETWBypass = false;

    // Data collection
    bool hasKeyloggerIndicators = false;
    bool hasScreenCaptureIndicators = false;
    bool hasClipboardAccess = false;
    bool hasCredentialAccess = false;
    bool hasBrowserDataAccess = false;

    // Overall assessment
    uint32_t behaviorRiskScore = 0;
    std::vector<std::wstring> indicatorDescriptions;
};

/**
 * @struct ProcessAnalysisResult
 * @brief Complete analysis result for a process.
 */
struct alignas(64) ProcessAnalysisResult {
    // Target process identification
    uint32_t processId = 0;
    std::wstring processName;
    std::wstring processPath;
    std::wstring commandLine;
    std::chrono::system_clock::time_point startTime;
    std::chrono::system_clock::time_point analysisTime;
    AnalysisDepth analysisDepth = AnalysisDepth::Standard;

    // Overall assessment
    ProcessRiskLevel riskLevel = ProcessRiskLevel::Unknown;
    uint32_t overallRiskScore = 0;                    ///< 0-100
    ProcessCategory category = ProcessCategory::Unknown;
    bool isWhitelisted = false;
    bool isKnownMalicious = false;
    std::wstring threatName;                          ///< If malicious

    // Process classification
    bool isSystemProcess = false;
    bool isCriticalProcess = false;                   ///< Cannot be terminated
    bool isSecuritySoftware = false;
    bool isLOLBin = false;

    // Main image signature
    SignatureInfo signatureInfo;

    // Module analysis
    uint32_t loadedModuleCount = 0;
    uint32_t suspiciousModuleCount = 0;
    uint32_t unsignedModuleCount = 0;
    std::vector<ModuleInfo> modules;
    std::vector<ModuleInfo> suspiciousModules;

    // Handle analysis
    HandleSummary handleSummary;

    // Memory analysis
    MemorySummary memorySummary;

    // Thread analysis
    ThreadSummary threadSummary;

    // Security context
    SecurityContext securityContext;

    // Parent-child relationship
    ParentChildAnalysis parentChildAnalysis;

    // Network footprint
    NetworkFootprint networkFootprint;

    // Behavioral indicators
    BehavioralIndicators behavioralIndicators;

    // Hash lookups
    bool hashChecked = false;
    bool hashFoundMalicious = false;
    bool hashFoundClean = false;
    uint32_t reputationScore = 0;                     ///< From ThreatIntel (0-100)

    // Analysis metadata
    uint32_t analysisDurationMs = 0;
    bool analysisComplete = false;
    std::wstring analysisError;

    // Aggregated findings
    std::vector<std::wstring> criticalFindings;
    std::vector<std::wstring> warnings;
    std::vector<std::wstring> informationalFindings;

    // MITRE ATT&CK mappings
    std::vector<std::string> mitreAttackTechniques;

    /**
     * @brief Calculate final risk score from all components.
     */
    void CalculateOverallRisk() noexcept;
};

/**
 * @struct AnalyzerConfig
 * @brief Configuration for process analysis.
 */
struct AnalyzerConfig {
    // Analysis scope
    AnalysisDepth defaultDepth = AnalysisDepth::Standard;
    bool enableModuleAnalysis = true;
    bool enableHandleAnalysis = true;
    bool enableMemoryAnalysis = true;
    bool enableThreadAnalysis = true;
    bool enableNetworkAnalysis = true;
    bool enableBehavioralAnalysis = true;
    bool enableSignatureVerification = true;
    bool enableThreatIntelLookup = true;

    // Performance tuning
    uint32_t maxModulesToAnalyze = AnalyzerConstants::MAX_MODULES_TO_ANALYZE;
    uint32_t maxHandlesToEnumerate = AnalyzerConstants::MAX_HANDLES_TO_ENUMERATE;
    uint32_t maxThreadsToAnalyze = AnalyzerConstants::MAX_THREADS_TO_ANALYZE;
    uint32_t maxMemoryRegions = AnalyzerConstants::MAX_MEMORY_REGIONS;

    // Timeouts
    uint32_t signatureCheckTimeoutMs = AnalyzerConstants::SIGNATURE_CHECK_TIMEOUT_MS;
    uint32_t handleEnumTimeoutMs = AnalyzerConstants::HANDLE_ENUM_TIMEOUT_MS;
    uint32_t memoryScanTimeoutMs = AnalyzerConstants::MEMORY_SCAN_TIMEOUT_MS;

    // Thresholds
    double highEntropyThreshold = AnalyzerConstants::HIGH_ENTROPY_THRESHOLD;
    uint32_t suspiciousHandleCountThreshold = AnalyzerConstants::SUSPICIOUS_HANDLE_COUNT_THRESHOLD;
    uint32_t suspiciousThreadCountThreshold = AnalyzerConstants::SUSPICIOUS_THREAD_COUNT_THRESHOLD;

    // Risk scoring
    bool enableRiskScoring = true;
    uint32_t riskWeightUnsigned = AnalyzerConstants::RISK_WEIGHT_UNSIGNED;
    uint32_t riskWeightParentAnomaly = AnalyzerConstants::RISK_WEIGHT_PARENT_ANOMALY;
    uint32_t riskWeightRWXMemory = AnalyzerConstants::RISK_WEIGHT_RWX_MEMORY;

    // Caching
    bool enableAnalysisCache = true;
    size_t analysisCacheSize = AnalyzerConstants::ANALYSIS_CACHE_SIZE;
    uint32_t analysisCacheTTLSeconds = AnalyzerConstants::ANALYSIS_CACHE_TTL_SECONDS;
    bool enableSignatureCache = true;
    size_t signatureCacheSize = AnalyzerConstants::SIGNATURE_CACHE_SIZE;

    // Exceptions
    std::vector<std::wstring> excludedProcesses;      ///< Never analyze these
    std::vector<std::wstring> excludedPaths;          ///< Skip modules from these paths

    // Callbacks
    bool enableProgressCallbacks = false;

    /**
     * @brief Create default configuration.
     */
    static AnalyzerConfig CreateDefault() noexcept;

    /**
     * @brief Create configuration for quick analysis.
     */
    static AnalyzerConfig CreateQuick() noexcept;

    /**
     * @brief Create configuration for deep forensic analysis.
     */
    static AnalyzerConfig CreateForensic() noexcept;

    /**
     * @brief Create configuration optimized for real-time scanning.
     */
    static AnalyzerConfig CreateRealTime() noexcept;
};

/**
 * @struct AnalyzerStatistics
 * @brief Runtime statistics for the analyzer.
 */
struct alignas(64) AnalyzerStatistics {
    // Analysis counts
    std::atomic<uint64_t> totalAnalyses{0};
    std::atomic<uint64_t> quickAnalyses{0};
    std::atomic<uint64_t> standardAnalyses{0};
    std::atomic<uint64_t> deepAnalyses{0};
    std::atomic<uint64_t> forensicAnalyses{0};

    // Results
    std::atomic<uint64_t> trustedProcesses{0};
    std::atomic<uint64_t> safeProcesses{0};
    std::atomic<uint64_t> unknownProcesses{0};
    std::atomic<uint64_t> suspiciousProcesses{0};
    std::atomic<uint64_t> maliciousProcesses{0};

    // Component analysis
    std::atomic<uint64_t> modulesAnalyzed{0};
    std::atomic<uint64_t> handlesEnumerated{0};
    std::atomic<uint64_t> memoryRegionsScanned{0};
    std::atomic<uint64_t> threadsAnalyzed{0};
    std::atomic<uint64_t> signaturesVerified{0};

    // Detections
    std::atomic<uint64_t> unsignedModulesDetected{0};
    std::atomic<uint64_t> suspiciousModulesDetected{0};
    std::atomic<uint64_t> rwxRegionsDetected{0};
    std::atomic<uint64_t> unbackedExecDetected{0};
    std::atomic<uint64_t> suspiciousThreadsDetected{0};
    std::atomic<uint64_t> parentAnomaliesDetected{0};
    std::atomic<uint64_t> ppidSpoofingDetected{0};
    std::atomic<uint64_t> injectionIndicatorsDetected{0};

    // Cache performance
    std::atomic<uint64_t> analysisCacheHits{0};
    std::atomic<uint64_t> analysisCacheMisses{0};
    std::atomic<uint64_t> signatureCacheHits{0};
    std::atomic<uint64_t> signatureCacheMisses{0};

    // Performance
    std::atomic<uint64_t> totalAnalysisTimeMs{0};
    std::atomic<uint64_t> minAnalysisTimeMs{UINT64_MAX};
    std::atomic<uint64_t> maxAnalysisTimeMs{0};

    // Errors
    std::atomic<uint64_t> analysisErrors{0};
    std::atomic<uint64_t> accessDeniedErrors{0};
    std::atomic<uint64_t> timeoutErrors{0};

    /**
     * @brief Reset all statistics.
     */
    void Reset() noexcept;

    /**
     * @brief Get average analysis time.
     */
    double GetAverageAnalysisTimeMs() const noexcept;

    /**
     * @brief Get cache hit ratio.
     */
    double GetAnalysisCacheHitRatio() const noexcept;
};

// ============================================================================
// CALLBACK DEFINITIONS
// ============================================================================

/**
 * @brief Callback for analysis progress updates.
 * @param pid Process being analyzed
 * @param stage Current analysis stage description
 * @param percentComplete 0-100
 */
using AnalysisProgressCallback = std::function<void(
    uint32_t pid,
    const std::wstring& stage,
    uint32_t percentComplete
)>;

/**
 * @brief Callback for suspicious finding during analysis.
 * @param pid Process ID
 * @param finding Description of the finding
 * @param riskScore Risk score for this finding (0-100)
 */
using SuspiciousFindingCallback = std::function<void(
    uint32_t pid,
    const std::wstring& finding,
    uint32_t riskScore
)>;

/**
 * @brief Callback for module analysis completion.
 * @param pid Process ID
 * @param module The analyzed module
 */
using ModuleAnalyzedCallback = std::function<void(
    uint32_t pid,
    const ModuleInfo& module
)>;

// ============================================================================
// PROCESS ANALYZER CLASS
// ============================================================================

/**
 * @class ProcessAnalyzer
 * @brief Comprehensive process analysis engine.
 *
 * Thread-safety: All public methods are thread-safe.
 * Pattern: Singleton with PIMPL for ABI stability.
 *
 * Usage:
 * @code
 * auto& analyzer = ProcessAnalyzer::Instance();
 * 
 * // Quick analysis
 * auto risk = analyzer.QuickAssessRisk(targetPid);
 * if (risk >= ProcessRiskLevel::Suspicious) {
 *     // Perform deeper analysis
 *     auto result = analyzer.AnalyzeProcess(targetPid, AnalysisDepth::Deep);
 *     // Handle result...
 * }
 * @endcode
 */
class ProcessAnalyzer {
public:
    // ========================================================================
    // SINGLETON ACCESS
    // ========================================================================

    /**
     * @brief Get singleton instance.
     * @return Reference to the singleton instance.
     */
    [[nodiscard]] static ProcessAnalyzer& Instance();

    /**
     * @brief Delete copy constructor.
     */
    ProcessAnalyzer(const ProcessAnalyzer&) = delete;

    /**
     * @brief Delete copy assignment.
     */
    ProcessAnalyzer& operator=(const ProcessAnalyzer&) = delete;

    /**
     * @brief Delete move constructor.
     */
    ProcessAnalyzer(ProcessAnalyzer&&) = delete;

    /**
     * @brief Delete move assignment.
     */
    ProcessAnalyzer& operator=(ProcessAnalyzer&&) = delete;

    // ========================================================================
    // LIFECYCLE MANAGEMENT
    // ========================================================================

    /**
     * @brief Initialize the analyzer with configuration.
     * @param config Configuration settings.
     * @return True if initialization succeeded.
     */
    [[nodiscard]] bool Initialize(const AnalyzerConfig& config = AnalyzerConfig::CreateDefault());

    /**
     * @brief Shutdown the analyzer and release resources.
     */
    void Shutdown();

    /**
     * @brief Check if analyzer is initialized.
     * @return True if ready for analysis.
     */
    [[nodiscard]] bool IsInitialized() const noexcept;

    /**
     * @brief Update configuration (hot reload).
     * @param config New configuration.
     * @return True if configuration was applied.
     */
    bool UpdateConfig(const AnalyzerConfig& config);

    /**
     * @brief Get current configuration.
     * @return Current configuration.
     */
    [[nodiscard]] AnalyzerConfig GetConfig() const;

    // ========================================================================
    // COMPREHENSIVE ANALYSIS
    // ========================================================================

    /**
     * @brief Perform comprehensive analysis of a process.
     * @param pid Process ID to analyze.
     * @param depth Analysis depth level.
     * @return Complete analysis result.
     */
    [[nodiscard]] ProcessAnalysisResult AnalyzeProcess(
        uint32_t pid,
        AnalysisDepth depth = AnalysisDepth::Standard
    );

    /**
     * @brief Analyze process by path (find and analyze).
     * @param processPath Path to the executable.
     * @param depth Analysis depth level.
     * @return Analysis results for all matching processes.
     */
    [[nodiscard]] std::vector<ProcessAnalysisResult> AnalyzeByPath(
        const std::wstring& processPath,
        AnalysisDepth depth = AnalysisDepth::Standard
    );

    /**
     * @brief Analyze process by name (all instances).
     * @param processName Process name (e.g., "notepad.exe").
     * @param depth Analysis depth level.
     * @return Analysis results for all matching processes.
     */
    [[nodiscard]] std::vector<ProcessAnalysisResult> AnalyzeByName(
        const std::wstring& processName,
        AnalysisDepth depth = AnalysisDepth::Standard
    );

    /**
     * @brief Analyze multiple processes in parallel.
     * @param pids Process IDs to analyze.
     * @param depth Analysis depth level.
     * @param maxConcurrent Maximum concurrent analyses.
     * @return Analysis results for all processes.
     */
    [[nodiscard]] std::vector<ProcessAnalysisResult> AnalyzeMultiple(
        const std::vector<uint32_t>& pids,
        AnalysisDepth depth = AnalysisDepth::Standard,
        uint32_t maxConcurrent = 4
    );

    // ========================================================================
    // QUICK ASSESSMENT (FAST PATH)
    // ========================================================================

    /**
     * @brief Quickly assess risk level without full analysis.
     * @param pid Process ID.
     * @return Risk level assessment.
     *
     * This performs only essential checks:
     * - Whitelist lookup
     * - Hash lookup
     * - Signature verification
     * - Basic parent validation
     */
    [[nodiscard]] ProcessRiskLevel QuickAssessRisk(uint32_t pid);

    /**
     * @brief Check if process is whitelisted.
     * @param pid Process ID.
     * @return True if whitelisted.
     */
    [[nodiscard]] bool IsWhitelisted(uint32_t pid);

    /**
     * @brief Check if process is known malicious.
     * @param pid Process ID.
     * @return True if known malicious, with optional threat name.
     */
    [[nodiscard]] std::pair<bool, std::wstring> IsKnownMalicious(uint32_t pid);

    /**
     * @brief Get process category classification.
     * @param pid Process ID.
     * @return Process category.
     */
    [[nodiscard]] ProcessCategory CategorizeProcess(uint32_t pid);

    // ========================================================================
    // MODULE ANALYSIS
    // ========================================================================

    /**
     * @brief Get all loaded modules for a process.
     * @param pid Process ID.
     * @return Vector of module information.
     */
    [[nodiscard]] std::vector<ModuleInfo> GetLoadedModules(uint32_t pid);

    /**
     * @brief Analyze a specific module.
     * @param pid Process ID.
     * @param moduleBase Base address of the module.
     * @return Detailed module information.
     */
    [[nodiscard]] std::optional<ModuleInfo> AnalyzeModule(
        uint32_t pid,
        uintptr_t moduleBase
    );

    /**
     * @brief Find suspicious modules in a process.
     * @param pid Process ID.
     * @return Vector of suspicious modules.
     */
    [[nodiscard]] std::vector<ModuleInfo> FindSuspiciousModules(uint32_t pid);

    /**
     * @brief Detect phantom/hidden modules not in PEB.
     * @param pid Process ID.
     * @return Vector of phantom modules.
     */
    [[nodiscard]] std::vector<ModuleInfo> DetectPhantomModules(uint32_t pid);

    /**
     * @brief Detect potential side-loaded DLLs.
     * @param pid Process ID.
     * @return Vector of side-loaded DLL candidates.
     */
    [[nodiscard]] std::vector<ModuleInfo> DetectSideLoadedDLLs(uint32_t pid);

    /**
     * @brief Compare module in memory vs on disk.
     * @param pid Process ID.
     * @param moduleBase Base address of the module.
     * @return True if module matches disk image.
     */
    [[nodiscard]] bool ValidateModuleIntegrity(
        uint32_t pid,
        uintptr_t moduleBase
    );

    // ========================================================================
    // HANDLE ANALYSIS
    // ========================================================================

    /**
     * @brief Enumerate all handles for a process.
     * @param pid Process ID.
     * @return Handle summary with suspicious handles flagged.
     */
    [[nodiscard]] HandleSummary EnumerateHandles(uint32_t pid);

    /**
     * @brief Get handles of a specific type.
     * @param pid Process ID.
     * @param type Handle type to filter.
     * @return Vector of matching handles.
     */
    [[nodiscard]] std::vector<HandleInfo> GetHandlesByType(
        uint32_t pid,
        HandleType type
    );

    /**
     * @brief Check for suspicious handle access patterns.
     * @param pid Process ID.
     * @return Vector of suspicious handles with reasons.
     */
    [[nodiscard]] std::vector<HandleInfo> FindSuspiciousHandles(uint32_t pid);

    /**
     * @brief Check if process has handles to sensitive processes.
     * @param pid Process ID.
     * @return True if has suspicious cross-process handles.
     */
    [[nodiscard]] bool HasCrossProcessHandles(uint32_t pid);

    /**
     * @brief Check if process has handles to LSASS.
     * @param pid Process ID.
     * @return True if has LSASS access.
     */
    [[nodiscard]] bool HasLsassAccess(uint32_t pid);

    // ========================================================================
    // MEMORY ANALYSIS
    // ========================================================================

    /**
     * @brief Analyze process memory layout.
     * @param pid Process ID.
     * @return Memory summary with anomalies flagged.
     */
    [[nodiscard]] MemorySummary AnalyzeMemory(uint32_t pid);

    /**
     * @brief Get all memory regions for a process.
     * @param pid Process ID.
     * @return Vector of memory region information.
     */
    [[nodiscard]] std::vector<MemoryRegionInfo> GetMemoryRegions(uint32_t pid);

    /**
     * @brief Find RWX (read-write-execute) memory regions.
     * @param pid Process ID.
     * @return Vector of RWX regions.
     */
    [[nodiscard]] std::vector<MemoryRegionInfo> FindRWXRegions(uint32_t pid);

    /**
     * @brief Find executable memory not backed by files.
     * @param pid Process ID.
     * @return Vector of unbacked executable regions.
     */
    [[nodiscard]] std::vector<MemoryRegionInfo> FindUnbackedExecutable(uint32_t pid);

    /**
     * @brief Find regions with high entropy (potential packed code).
     * @param pid Process ID.
     * @param threshold Entropy threshold (default: 7.2).
     * @return Vector of high-entropy regions.
     */
    [[nodiscard]] std::vector<MemoryRegionInfo> FindHighEntropyRegions(
        uint32_t pid,
        double threshold = AnalyzerConstants::HIGH_ENTROPY_THRESHOLD
    );

    /**
     * @brief Check if a memory address is backed by a module.
     * @param pid Process ID.
     * @param address Memory address to check.
     * @return Optional module info if backed.
     */
    [[nodiscard]] std::optional<ModuleInfo> GetBackingModule(
        uint32_t pid,
        uintptr_t address
    );

    // ========================================================================
    // THREAD ANALYSIS
    // ========================================================================

    /**
     * @brief Analyze all threads in a process.
     * @param pid Process ID.
     * @return Thread summary with suspicious threads flagged.
     */
    [[nodiscard]] ThreadSummary AnalyzeThreads(uint32_t pid);

    /**
     * @brief Get detailed information about a specific thread.
     * @param tid Thread ID.
     * @return Thread information.
     */
    [[nodiscard]] std::optional<ThreadInfo> GetThreadInfo(uint32_t tid);

    /**
     * @brief Find threads with unbacked start addresses.
     * @param pid Process ID.
     * @return Vector of suspicious threads.
     */
    [[nodiscard]] std::vector<ThreadInfo> FindUnbackedThreads(uint32_t pid);

    /**
     * @brief Get call stack for a thread.
     * @param tid Thread ID.
     * @param maxFrames Maximum stack frames to capture.
     * @return Thread info with call stack populated.
     */
    [[nodiscard]] std::optional<ThreadInfo> GetThreadCallStack(
        uint32_t tid,
        uint32_t maxFrames = 64
    );

    /**
     * @brief Validate that thread start addresses are in valid modules.
     * @param pid Process ID.
     * @return True if all threads have valid start addresses.
     */
    [[nodiscard]] bool ValidateThreadStartAddresses(uint32_t pid);

    // ========================================================================
    // SIGNATURE VERIFICATION
    // ========================================================================

    /**
     * @brief Verify digital signature of process image.
     * @param pid Process ID.
     * @return Signature information.
     */
    [[nodiscard]] SignatureInfo VerifyProcessSignature(uint32_t pid);

    /**
     * @brief Verify digital signature of a file.
     * @param filePath Path to the file.
     * @return Signature information.
     */
    [[nodiscard]] SignatureInfo VerifyFileSignature(const std::wstring& filePath);

    /**
     * @brief Check if process image is signed by Microsoft.
     * @param pid Process ID.
     * @return True if Microsoft-signed.
     */
    [[nodiscard]] bool IsMicrosoftSigned(uint32_t pid);

    /**
     * @brief Check if process image is properly signed.
     * @param pid Process ID.
     * @return True if has valid signature.
     */
    [[nodiscard]] bool IsImageSigned(uint32_t pid);

    /**
     * @brief Check if certificate is known to be compromised.
     * @param thumbprint Certificate thumbprint.
     * @return True if compromised.
     */
    [[nodiscard]] bool IsCertificateCompromised(const std::string& thumbprint);

    // ========================================================================
    // SECURITY CONTEXT ANALYSIS
    // ========================================================================

    /**
     * @brief Analyze process security context (token, privileges).
     * @param pid Process ID.
     * @return Security context information.
     */
    [[nodiscard]] SecurityContext AnalyzeSecurityContext(uint32_t pid);

    /**
     * @brief Get process privileges.
     * @param pid Process ID.
     * @return Vector of privilege names and their enabled state.
     */
    [[nodiscard]] std::vector<std::pair<std::wstring, bool>> GetProcessPrivileges(
        uint32_t pid
    );

    /**
     * @brief Check if process has dangerous privileges enabled.
     * @param pid Process ID.
     * @return Vector of dangerous privilege names that are enabled.
     */
    [[nodiscard]] std::vector<std::wstring> GetDangerousPrivileges(uint32_t pid);

    /**
     * @brief Get process integrity level.
     * @param pid Process ID.
     * @return Integrity level (SECURITY_MANDATORY_*).
     */
    [[nodiscard]] uint32_t GetIntegrityLevel(uint32_t pid);

    /**
     * @brief Check if process is running elevated.
     * @param pid Process ID.
     * @return True if elevated.
     */
    [[nodiscard]] bool IsElevated(uint32_t pid);

    /**
     * @brief Check if process is impersonating another user.
     * @param pid Process ID.
     * @return True if impersonating.
     */
    [[nodiscard]] bool IsImpersonating(uint32_t pid);

    // ========================================================================
    // PARENT-CHILD ANALYSIS
    // ========================================================================

    /**
     * @brief Analyze parent-child relationship.
     * @param pid Process ID.
     * @return Parent-child analysis result.
     */
    [[nodiscard]] ParentChildAnalysis AnalyzeParentChild(uint32_t pid);

    /**
     * @brief Validate if parent is expected for a process.
     * @param pid Process ID.
     * @return True if parent is expected/normal.
     */
    [[nodiscard]] bool ValidateParentAnomaly(uint32_t pid);

    /**
     * @brief Detect PPID spoofing.
     * @param pid Process ID.
     * @return True if PPID appears spoofed.
     */
    [[nodiscard]] bool DetectPPIDSpoofing(uint32_t pid);

    /**
     * @brief Get full process ancestry chain.
     * @param pid Process ID.
     * @param maxDepth Maximum ancestry depth.
     * @return Vector of ancestor process info.
     */
    [[nodiscard]] std::vector<Utils::ProcessUtils::ProcessBasicInfo> GetAncestry(
        uint32_t pid,
        uint32_t maxDepth = AnalyzerConstants::MAX_ANCESTRY_DEPTH
    );

    /**
     * @brief Get all child processes.
     * @param pid Process ID.
     * @param recursive Include all descendants.
     * @return Vector of child process info.
     */
    [[nodiscard]] std::vector<Utils::ProcessUtils::ProcessBasicInfo> GetChildren(
        uint32_t pid,
        bool recursive = false
    );

    // ========================================================================
    // NETWORK ANALYSIS
    // ========================================================================

    /**
     * @brief Analyze network footprint of a process.
     * @param pid Process ID.
     * @return Network footprint information.
     */
    [[nodiscard]] NetworkFootprint AnalyzeNetworkFootprint(uint32_t pid);

    /**
     * @brief Get active network connections for a process.
     * @param pid Process ID.
     * @return Vector of connection information.
     */
    [[nodiscard]] std::vector<NetworkFootprint::ConnectionInfo> GetConnections(
        uint32_t pid
    );

    /**
     * @brief Check if process has network capabilities.
     * @param pid Process ID.
     * @return True if has network modules loaded.
     */
    [[nodiscard]] bool HasNetworkCapability(uint32_t pid);

    /**
     * @brief Get listening ports for a process.
     * @param pid Process ID.
     * @return Vector of listening port numbers.
     */
    [[nodiscard]] std::vector<uint16_t> GetListeningPorts(uint32_t pid);

    // ========================================================================
    // BEHAVIORAL ANALYSIS
    // ========================================================================

    /**
     * @brief Analyze behavioral indicators.
     * @param pid Process ID.
     * @return Behavioral indicators summary.
     */
    [[nodiscard]] BehavioralIndicators AnalyzeBehavior(uint32_t pid);

    /**
     * @brief Detect anti-analysis techniques.
     * @param pid Process ID.
     * @return Vector of detected anti-analysis indicators.
     */
    [[nodiscard]] std::vector<AntiAnalysisIndicator> DetectAntiAnalysis(uint32_t pid);

    /**
     * @brief Check if process is being debugged.
     * @param pid Process ID.
     * @return True if debugger is attached.
     */
    [[nodiscard]] bool IsBeingDebugged(uint32_t pid);

    /**
     * @brief Detect process hollowing.
     * @param pid Process ID.
     * @return True if hollowing is detected.
     */
    [[nodiscard]] bool DetectProcessHollowing(uint32_t pid);

    /**
     * @brief Detect direct syscall usage.
     * @param pid Process ID.
     * @return True if direct syscalls detected.
     */
    [[nodiscard]] bool DetectDirectSyscalls(uint32_t pid);

    // ========================================================================
    // CALLBACK REGISTRATION
    // ========================================================================

    /**
     * @brief Register callback for analysis progress.
     * @param callback Progress callback function.
     * @return Callback ID for unregistration.
     */
    uint64_t RegisterProgressCallback(AnalysisProgressCallback callback);

    /**
     * @brief Register callback for suspicious findings.
     * @param callback Finding callback function.
     * @return Callback ID for unregistration.
     */
    uint64_t RegisterFindingCallback(SuspiciousFindingCallback callback);

    /**
     * @brief Register callback for module analysis completion.
     * @param callback Module analyzed callback function.
     * @return Callback ID for unregistration.
     */
    uint64_t RegisterModuleCallback(ModuleAnalyzedCallback callback);

    /**
     * @brief Unregister a callback.
     * @param callbackId ID returned from registration.
     */
    void UnregisterCallback(uint64_t callbackId);

    // ========================================================================
    // CACHE MANAGEMENT
    // ========================================================================

    /**
     * @brief Clear analysis cache.
     */
    void ClearAnalysisCache();

    /**
     * @brief Clear signature verification cache.
     */
    void ClearSignatureCache();

    /**
     * @brief Clear all caches.
     */
    void ClearAllCaches();

    /**
     * @brief Invalidate cache entry for a process.
     * @param pid Process ID.
     */
    void InvalidateCacheEntry(uint32_t pid);

    // ========================================================================
    // STATISTICS & DIAGNOSTICS
    // ========================================================================

    /**
     * @brief Get analyzer statistics.
     * @return Current statistics.
     */
    [[nodiscard]] AnalyzerStatistics GetStatistics() const;

    /**
     * @brief Reset statistics.
     */
    void ResetStatistics();

    /**
     * @brief Get analyzer version.
     * @return Version string.
     */
    [[nodiscard]] static std::wstring GetVersion() noexcept;

    // ========================================================================
    // UTILITY METHODS
    // ========================================================================

    /**
     * @brief Get path from process ID.
     * @param pid Process ID.
     * @return Process executable path.
     */
    [[nodiscard]] std::wstring GetProcessPath(uint32_t pid);

    /**
     * @brief Check if a process is a system process.
     * @param processName Process name.
     * @return True if recognized system process.
     */
    [[nodiscard]] static bool IsSystemProcess(const std::wstring& processName) noexcept;

    /**
     * @brief Check if a process is a critical process (cannot be terminated).
     * @param pid Process ID.
     * @return True if critical.
     */
    [[nodiscard]] bool IsCriticalProcess(uint32_t pid);

    /**
     * @brief Check if process is a Living-off-the-Land binary.
     * @param processPath Process path or name.
     * @return True if LOLBIN.
     */
    [[nodiscard]] static bool IsLOLBin(const std::wstring& processPath) noexcept;

    /**
     * @brief Convert risk level to string.
     * @param level Risk level.
     * @return String representation.
     */
    [[nodiscard]] static std::wstring RiskLevelToString(ProcessRiskLevel level) noexcept;

    /**
     * @brief Convert risk score (0-100) to risk level.
     * @param score Risk score.
     * @return Corresponding risk level.
     */
    [[nodiscard]] static ProcessRiskLevel ScoreToRiskLevel(uint32_t score) noexcept;

private:
    // ========================================================================
    // PRIVATE CONSTRUCTOR (SINGLETON)
    // ========================================================================

    ProcessAnalyzer();
    ~ProcessAnalyzer();

    // ========================================================================
    // IMPLEMENTATION
    // ========================================================================

    std::unique_ptr<ProcessAnalyzerImpl> m_impl;
};

} // namespace Process
} // namespace Core
} // namespace ShadowStrike
