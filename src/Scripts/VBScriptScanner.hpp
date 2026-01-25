/**
 * ============================================================================
 * ShadowStrike NGAV - VBSCRIPT SCANNER MODULE
 * ============================================================================
 *
 * @file VBScriptScanner.hpp
 * @brief Enterprise-grade VBScript malware analysis engine for detection of
 *        malicious Windows Script Host (WSH) threats.
 *
 * Provides comprehensive detection of VBScript-based malware including
 * obfuscated scripts, fileless attacks, and APT-style techniques.
 *
 * DETECTION CAPABILITIES:
 * =======================
 *
 * 1. DANGEROUS OBJECT DETECTION
 *    - WScript.Shell (command execution)
 *    - Scripting.FileSystemObject (file operations)
 *    - ADODB.Stream (binary file creation)
 *    - MSXML2.ServerXMLHTTP (network operations)
 *    - Shell.Application (process execution)
 *    - WMI access (WbemScripting)
 *    - PowerShell invocation
 *    - Registry manipulation
 *
 * 2. FILELESS ATTACK DETECTION
 *    - In-memory execution
 *    - WMI event subscription
 *    - Registry persistence
 *    - Scheduled task creation
 *    - COM object hijacking
 *
 * 3. OBFUSCATION DETECTION
 *    - String concatenation
 *    - Chr() encoding
 *    - Execute/ExecuteGlobal
 *    - Eval() chains
 *    - Variable substitution
 *    - Code splitting
 *
 * 4. PAYLOAD DELIVERY DETECTION
 *    - Download and execute
 *    - Base64 encoded payloads
 *    - PowerShell download cradles
 *    - certutil abuse
 *    - bitsadmin abuse
 *
 * 5. ENTERPRISE THREATS
 *    - APT-style VBS droppers
 *    - Ransomware downloaders
 *    - Email attachment attacks
 *    - HTA embedded VBScript
 *
 * INTEGRATION:
 * ============
 * - PatternStore for VBS patterns
 * - SignatureStore for malware signatures
 * - HashStore for known bad scripts
 * - ThreatIntel for IOC correlation
 * - AMSI for real-time scanning
 *
 * @note Legacy but still heavily used in enterprise environments.
 * @note Deprecated in Windows 11 24H2 but still present.
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
#include <unordered_set>
#include <set>
#include <optional>
#include <memory>
#include <functional>
#include <chrono>
#include <atomic>
#include <mutex>
#include <shared_mutex>
#include <span>
#include <filesystem>
#include <regex>

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
#include "../Utils/HashUtils.hpp"
#include "../Utils/FileUtils.hpp"
#include "../PatternStore/PatternStore.hpp"
#include "../SignatureStore/SignatureStore.hpp"
#include "../HashStore/HashStore.hpp"
#include "../ThreatIntel/ThreatIntelManager.hpp"

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

namespace ShadowStrike::Scripts {
    class VBScriptScannerImpl;
}

namespace ShadowStrike {
namespace Scripts {

// ============================================================================
// COMPILE-TIME CONSTANTS
// ============================================================================

namespace VBSConstants {

    inline constexpr uint32_t VERSION_MAJOR = 3;
    inline constexpr uint32_t VERSION_MINOR = 0;
    inline constexpr uint32_t VERSION_PATCH = 0;

    /// @brief Maximum script size (25 MB)
    inline constexpr size_t MAX_SCRIPT_SIZE = 25 * 1024 * 1024;
    
    /// @brief Maximum deobfuscation depth
    inline constexpr size_t MAX_DEOBFUSCATION_DEPTH = 50;
    
    /// @brief Chr() threshold for obfuscation
    inline constexpr size_t CHR_OBFUSCATION_THRESHOLD = 10;
    
    /// @brief Dangerous COM objects
    inline constexpr const char* DANGEROUS_OBJECTS[] = {
        "WScript.Shell",
        "Scripting.FileSystemObject",
        "ADODB.Stream",
        "MSXML2.ServerXMLHTTP",
        "MSXML2.XMLHTTP",
        "Microsoft.XMLHTTP",
        "Shell.Application",
        "WbemScripting.SWbemLocator",
        "Schedule.Service",
        "MMC20.Application",
        "Excel.Application",
        "Word.Application",
        "Outlook.Application",
        "WScript.Network",
        "Scripting.Dictionary",
        "InternetExplorer.Application"
    };

}  // namespace VBSConstants

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
 * @brief VBScript file type
 */
enum class VBSFileType : uint8_t {
    Unknown     = 0,
    VBS         = 1,    ///< Standard .vbs file
    VBE         = 2,    ///< Encoded .vbe file
    WSF         = 3,    ///< Windows Script File (.wsf)
    HTA         = 4,    ///< HTML Application (.hta)
    Embedded    = 5,    ///< Embedded in document
    Memory      = 6     ///< In-memory script
};

/**
 * @brief Dangerous COM object type
 */
enum class DangerousObjectType : uint8_t {
    None            = 0,
    WScriptShell    = 1,    ///< WScript.Shell
    FileSystemObject = 2,   ///< Scripting.FileSystemObject
    ADODBStream     = 3,    ///< ADODB.Stream
    XMLHTTP         = 4,    ///< MSXML2.XMLHTTP variants
    ShellApplication = 5,   ///< Shell.Application
    WMI             = 6,    ///< WbemScripting
    Scheduler       = 7,    ///< Schedule.Service
    OfficeApp       = 8,    ///< Office applications
    Network         = 9,    ///< WScript.Network
    IE              = 10    ///< InternetExplorer.Application
};

/**
 * @brief Detected capability
 */
enum class VBSCapability : uint32_t {
    None                = 0,
    CommandExecution    = 1 << 0,   ///< WScript.Shell.Run/Exec
    FileOperations      = 1 << 1,   ///< FSO file read/write
    NetworkDownload     = 1 << 2,   ///< XMLHTTP/download
    BinaryFileCreate    = 1 << 3,   ///< ADODB.Stream binary
    RegistryAccess      = 1 << 4,   ///< RegRead/RegWrite
    ProcessCreation     = 1 << 5,   ///< Shell.Application
    WMIAccess           = 1 << 6,   ///< WMI queries
    ScheduledTask       = 1 << 7,   ///< Task scheduler
    PowerShellInvoke    = 1 << 8,   ///< PowerShell execution
    Persistence         = 1 << 9,   ///< Startup persistence
    EmailAccess         = 1 << 10,  ///< Outlook automation
    SystemInfo          = 1 << 11,  ///< System enumeration
    UserEnum            = 1 << 12,  ///< User/domain enum
    CredentialAccess    = 1 << 13,  ///< Password access
    AntiSandbox         = 1 << 14,  ///< Sandbox detection
    SleepEvasion        = 1 << 15,  ///< Time-based evasion
    DocumentEmbed       = 1 << 16,  ///< Embedded in docs
    DynamicExecution    = 1 << 17,  ///< Execute/ExecuteGlobal
    EncodedPayload      = 1 << 18,  ///< Base64/encoded content
    SelfModifying       = 1 << 19   ///< Self-modifying code
};

/**
 * @brief Obfuscation type
 */
enum class VBSObfuscationType : uint8_t {
    None                = 0,
    ChrEncoding         = 1,    ///< Chr() character encoding
    StringConcatenation = 2,    ///< String splitting/concat
    VariableSubstitution = 3,   ///< Variable name obfuscation
    ExecuteChain        = 4,    ///< Execute/ExecuteGlobal chain
    EvalUsage           = 5,    ///< Eval() usage
    ReplaceTechnique    = 6,    ///< Replace() deobfuscation
    MixedTechniques     = 7,    ///< Multiple techniques
    VBEEncoding         = 8,    ///< Script Encoder encoding
    CustomEncoder       = 9     ///< Custom encoding
};

/**
 * @brief Threat category
 */
enum class VBSThreatCategory : uint8_t {
    None            = 0,
    Dropper         = 1,    ///< Payload dropper
    Downloader      = 2,    ///< File downloader
    RAT             = 3,    ///< Remote access trojan
    Ransomware      = 4,    ///< Ransomware
    Stealer         = 5,    ///< Information stealer
    Backdoor        = 6,    ///< Backdoor
    Worm            = 7,    ///< Self-propagating worm
    BotClient       = 8,    ///< Botnet client
    Reconnaissance  = 9,    ///< System enumeration
    Persistence     = 10,   ///< Persistence mechanism
    Launcher        = 11    ///< Malware launcher
};

/**
 * @brief Scan status
 */
enum class VBSScanStatus : uint8_t {
    Clean               = 0,
    Suspicious          = 1,
    Malicious           = 2,
    ErrorFileAccess     = 3,
    ErrorParsing        = 4,
    ErrorDeobfuscation  = 5,
    SkippedWhitelisted  = 6,
    SkippedSizeLimit    = 7
};

/**
 * @brief Module status
 */
enum class ModuleStatus : uint8_t {
    Uninitialized   = 0,
    Initializing    = 1,
    Running         = 2,
    Paused          = 3,
    Stopping        = 4,
    Stopped         = 5,
    Error           = 6
};

// ============================================================================
// STRUCTURES
// ============================================================================

/**
 * @brief COM object usage info
 */
struct COMObjectUsage {
    /// @brief Object name
    std::string objectName;
    
    /// @brief Object type
    DangerousObjectType type = DangerousObjectType::None;
    
    /// @brief Methods called
    std::vector<std::string> methodsCalled;
    
    /// @brief Line number
    size_t lineNumber = 0;
    
    /// @brief Is dangerous
    bool isDangerous = false;
    
    /// @brief Danger reason
    std::string dangerReason;
    
    /// @brief Capabilities provided
    VBSCapability capabilities = VBSCapability::None;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Deobfuscation result
 */
struct VBSDeobfuscationResult {
    /// @brief Was successful
    bool success = false;
    
    /// @brief Original script
    std::string originalScript;
    
    /// @brief Deobfuscated script
    std::string deobfuscatedScript;
    
    /// @brief Obfuscation type
    VBSObfuscationType obfuscationType = VBSObfuscationType::None;
    
    /// @brief Deobfuscation depth
    size_t depth = 0;
    
    /// @brief Chr() call count
    size_t chrCallCount = 0;
    
    /// @brief Extracted strings
    std::vector<std::string> extractedStrings;
    
    /// @brief Extracted URLs
    std::vector<std::string> extractedUrls;
    
    /// @brief Extracted IPs
    std::vector<std::string> extractedIps;
    
    /// @brief Error message (if failed)
    std::string errorMessage;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Scan result
 */
struct VBSScanResult {
    /// @brief Scan status
    VBSScanStatus status = VBSScanStatus::Clean;
    
    /// @brief Is malicious
    bool isMalicious = false;
    
    /// @brief Threat category
    VBSThreatCategory category = VBSThreatCategory::None;
    
    /// @brief Risk score (0-100)
    int riskScore = 0;
    
    /// @brief Detected family
    std::string detectedFamily;
    
    /// @brief Threat name
    std::string threatName;
    
    /// @brief File type
    VBSFileType fileType = VBSFileType::Unknown;
    
    /// @brief Detected capabilities
    VBSCapability capabilities = VBSCapability::None;
    
    /// @brief Capability names
    std::vector<std::string> detectedCapabilities;
    
    /// @brief COM object usage
    std::vector<COMObjectUsage> comObjectUsage;
    
    /// @brief Dangerous objects found
    std::vector<COMObjectUsage> dangerousObjects;
    
    /// @brief Deobfuscation result
    std::optional<VBSDeobfuscationResult> deobfuscation;
    
    /// @brief Is obfuscated
    bool isObfuscated = false;
    
    /// @brief Obfuscation type
    VBSObfuscationType obfuscationType = VBSObfuscationType::None;
    
    /// @brief Matched signatures
    std::vector<std::string> matchedSignatures;
    
    /// @brief Extracted IOCs
    std::vector<std::string> extractedIOCs;
    
    /// @brief Extracted URLs
    std::vector<std::string> extractedUrls;
    
    /// @brief Extracted commands
    std::vector<std::string> extractedCommands;
    
    /// @brief Flagged lines
    std::vector<std::pair<size_t, std::string>> flaggedLines;
    
    /// @brief File path
    std::filesystem::path filePath;
    
    /// @brief File hash (SHA-256)
    std::string sha256;
    
    /// @brief File size
    size_t fileSize = 0;
    
    /// @brief Scan time
    SystemTimePoint scanTime;
    
    /// @brief Scan duration
    std::chrono::microseconds scanDuration{0};
    
    [[nodiscard]] bool ShouldBlock() const noexcept;
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Statistics
 */
struct VBSStatistics {
    std::atomic<uint64_t> totalScans{0};
    std::atomic<uint64_t> maliciousDetected{0};
    std::atomic<uint64_t> suspiciousDetected{0};
    std::atomic<uint64_t> vbsFilesScanned{0};
    std::atomic<uint64_t> vbeFilesScanned{0};
    std::atomic<uint64_t> wsfFilesScanned{0};
    std::atomic<uint64_t> htaFilesScanned{0};
    std::atomic<uint64_t> obfuscatedDetected{0};
    std::atomic<uint64_t> deobfuscationSuccess{0};
    std::atomic<uint64_t> deobfuscationFailure{0};
    std::atomic<uint64_t> dangerousObjectsFound{0};
    std::atomic<uint64_t> totalBytesScanned{0};
    std::array<std::atomic<uint64_t>, 16> byCategory{};
    std::array<std::atomic<uint64_t>, 32> byCapability{};
    TimePoint startTime = Clock::now();
    
    void Reset() noexcept;
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Configuration
 */
struct VBSScannerConfiguration {
    /// @brief Enable scanning
    bool enabled = true;
    
    /// @brief Enable deobfuscation
    bool enableDeobfuscation = true;
    
    /// @brief Block dangerous objects
    bool blockDangerousObjects = true;
    
    /// @brief Block obfuscated scripts
    bool blockObfuscatedScripts = false;
    
    /// @brief Block WScript.Shell
    bool blockWScriptShell = true;
    
    /// @brief Block FSO
    bool blockFileSystemObject = false;
    
    /// @brief Maximum file size
    size_t maxFileSize = VBSConstants::MAX_SCRIPT_SIZE;
    
    /// @brief Maximum deobfuscation depth
    size_t maxDeobfuscationDepth = VBSConstants::MAX_DEOBFUSCATION_DEPTH;
    
    /// @brief Extract IOCs
    bool extractIOCs = true;
    
    /// @brief Scan HTA files
    bool scanHTA = true;
    
    /// @brief Verbose logging
    bool verboseLogging = false;
    
    [[nodiscard]] bool IsValid() const noexcept;
};

// ============================================================================
// CALLBACK TYPES
// ============================================================================

using ScanResultCallback = std::function<void(const VBSScanResult&)>;
using ErrorCallback = std::function<void(const std::string& message, int code)>;

// ============================================================================
// VBSCRIPT SCANNER CLASS
// ============================================================================

/**
 * @class VBScriptScanner
 * @brief Enterprise-grade VBScript malware detection engine
 */
class VBScriptScanner final {
public:
    [[nodiscard]] static VBScriptScanner& Instance() noexcept;
    [[nodiscard]] static bool HasInstance() noexcept;
    
    VBScriptScanner(const VBScriptScanner&) = delete;
    VBScriptScanner& operator=(const VBScriptScanner&) = delete;
    VBScriptScanner(VBScriptScanner&&) = delete;
    VBScriptScanner& operator=(VBScriptScanner&&) = delete;

    // ========================================================================
    // LIFECYCLE
    // ========================================================================
    
    [[nodiscard]] bool Initialize(const VBSScannerConfiguration& config = {});
    void Shutdown();
    [[nodiscard]] bool IsInitialized() const noexcept;
    [[nodiscard]] ModuleStatus GetStatus() const noexcept;
    
    [[nodiscard]] bool UpdateConfiguration(const VBSScannerConfiguration& config);
    [[nodiscard]] VBSScannerConfiguration GetConfiguration() const;

    // ========================================================================
    // SCANNING
    // ========================================================================
    
    /// @brief Scan VBScript file (auto-detect type)
    [[nodiscard]] VBSScanResult ScanFile(const std::filesystem::path& path);
    
    /// @brief Scan VBScript source code
    [[nodiscard]] VBSScanResult ScanSource(
        std::string_view source,
        const std::string& sourceName = "memory.vbs");
    
    /// @brief Scan encoded VBE file
    [[nodiscard]] VBSScanResult ScanEncodedVBE(const std::filesystem::path& vbePath);
    
    /// @brief Scan WSF file
    [[nodiscard]] VBSScanResult ScanWSF(const std::filesystem::path& wsfPath);
    
    /// @brief Scan HTA file (extract VBScript)
    [[nodiscard]] VBSScanResult ScanHTA(const std::filesystem::path& htaPath);

    // ========================================================================
    // ANALYSIS
    // ========================================================================
    
    /// @brief Detect file type
    [[nodiscard]] VBSFileType DetectFileType(const std::filesystem::path& path);
    
    /// @brief Analyze COM object usage
    [[nodiscard]] std::vector<COMObjectUsage> AnalyzeCOMUsage(
        std::string_view source);
    
    /// @brief Detect capabilities
    [[nodiscard]] VBSCapability DetectCapabilities(std::string_view source);
    
    /// @brief Deobfuscate script
    [[nodiscard]] VBSDeobfuscationResult Deobfuscate(std::string_view source);
    
    /// @brief Decode VBE script
    [[nodiscard]] std::optional<std::string> DecodeVBE(std::string_view encodedScript);
    
    /// @brief Detect obfuscation
    [[nodiscard]] VBSObfuscationType DetectObfuscation(std::string_view source);
    
    /// @brief Extract IOCs from script
    [[nodiscard]] std::vector<std::string> ExtractIOCs(std::string_view source);
    
    /// @brief Check if COM object is dangerous
    [[nodiscard]] bool IsDangerousCOMObject(std::string_view objectName) const noexcept;

    // ========================================================================
    // CALLBACKS
    // ========================================================================
    
    void RegisterCallback(ScanResultCallback callback);
    void RegisterErrorCallback(ErrorCallback callback);
    void UnregisterCallbacks();

    // ========================================================================
    // STATISTICS
    // ========================================================================
    
    [[nodiscard]] VBSStatistics GetStatistics() const;
    void ResetStatistics();
    
    [[nodiscard]] bool SelfTest();
    [[nodiscard]] static std::string GetVersionString() noexcept;

private:
    VBScriptScanner();
    ~VBScriptScanner();
    
    std::unique_ptr<VBScriptScannerImpl> m_impl;
    static std::atomic<bool> s_instanceCreated;
};

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

[[nodiscard]] std::string_view GetVBSFileTypeName(VBSFileType type) noexcept;
[[nodiscard]] std::string_view GetDangerousObjectTypeName(DangerousObjectType type) noexcept;
[[nodiscard]] std::string_view GetVBSCapabilityName(VBSCapability cap) noexcept;
[[nodiscard]] std::string_view GetVBSThreatCategoryName(VBSThreatCategory cat) noexcept;
[[nodiscard]] std::string_view GetVBSObfuscationTypeName(VBSObfuscationType type) noexcept;
[[nodiscard]] bool IsSuspiciousVBSKeyword(std::string_view keyword) noexcept;
[[nodiscard]] DangerousObjectType ClassifyCOMObject(std::string_view objectName) noexcept;

}  // namespace Scripts
}  // namespace ShadowStrike

// ============================================================================
// MACROS
// ============================================================================

#define SS_VBS_SCAN(path) \
    ::ShadowStrike::Scripts::VBScriptScanner::Instance().ScanFile(path)

#define SS_VBS_SCAN_SOURCE(source) \
    ::ShadowStrike::Scripts::VBScriptScanner::Instance().ScanSource(source)