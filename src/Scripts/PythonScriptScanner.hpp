/**
 * ============================================================================
 * ShadowStrike NGAV - PYTHON SCRIPT SCANNER MODULE
 * ============================================================================
 *
 * @file PythonScriptScanner.hpp
 * @brief Enterprise-grade Python script and bytecode analysis engine for
 *        detection of malicious Python-based threats.
 *
 * Provides comprehensive detection of Python malware including source scripts,
 * compiled bytecode (.pyc), and packed executables (PyInstaller, cx_Freeze).
 *
 * DETECTION CAPABILITIES:
 * =======================
 *
 * 1. SOURCE CODE ANALYSIS
 *    - Malicious import detection
 *    - Dangerous function calls
 *    - Code injection patterns
 *    - Obfuscation detection
 *    - Dynamic code execution (exec/eval)
 *
 * 2. MALICIOUS IMPORT DETECTION
 *    - socket (network operations)
 *    - ctypes (native code)
 *    - subprocess (process execution)
 *    - os (system operations)
 *    - cryptography (ransomware indicator)
 *    - winreg (registry access)
 *    - pyautogui (automation/keylogging)
 *    - pynput (input capture)
 *
 * 3. BYTECODE ANALYSIS
 *    - .pyc file parsing
 *    - Opcode analysis
 *    - Decompilation
 *    - Magic number validation
 *    - Version fingerprinting
 *
 * 4. PACKED EXECUTABLE ANALYSIS
 *    - PyInstaller detection/extraction
 *    - cx_Freeze analysis
 *    - Nuitka detection
 *    - py2exe analysis
 *    - Embedded script extraction
 *
 * 5. CAPABILITY DETECTION
 *    - Screenshot capture
 *    - Keylogging
 *    - Webcam access
 *    - Clipboard monitoring
 *    - File encryption
 *    - Persistence mechanisms
 *    - C2 communication
 *
 * 6. MALWARE FAMILY DETECTION
 *    - Python RATs (Pupy, etc.)
 *    - Ransomware (PyLocky, etc.)
 *    - Stealers (Browser cookies, credentials)
 *    - Cryptominers
 *    - Backdoors
 *
 * INTEGRATION:
 * ============
 * - PatternStore for Python patterns
 * - SignatureStore for malware families
 * - HashStore for known malicious scripts
 * - ThreatIntel for IOC correlation
 *
 * @note Supports Python 2.7 and 3.x bytecode.
 * @note Requires decompiler for bytecode analysis.
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
    class PythonScriptScannerImpl;
}

namespace ShadowStrike {
namespace Scripts {

// ============================================================================
// COMPILE-TIME CONSTANTS
// ============================================================================

namespace PythonConstants {

    inline constexpr uint32_t VERSION_MAJOR = 3;
    inline constexpr uint32_t VERSION_MINOR = 0;
    inline constexpr uint32_t VERSION_PATCH = 0;

    /// @brief Maximum script size (50 MB)
    inline constexpr size_t MAX_SCRIPT_SIZE = 50 * 1024 * 1024;
    
    /// @brief Maximum decompiled bytecode size
    inline constexpr size_t MAX_DECOMPILED_SIZE = 100 * 1024 * 1024;
    
    /// @brief Python 2.7 magic number
    inline constexpr uint32_t PYC_MAGIC_27 = 0x03F30D0A;
    
    /// @brief Python 3.x magic numbers (range)
    inline constexpr uint32_t PYC_MAGIC_3X_MIN = 0x0D0A0000;
    inline constexpr uint32_t PYC_MAGIC_3X_MAX = 0x0D0AFFFF;
    
    /// @brief Suspicious imports
    inline constexpr const char* SUSPICIOUS_IMPORTS[] = {
        "socket", "ctypes", "subprocess", "os", "sys",
        "cryptography", "Crypto", "pycryptodome", "winreg",
        "pyautogui", "pynput", "cv2", "PIL", "pywin32",
        "win32api", "win32con", "win32gui", "winshell",
        "requests", "urllib", "http.client", "paramiko",
        "pexpect", "ptyprocess", "keyboard", "mouse",
        "pyperclip", "pyHook", "pythoncom", "wmi",
    };

}  // namespace PythonConstants

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
 * @brief Python artifact type
 */
enum class PythonArtifactType : uint8_t {
    Unknown         = 0,
    SourcePy        = 1,    ///< .py source file
    BytecodePyc     = 2,    ///< .pyc compiled bytecode
    OptimizedPyo    = 3,    ///< .pyo optimized bytecode
    PackedPyInstaller = 4,  ///< PyInstaller executable
    PackedCxFreeze  = 5,    ///< cx_Freeze executable
    PackedNuitka    = 6,    ///< Nuitka compiled
    PackedPy2Exe    = 7,    ///< py2exe executable
    PackedBBFreeze  = 8,    ///< bbfreeze executable
    Notebook        = 9,    ///< Jupyter notebook (.ipynb)
    EggZip          = 10,   ///< Python egg/wheel
    ZipApp          = 11    ///< Python zip application
};

/**
 * @brief Python version
 */
enum class PythonVersion : uint8_t {
    Unknown     = 0,
    Python27    = 27,
    Python30    = 30,
    Python35    = 35,
    Python36    = 36,
    Python37    = 37,
    Python38    = 38,
    Python39    = 39,
    Python310   = 310,
    Python311   = 311,
    Python312   = 312
};

/**
 * @brief Detected capability
 */
enum class PythonCapability : uint32_t {
    None                    = 0,
    NetworkCommunication    = 1 << 0,   ///< Network operations
    FileOperations          = 1 << 1,   ///< File read/write
    ProcessExecution        = 1 << 2,   ///< Subprocess execution
    RegistryAccess          = 1 << 3,   ///< Windows registry
    ScreenCapture           = 1 << 4,   ///< Screenshot capability
    Keylogging              = 1 << 5,   ///< Keystroke capture
    WebcamAccess            = 1 << 6,   ///< Camera access
    ClipboardMonitor        = 1 << 7,   ///< Clipboard access
    FileEncryption          = 1 << 8,   ///< Encryption operations
    Persistence             = 1 << 9,   ///< Persistence mechanism
    CredentialAccess        = 1 << 10,  ///< Password/credential theft
    SystemInfo              = 1 << 11,  ///< System enumeration
    ProcessInjection        = 1 << 12,  ///< Code injection
    AntiVM                  = 1 << 13,  ///< VM detection
    AntiDebug               = 1 << 14,  ///< Debug detection
    SelfModifying           = 1 << 15,  ///< Self-modifying code
    DynamicExecution        = 1 << 16,  ///< exec/eval usage
    ShellAccess             = 1 << 17,  ///< Shell command execution
    EmailAccess             = 1 << 18,  ///< Email operations
    BrowserManipulation     = 1 << 19   ///< Browser automation
};

/**
 * @brief Threat category
 */
enum class PythonThreatCategory : uint8_t {
    None            = 0,
    RAT             = 1,    ///< Remote access trojan
    Ransomware      = 2,    ///< File encryption malware
    Stealer         = 3,    ///< Information stealer
    CryptoMiner     = 4,    ///< Cryptocurrency miner
    Backdoor        = 5,    ///< Backdoor
    Keylogger       = 6,    ///< Keystroke logger
    Spyware         = 7,    ///< Spyware
    BotnetClient    = 8,    ///< Botnet component
    Dropper         = 9,    ///< Payload dropper
    Reconnaissance  = 10,   ///< System enumeration
    Exploit         = 11,   ///< Exploit code
    WebShell        = 12    ///< Web shell
};

/**
 * @brief Obfuscation type
 */
enum class PythonObfuscationType : uint8_t {
    None                = 0,
    Base64Encoding      = 1,    ///< Base64 encoded strings
    HexEncoding         = 2,    ///< Hex encoded strings
    XorEncryption       = 3,    ///< XOR encrypted
    AESEncryption       = 4,    ///< AES encrypted
    MarshalSerialized   = 5,    ///< marshal module usage
    CompileDynamic      = 6,    ///< compile() usage
    ExecEval            = 7,    ///< exec/eval chains
    PyArmor             = 8,    ///< PyArmor protected
    PyObfuscate         = 9,    ///< pyobfuscate
    Pyminifier          = 10,   ///< pyminifier
    VariableRenaming    = 11,   ///< Meaningless names
    CustomObfuscation   = 255   ///< Custom/unknown
};

/**
 * @brief Scan status
 */
enum class PythonScanStatus : uint8_t {
    Clean               = 0,
    Suspicious          = 1,
    Malicious           = 2,
    ErrorFileAccess     = 3,
    ErrorParsing        = 4,
    ErrorDecompile      = 5,
    ErrorExtraction     = 6,
    SkippedWhitelisted  = 7,
    SkippedSizeLimit    = 8
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
 * @brief Import analysis info
 */
struct PythonImportInfo {
    /// @brief Module name
    std::string moduleName;
    
    /// @brief Is standard library
    bool isStdLib = false;
    
    /// @brief Is suspicious
    bool isSuspicious = false;
    
    /// @brief Suspicion reason
    std::string suspicionReason;
    
    /// @brief Functions imported
    std::vector<std::string> functionsImported;
    
    /// @brief Line number
    size_t lineNumber = 0;
    
    /// @brief Capabilities provided
    PythonCapability capabilities = PythonCapability::None;
    
    /**
     * @brief Serialize to JSON
     */
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Bytecode analysis info
 */
struct PythonBytecodeInfo {
    /// @brief Python version
    PythonVersion version = PythonVersion::Unknown;
    
    /// @brief Magic number
    uint32_t magicNumber = 0;
    
    /// @brief Timestamp
    uint32_t timestamp = 0;
    
    /// @brief Source size (Python 3.3+)
    uint32_t sourceSize = 0;
    
    /// @brief Code object count
    size_t codeObjectCount = 0;
    
    /// @brief Was successfully decompiled
    bool wasDecompiled = false;
    
    /// @brief Decompiled source (if available)
    std::string decompiledSource;
    
    /// @brief Decompilation error (if failed)
    std::string decompileError;
    
    /**
     * @brief Serialize to JSON
     */
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Packed executable analysis info
 */
struct PackedPythonInfo {
    /// @brief Packer type
    PythonArtifactType packerType = PythonArtifactType::Unknown;
    
    /// @brief Packer version (if detected)
    std::string packerVersion;
    
    /// @brief Entry script name
    std::string entryScript;
    
    /// @brief Embedded script count
    size_t embeddedScriptCount = 0;
    
    /// @brief Embedded scripts
    std::vector<std::string> embeddedScripts;
    
    /// @brief Python version bundled
    PythonVersion pythonVersion = PythonVersion::Unknown;
    
    /// @brief Was successfully extracted
    bool wasExtracted = false;
    
    /// @brief Extraction error
    std::string extractionError;
    
    /// @brief Extracted entry script source
    std::string extractedSource;
    
    /**
     * @brief Serialize to JSON
     */
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Scan result
 */
struct PythonScanResult {
    /// @brief Scan status
    PythonScanStatus status = PythonScanStatus::Clean;
    
    /// @brief Is malicious
    bool isMalicious = false;
    
    /// @brief Threat category
    PythonThreatCategory category = PythonThreatCategory::None;
    
    /// @brief Risk score (0-100)
    int riskScore = 0;
    
    /// @brief Detected family
    std::string detectedFamily;
    
    /// @brief Threat name
    std::string threatName;
    
    /// @brief Artifact type
    PythonArtifactType artifactType = PythonArtifactType::Unknown;
    
    /// @brief Detected capabilities
    PythonCapability capabilities = PythonCapability::None;
    
    /// @brief Capability list (names)
    std::vector<std::string> detectedCapabilities;
    
    /// @brief Suspicious imports
    std::vector<PythonImportInfo> suspiciousImports;
    
    /// @brief All imports
    std::vector<PythonImportInfo> allImports;
    
    /// @brief Bytecode info (if .pyc)
    std::optional<PythonBytecodeInfo> bytecodeInfo;
    
    /// @brief Packed info (if executable)
    std::optional<PackedPythonInfo> packedInfo;
    
    /// @brief Obfuscation type
    PythonObfuscationType obfuscationType = PythonObfuscationType::None;
    
    /// @brief Is obfuscated
    bool isObfuscated = false;
    
    /// @brief Matched signatures
    std::vector<std::string> matchedSignatures;
    
    /// @brief Extracted IOCs
    std::vector<std::string> extractedIOCs;
    
    /// @brief Flagged lines (line number, content)
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
    
    /**
     * @brief Check if should block
     */
    [[nodiscard]] bool ShouldBlock() const noexcept;
    
    /**
     * @brief Serialize to JSON
     */
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Statistics
 */
struct PythonStatistics {
    std::atomic<uint64_t> totalScans{0};
    std::atomic<uint64_t> maliciousDetected{0};
    std::atomic<uint64_t> suspiciousDetected{0};
    std::atomic<uint64_t> sourceFilesScanned{0};
    std::atomic<uint64_t> bytecodeFilesScanned{0};
    std::atomic<uint64_t> packedExecutablesScanned{0};
    std::atomic<uint64_t> obfuscatedDetected{0};
    std::atomic<uint64_t> decompileFailures{0};
    std::atomic<uint64_t> extractionFailures{0};
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
struct PythonScannerConfiguration {
    /// @brief Enable scanning
    bool enabled = true;
    
    /// @brief Enable bytecode decompilation
    bool enableDecompilation = true;
    
    /// @brief Enable packed executable extraction
    bool enablePackedExtraction = true;
    
    /// @brief Block dangerous imports
    bool blockDangerousImports = false;
    
    /// @brief Block obfuscated scripts
    bool blockObfuscatedScripts = false;
    
    /// @brief Maximum file size
    size_t maxFileSize = PythonConstants::MAX_SCRIPT_SIZE;
    
    /// @brief Scan notebooks (.ipynb)
    bool scanNotebooks = true;
    
    /// @brief Extract IOCs
    bool extractIOCs = true;
    
    /// @brief Whitelisted imports (override suspicious)
    std::vector<std::string> whitelistedImports;
    
    /// @brief Verbose logging
    bool verboseLogging = false;
    
    [[nodiscard]] bool IsValid() const noexcept;
};

// ============================================================================
// CALLBACK TYPES
// ============================================================================

using ScanResultCallback = std::function<void(const PythonScanResult&)>;
using ErrorCallback = std::function<void(const std::string& message, int code)>;

// ============================================================================
// PYTHON SCRIPT SCANNER CLASS
// ============================================================================

/**
 * @class PythonScriptScanner
 * @brief Enterprise-grade Python malware detection engine
 */
class PythonScriptScanner final {
public:
    [[nodiscard]] static PythonScriptScanner& Instance() noexcept;
    [[nodiscard]] static bool HasInstance() noexcept;
    
    PythonScriptScanner(const PythonScriptScanner&) = delete;
    PythonScriptScanner& operator=(const PythonScriptScanner&) = delete;
    PythonScriptScanner(PythonScriptScanner&&) = delete;
    PythonScriptScanner& operator=(PythonScriptScanner&&) = delete;

    // ========================================================================
    // LIFECYCLE
    // ========================================================================
    
    [[nodiscard]] bool Initialize(const PythonScannerConfiguration& config = {});
    void Shutdown();
    [[nodiscard]] bool IsInitialized() const noexcept;
    [[nodiscard]] ModuleStatus GetStatus() const noexcept;
    
    [[nodiscard]] bool UpdateConfiguration(const PythonScannerConfiguration& config);
    [[nodiscard]] PythonScannerConfiguration GetConfiguration() const;

    // ========================================================================
    // SCANNING
    // ========================================================================
    
    /// @brief Scan Python file (auto-detect type)
    [[nodiscard]] PythonScanResult ScanFile(const std::filesystem::path& path);
    
    /// @brief Scan Python source code
    [[nodiscard]] PythonScanResult ScanSource(
        std::string_view source,
        const std::string& sourceName = "memory.py");
    
    /// @brief Scan PyInstaller executable
    [[nodiscard]] PythonScanResult ScanPyInstallerExe(
        const std::filesystem::path& exePath);
    
    /// @brief Scan Python bytecode (.pyc)
    [[nodiscard]] PythonScanResult ScanBytecode(
        const std::filesystem::path& pycPath);

    // ========================================================================
    // ANALYSIS
    // ========================================================================
    
    /// @brief Detect artifact type
    [[nodiscard]] PythonArtifactType DetectArtifactType(
        const std::filesystem::path& path);
    
    /// @brief Analyze imports
    [[nodiscard]] std::vector<PythonImportInfo> AnalyzeImports(
        std::string_view source);
    
    /// @brief Detect capabilities
    [[nodiscard]] PythonCapability DetectCapabilities(std::string_view source);
    
    /// @brief Decompile bytecode
    [[nodiscard]] std::optional<std::string> DecompileBytecode(
        const std::filesystem::path& pycPath);
    
    /// @brief Extract from packed executable
    [[nodiscard]] std::optional<PackedPythonInfo> ExtractFromPacked(
        const std::filesystem::path& exePath);
    
    /// @brief Detect obfuscation
    [[nodiscard]] PythonObfuscationType DetectObfuscation(std::string_view source);

    // ========================================================================
    // CALLBACKS
    // ========================================================================
    
    void RegisterCallback(ScanResultCallback callback);
    void RegisterErrorCallback(ErrorCallback callback);
    void UnregisterCallbacks();

    // ========================================================================
    // STATISTICS
    // ========================================================================
    
    [[nodiscard]] PythonStatistics GetStatistics() const;
    void ResetStatistics();
    
    [[nodiscard]] bool SelfTest();
    [[nodiscard]] static std::string GetVersionString() noexcept;

private:
    PythonScriptScanner();
    ~PythonScriptScanner();
    
    std::unique_ptr<PythonScriptScannerImpl> m_impl;
    static std::atomic<bool> s_instanceCreated;
};

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

[[nodiscard]] std::string_view GetPythonArtifactTypeName(PythonArtifactType type) noexcept;
[[nodiscard]] std::string_view GetPythonVersionName(PythonVersion version) noexcept;
[[nodiscard]] std::string_view GetPythonCapabilityName(PythonCapability cap) noexcept;
[[nodiscard]] std::string_view GetPythonThreatCategoryName(PythonThreatCategory cat) noexcept;
[[nodiscard]] std::string_view GetPythonObfuscationTypeName(PythonObfuscationType type) noexcept;
[[nodiscard]] bool IsSuspiciousPythonImport(std::string_view moduleName) noexcept;
[[nodiscard]] PythonVersion DetectPythonVersionFromMagic(uint32_t magic) noexcept;

}  // namespace Scripts
}  // namespace ShadowStrike

// ============================================================================
// MACROS
// ============================================================================

#define SS_PYTHON_SCAN(path) \
    ::ShadowStrike::Scripts::PythonScriptScanner::Instance().ScanFile(path)

#define SS_PYTHON_SCAN_SOURCE(source) \
    ::ShadowStrike::Scripts::PythonScriptScanner::Instance().ScanSource(source)