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
 * ShadowStrike Core Process - DLL INJECTION DETECTOR (The Classic)
 * ============================================================================
 *
 * @file DLLInjectionDetector.hpp
 * @brief Enterprise-grade detection of classic DLL injection attacks.
 *
 * DLL injection is one of the oldest and most commonly used code injection
 * techniques. This detector provides comprehensive coverage of both classic
 * and modern DLL injection methods.
 *
 * ============================================================================
 * INJECTION TECHNIQUES DETECTED
 * ============================================================================
 *
 * | Category         | Technique                    | Detection Method          |
 * |------------------|------------------------------|---------------------------|
 * | Classic          | CreateRemoteThread           | Thread creation monitoring|
 * | Classic          | LoadLibrary                  | Module load events        |
 * | Classic          | SetWindowsHookEx             | Hook registration         |
 * | Registry-based   | AppInit_DLLs                 | Registry monitoring       |
 * | Registry-based   | Image File Execution Options | IFEO key monitoring       |
 * | Shim-based       | Application Compatibility    | Shim database analysis    |
 * | COM-based        | COM Hijacking                | COM registration          |
 * | Import Table     | Import Table Hooking         | IAT analysis              |
 * | Thread Pool      | QueueUserWorkItem            | Thread pool monitoring    |
 * | Callback-based   | TLS Callback                 | TLS directory analysis    |
 * | Callback-based   | Window Subclassing           | Window procedure hooks    |
 * | Context-based    | SetThreadContext             | Context modification      |
 * | APC-based        | QueueUserAPC                 | APC monitoring            |
 * | Section-based    | NtMapViewOfSection           | Section mapping events    |
 * | RtlCreate*       | RtlCreateUserThread          | User thread creation      |
 *
 * ============================================================================
 * MITRE ATT&CK COVERAGE
 * ============================================================================
 *
 * | Technique ID | Technique Name              | Sub-technique             |
 * |--------------|-----------------------------|---------------------------|
 * | T1055.001    | DLL Injection               | All variants              |
 * | T1574.001    | DLL Search Order Hijacking  | Path analysis             |
 * | T1574.002    | DLL Side-Loading            | Known pairs               |
 * | T1574.006    | DLL Path Interception       | Path monitoring           |
 * | T1574.007    | Path Interception (Unquoted)| Unquoted path analysis    |
 * | T1574.008    | Path Interception (Search)  | Search order analysis     |
 * | T1574.009    | Path Interception (Env Var) | Environment variable      |
 * | T1546.010    | AppInit DLLs                | Registry monitoring       |
 * | T1546.011    | Application Shimming        | Shim analysis             |
 * | T1546.015    | Component Object Model      | COM hijacking             |
 *
 * ============================================================================
 * DETECTION ARCHITECTURE
 * ============================================================================
 *
 * ┌─────────────────────────────────────────────────────────────────────────┐
 * │                        DLLInjectionDetector                             │
 * └───────────────────┬─────────────────────────────────────────────────────┘
 *                     │
 *     ┌───────────────┼───────────────┬───────────────────┐
 *     ▼               ▼               ▼                   ▼
 * ┌─────────┐   ┌─────────┐   ┌───────────┐   ┌──────────────┐
 * │ Module  │   │ Thread  │   │ Registry  │   │    API       │
 * │ Monitor │   │ Monitor │   │ Monitor   │   │   Monitor    │
 * └─────────┘   └─────────┘   └───────────┘   └──────────────┘
 *     │               │               │                   │
 *     └───────────────┴───────────────┴───────────────────┘
 *                             │
 *                             ▼
 *                   ┌──────────────────┐
 *                   │ Correlation      │
 *                   │ Engine           │
 *                   └──────────────────┘
 *                             │
 *                             ▼
 *                   ┌──────────────────┐
 *                   │ Trust/Whitelist  │
 *                   │ Validation       │
 *                   └──────────────────┘
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
#include "../../Utils/RegistryUtils.hpp"
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
#include <array>
#include <cstdint>

namespace ShadowStrike {
namespace Core {
namespace Process {

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

class DLLInjectionDetectorImpl;

// ============================================================================
// CONSTANTS
// ============================================================================

namespace DLLInjectionConstants {

    // Version information
    constexpr uint32_t VERSION_MAJOR = 4;
    constexpr uint32_t VERSION_MINOR = 0;
    constexpr uint32_t VERSION_PATCH = 0;

    // Detection limits
    constexpr size_t MAX_MODULES_TO_TRACK = 4096;
    constexpr size_t MAX_INJECTION_EVENTS = 16384;
    constexpr size_t MAX_HOOK_ENTRIES = 1024;
    constexpr uint32_t MAX_PROCESSES_TO_MONITOR = 10000;

    // Timeouts
    constexpr uint32_t ANALYSIS_TIMEOUT_MS = 5000;
    constexpr uint32_t LOAD_CORRELATION_WINDOW_MS = 1000;
    constexpr uint32_t THREAD_CREATION_WINDOW_MS = 500;

    // Thresholds
    constexpr uint32_t SUSPICIOUS_LOAD_THRESHOLD = 10;
    constexpr double HIGH_ENTROPY_THRESHOLD = 7.2;
    constexpr size_t MIN_DLL_SIZE = 1024;

    // Registry paths for injection vectors
    constexpr std::wstring_view APPINIT_DLLS_PATH = 
        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows";
    constexpr std::wstring_view APPINIT_DLLS_VALUE = L"AppInit_DLLs";
    constexpr std::wstring_view APPINIT_LOAD_VALUE = L"LoadAppInit_DLLs";
    
    constexpr std::wstring_view IFEO_PATH = 
        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options";
    
    constexpr std::wstring_view KNOWNDLLS_PATH = 
        L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\KnownDLLs";

    // Hook types (SetWindowsHookEx) — prefixed SS_ to avoid Windows macro clashes
    constexpr int SS_WH_KEYBOARD = 2;
    constexpr int SS_WH_KEYBOARD_LL = 13;
    constexpr int SS_WH_MOUSE = 7;
    constexpr int SS_WH_MOUSE_LL = 14;
    constexpr int SS_WH_CBT = 5;
    constexpr int SS_WH_GETMESSAGE = 3;
    constexpr int SS_WH_CALLWNDPROC = 4;
    constexpr int SS_WH_SHELL = 10;

    // Known legitimate loaders
    constexpr std::wstring_view LEGITIMATE_LOADERS[] = {
        L"ntdll.dll", L"kernel32.dll", L"kernelbase.dll",
        L"user32.dll", L"gdi32.dll", L"combase.dll",
        L"ole32.dll", L"shell32.dll", L"msvcrt.dll"
    };

} // namespace DLLInjectionConstants

// ============================================================================
// ENUMERATIONS
// ============================================================================

/**
 * @enum DLLInjectionType
 * @brief Types of DLL injection detected.
 */
enum class DLLInjectionType : uint8_t {
    Unknown = 0,
    CreateRemoteThread = 1,       ///< Classic CreateRemoteThread+LoadLibrary
    CreateRemoteThreadEx = 2,     ///< Extended version
    RtlCreateUserThread = 3,      ///< Lower-level thread creation
    NtCreateThreadEx = 4,         ///< NT native API
    SetWindowsHookEx = 5,         ///< Global hook injection
    QueueUserAPC = 6,             ///< APC-based injection
    QueueUserAPC2 = 7,            ///< Special APC
    SetThreadContext = 8,         ///< Thread context manipulation
    AppInitDLL = 9,               ///< AppInit_DLLs registry
    IFEO = 10,                    ///< Image File Execution Options
    KnownDLLHijack = 11,          ///< KnownDLLs hijacking
    SearchOrderHijack = 12,       ///< DLL search order hijacking
    SideLoading = 13,             ///< DLL side-loading
    PhantomDLL = 14,              ///< Phantom DLL loading
    COMHijacking = 15,            ///< COM object hijacking
    ApplicationShim = 16,         ///< Application compatibility shim
    ImportAddressTable = 17,      ///< IAT patching/hooking
    ExportAddressTable = 18,      ///< EAT patching/hooking
    TLSCallback = 19,             ///< TLS callback injection
    WindowSubclass = 20,          ///< Window subclassing
    ThreadPoolWait = 21,          ///< Thread pool injection
    ETWCallback = 22,             ///< ETW consumer injection
    ExceptionHandler = 23,        ///< VEH/SEH injection
    ModuleCallback = 24,          ///< LdrRegisterDllNotification
    ConfigOverride = 25,          ///< Config file DLL override
    PluginLoad = 26               ///< Legitimate plugin mechanism abuse
};

/**
 * @enum InjectionConfidence
 * @brief Confidence level of detection.
 */
enum class InjectionConfidence : uint8_t {
    None = 0,
    Low = 1,              ///< Single weak indicator
    Medium = 2,           ///< Multiple weak or single strong
    High = 3,             ///< Multiple strong indicators
    Confirmed = 4         ///< Definitive injection evidence
};

/**
 * @enum LoadReason
 * @brief Reason why a DLL was loaded.
 */
enum class LoadReason : uint8_t {
    Unknown = 0,
    StaticImport = 1,         ///< Static import table
    DelayLoad = 2,            ///< Delay-loaded import
    ExplicitLoad = 3,         ///< LoadLibrary call
    ExplicitLoadEx = 4,       ///< LoadLibraryEx call
    ForwardedImport = 5,      ///< Forwarded from another DLL
    DependencyOf = 6,         ///< Dependency of another DLL
    HookInjection = 7,        ///< SetWindowsHookEx
    RemoteThread = 8,         ///< Remote thread injection
    APCInjection = 9,         ///< APC injection
    AppInitDLLs = 10,         ///< AppInit_DLLs
    ShimEngine = 11,          ///< Application shim
    COMActivation = 12,       ///< COM/OLE activation
    CLRAssembly = 13,         ///< .NET assembly load
    PluginFramework = 14,     ///< Plugin system
    Injected = 15             ///< Generic injection
};

/**
 * @enum DLLMonitoringMode
 * @brief Real-time monitoring mode for DLL injection detector.
 */
enum class DLLMonitoringMode : uint8_t {
    Disabled = 0,
    PassiveOnly = 1,          ///< Monitor and alert
    ActiveBlock = 2,          ///< Block suspicious loads
    Aggressive = 3            ///< Block all untrusted
};

/**
 * @enum HookType
 * @brief Type of Windows hook (SetWindowsHookEx).
 */
enum class HookType : uint8_t {
    Unknown = 0,
    Keyboard = 1,
    KeyboardLowLevel = 2,
    Mouse = 3,
    MouseLowLevel = 4,
    CBT = 5,
    GetMessage = 6,
    CallWndProc = 7,
    CallWndProcRet = 8,
    Shell = 9,
    ForegroundIdle = 10,
    Debug = 11,
    JournalRecord = 12,
    JournalPlayback = 13,
    SysMsgFilter = 14,
    MsgFilter = 15
};

/**
 * @enum TrustLevel
 * @brief Trust level for a DLL.
 */
enum class TrustLevel : uint8_t {
    Unknown = 0,
    Malicious = 1,            ///< Known malicious
    Suspicious = 2,           ///< Suspicious characteristics
    Untrusted = 3,            ///< Unknown, not trusted
    ThirdParty = 4,           ///< Signed, known publisher
    System = 5,               ///< Windows system DLL
    Whitelisted = 6           ///< Explicitly whitelisted
};

// ============================================================================
// DATA STRUCTURES
// ============================================================================

/**
 * @struct LoadedDLLInfo
 * @brief Information about a loaded DLL.
 */
struct alignas(64) LoadedDLLInfo {
    // Identification
    std::wstring dllName;                         ///< Just the filename
    std::wstring dllPath;                         ///< Full path
    std::wstring normalizedPath;                  ///< Normalized for comparison
    
    // Memory layout
    uintptr_t baseAddress = 0;
    uint32_t sizeOfImage = 0;
    uintptr_t entryPoint = 0;
    
    // Loading context
    uint32_t loadingProcessId = 0;
    std::wstring loadingProcessName;
    uint32_t loadingThreadId = 0;
    std::chrono::system_clock::time_point loadTime;
    LoadReason loadReason = LoadReason::Unknown;
    
    // For remote injection detection
    uint32_t injectorProcessId = 0;              ///< If injected remotely
    std::wstring injectorProcessName;
    
    // Trust assessment
    TrustLevel trustLevel = TrustLevel::Unknown;
    bool isSigned = false;
    std::wstring signerName;
    bool isWhitelisted = false;
    bool isMicrosoftSigned = false;
    bool isKnownDLL = false;                     ///< In KnownDLLs
    
    // Hash information
    std::array<uint8_t, 32> sha256Hash{};
    bool hashComputed = false;
    bool hashFoundMalicious = false;
    bool hashFoundClean = false;
    
    // Path analysis
    bool isInSystemDir = false;
    bool isInKnownPath = false;
    bool isInTempPath = false;
    bool isInUserProfile = false;
    bool pathHasSpaces = false;                  ///< Unquoted path risk
    
    // Anomaly detection
    bool isSuspiciousLocation = false;
    bool isNameMasquerading = false;             ///< Similar to system DLL
    bool isPotentialSideLoad = false;
    bool hasAnomalousCharacteristics = false;
    double entropy = 0.0;
    
    // Verdict
    DLLInjectionType detectedInjectionType = DLLInjectionType::Unknown;
    InjectionConfidence confidence = InjectionConfidence::None;
    uint32_t riskScore = 0;
    std::vector<std::wstring> riskFactors;
};

/**
 * @struct DLLInjectionEvent
 * @brief Event representing a detected DLL injection.
 */
struct DLLInjectionEvent {
    uint64_t eventId = 0;
    std::chrono::system_clock::time_point timestamp;
    
    // Target process
    uint32_t targetPid = 0;
    std::wstring targetProcessName;
    std::wstring targetProcessPath;
    
    // Injector process (if applicable)
    uint32_t injectorPid = 0;
    std::wstring injectorProcessName;
    std::wstring injectorProcessPath;
    
    // Injected DLL
    LoadedDLLInfo dllInfo;
    
    // Detection details
    DLLInjectionType injectionType = DLLInjectionType::Unknown;
    InjectionConfidence confidence = InjectionConfidence::None;
    std::vector<std::wstring> detectionReasons;
    
    // Thread information (for thread-based injection)
    uint32_t injectionThreadId = 0;
    uintptr_t threadStartAddress = 0;
    
    // API sequence (if tracked)
    std::vector<std::wstring> apiSequence;
    
    // Risk assessment
    uint32_t riskScore = 0;
    bool wasBlocked = false;
    std::wstring blockReason;
    
    // Threat correlation
    bool correlatedWithThreat = false;
    std::wstring threatName;
    std::string mitreAttackId;
};

/**
 * @struct HookInfo
 * @brief Information about a Windows hook.
 */
struct HookInfo {
    HookType type = HookType::Unknown;
    int hookTypeValue = 0;                       ///< WH_* constant
    uintptr_t hookProc = 0;
    uint32_t threadId = 0;                       ///< 0 = global hook
    uint32_t installerPid = 0;
    std::wstring installerName;
    std::wstring modulePath;                     ///< DLL containing hook proc
    std::wstring moduleName;
    std::chrono::system_clock::time_point installTime;
    bool isGlobal = false;
    bool isSuspicious = false;
    std::wstring suspicionReason;
};

/**
 * @struct RegistryInjectionVector
 * @brief Registry-based injection vector information.
 */
struct RegistryInjectionVector {
    std::wstring registryPath;
    std::wstring valueName;
    std::wstring dllPath;
    bool isEnabled = false;
    std::chrono::system_clock::time_point lastModified;
    std::wstring modifierProcess;                ///< Who set this
    bool isSuspicious = false;
    std::wstring suspicionReason;
};

/**
 * @struct SideLoadInfo
 * @brief Information about potential DLL side-loading.
 */
struct SideLoadInfo {
    std::wstring targetExecutable;
    std::wstring expectedDllName;
    std::wstring actualDllPath;
    std::wstring expectedDllPath;               ///< Where it should be
    bool isKnownSideLoadPair = false;
    bool isSuspicious = false;
    std::wstring reason;
};

/**
 * @struct InjectionAnalysisResult
 * @brief Complete analysis result for a process.
 */
struct InjectionAnalysisResult {
    uint32_t processId = 0;
    std::wstring processName;
    std::wstring processPath;
    std::chrono::system_clock::time_point analysisTime;
    
    // Module analysis
    uint32_t totalModules = 0;
    uint32_t trustedModules = 0;
    uint32_t suspiciousModules = 0;
    uint32_t injectedModules = 0;
    std::vector<LoadedDLLInfo> allModules;
    std::vector<LoadedDLLInfo> suspiciousModules_;
    std::vector<LoadedDLLInfo> injectedModules_;
    
    // Hook analysis
    std::vector<HookInfo> installedHooks;
    uint32_t suspiciousHookCount = 0;
    
    // Injection events
    std::vector<DLLInjectionEvent> detectedInjections;
    
    // Side-load analysis
    std::vector<SideLoadInfo> potentialSideLoads;
    
    // Registry vectors
    std::vector<RegistryInjectionVector> registryVectors;
    
    // Overall assessment
    bool hasInjection = false;
    DLLInjectionType primaryInjectionType = DLLInjectionType::Unknown;
    InjectionConfidence overallConfidence = InjectionConfidence::None;
    uint32_t riskScore = 0;
    
    // Metadata
    uint32_t analysisDurationMs = 0;
    bool analysisComplete = false;
    std::wstring analysisError;
};

/**
 * @struct DLLInjectionConfig
 * @brief Configuration for the DLL injection detector.
 */
struct DLLInjectionConfig {
    // Monitoring mode
    DLLMonitoringMode mode = DLLMonitoringMode::PassiveOnly;
    bool enableRealTimeMonitoring = true;
    bool enableOnDemandAnalysis = true;
    
    // Detection features
    bool detectRemoteThread = true;
    bool detectAPCInjection = true;
    bool detectHookInjection = true;
    bool detectAppInitDLLs = true;
    bool detectIFEO = true;
    bool detectSearchOrderHijack = true;
    bool detectSideLoading = true;
    bool detectCOMHijacking = true;
    bool detectShimInjection = true;
    
    // Sensitivity
    InjectionConfidence alertThreshold = InjectionConfidence::Medium;
    InjectionConfidence blockThreshold = InjectionConfidence::High;
    bool alertOnUnsignedLoads = false;
    bool blockUnsignedLoads = false;
    
    // Trust settings
    bool trustMicrosoftSigned = true;
    bool trustKnownDLLs = true;
    bool trustKnownPublishers = true;
    bool useWhitelist = true;
    bool useThreatIntel = true;
    
    // Performance
    uint32_t analysisTimeoutMs = DLLInjectionConstants::ANALYSIS_TIMEOUT_MS;
    size_t maxModulesToTrack = DLLInjectionConstants::MAX_MODULES_TO_TRACK;
    bool enableHashLookup = true;
    bool computeHashesAsync = true;
    
    // Exclusions
    std::vector<std::wstring> excludedProcesses;
    std::vector<std::wstring> excludedDlls;
    std::vector<std::wstring> excludedPaths;
    
    /**
     * @brief Create default configuration.
     */
    static DLLInjectionConfig CreateDefault() noexcept;
    
    /**
     * @brief Create strict configuration.
     */
    static DLLInjectionConfig CreateStrict() noexcept;
    
    /**
     * @brief Create performance-optimized configuration.
     */
    static DLLInjectionConfig CreatePerformance() noexcept;
};

/**
 * @struct DLLInjectionStatistics
 * @brief Runtime statistics for the detector.
 */
struct alignas(64) DLLInjectionStatistics {
    // Module tracking
    std::atomic<uint64_t> totalModulesAnalyzed{0};
    std::atomic<uint64_t> trustedModulesFound{0};
    std::atomic<uint64_t> untrustedModulesFound{0};
    std::atomic<uint64_t> suspiciousModulesFound{0};

    // Detection counts
    std::atomic<uint64_t> injectionsDetected{0};
    std::atomic<uint64_t> remoteThreadInjections{0};
    std::atomic<uint64_t> hookInjections{0};
    std::atomic<uint64_t> apcInjections{0};
    std::atomic<uint64_t> appInitInjections{0};
    std::atomic<uint64_t> sideLoadingDetected{0};
    std::atomic<uint64_t> comHijackingDetected{0};
    std::atomic<uint64_t> searchOrderHijacks{0};

    // Blocking
    std::atomic<uint64_t> loadsBlocked{0};
    std::atomic<uint64_t> injectionsBlocked{0};

    // Real-time monitoring
    std::atomic<uint64_t> moduleLoadEventsProcessed{0};
    std::atomic<uint64_t> threadCreateEventsProcessed{0};
    std::atomic<uint64_t> hookEventsProcessed{0};

    // Cache/performance
    std::atomic<uint64_t> hashLookups{0};
    std::atomic<uint64_t> hashCacheHits{0};
    std::atomic<uint64_t> whitelistHits{0};

    // APC events
    std::atomic<uint64_t> apcEventsProcessed{0};

    // Errors
    std::atomic<uint64_t> analysisErrors{0};
    std::atomic<uint64_t> accessDeniedErrors{0};

    /**
     * @brief Default constructor.
     */
    DLLInjectionStatistics() noexcept = default;

    /**
     * @brief Copy constructor - loads each atomic for snapshot semantics.
     *
     * std::atomic is non-copyable by design. This explicit copy constructor
     * allows GetStatistics() to return a snapshot by value, which is the
     * standard pattern for exposing atomic statistics counters.
     */
    DLLInjectionStatistics(const DLLInjectionStatistics& other) noexcept
        : totalModulesAnalyzed(other.totalModulesAnalyzed.load(std::memory_order_relaxed))
        , trustedModulesFound(other.trustedModulesFound.load(std::memory_order_relaxed))
        , untrustedModulesFound(other.untrustedModulesFound.load(std::memory_order_relaxed))
        , suspiciousModulesFound(other.suspiciousModulesFound.load(std::memory_order_relaxed))
        , injectionsDetected(other.injectionsDetected.load(std::memory_order_relaxed))
        , remoteThreadInjections(other.remoteThreadInjections.load(std::memory_order_relaxed))
        , hookInjections(other.hookInjections.load(std::memory_order_relaxed))
        , apcInjections(other.apcInjections.load(std::memory_order_relaxed))
        , appInitInjections(other.appInitInjections.load(std::memory_order_relaxed))
        , sideLoadingDetected(other.sideLoadingDetected.load(std::memory_order_relaxed))
        , comHijackingDetected(other.comHijackingDetected.load(std::memory_order_relaxed))
        , searchOrderHijacks(other.searchOrderHijacks.load(std::memory_order_relaxed))
        , loadsBlocked(other.loadsBlocked.load(std::memory_order_relaxed))
        , injectionsBlocked(other.injectionsBlocked.load(std::memory_order_relaxed))
        , moduleLoadEventsProcessed(other.moduleLoadEventsProcessed.load(std::memory_order_relaxed))
        , threadCreateEventsProcessed(other.threadCreateEventsProcessed.load(std::memory_order_relaxed))
        , hookEventsProcessed(other.hookEventsProcessed.load(std::memory_order_relaxed))
        , hashLookups(other.hashLookups.load(std::memory_order_relaxed))
        , hashCacheHits(other.hashCacheHits.load(std::memory_order_relaxed))
        , whitelistHits(other.whitelistHits.load(std::memory_order_relaxed))
        , apcEventsProcessed(other.apcEventsProcessed.load(std::memory_order_relaxed))
        , analysisErrors(other.analysisErrors.load(std::memory_order_relaxed))
        , accessDeniedErrors(other.accessDeniedErrors.load(std::memory_order_relaxed)) {}

    /**
     * @brief Copy assignment - loads each atomic for snapshot semantics.
     */
    DLLInjectionStatistics& operator=(const DLLInjectionStatistics& other) noexcept {
        if (this != &other) {
            totalModulesAnalyzed.store(other.totalModulesAnalyzed.load(std::memory_order_relaxed), std::memory_order_relaxed);
            trustedModulesFound.store(other.trustedModulesFound.load(std::memory_order_relaxed), std::memory_order_relaxed);
            untrustedModulesFound.store(other.untrustedModulesFound.load(std::memory_order_relaxed), std::memory_order_relaxed);
            suspiciousModulesFound.store(other.suspiciousModulesFound.load(std::memory_order_relaxed), std::memory_order_relaxed);
            injectionsDetected.store(other.injectionsDetected.load(std::memory_order_relaxed), std::memory_order_relaxed);
            remoteThreadInjections.store(other.remoteThreadInjections.load(std::memory_order_relaxed), std::memory_order_relaxed);
            hookInjections.store(other.hookInjections.load(std::memory_order_relaxed), std::memory_order_relaxed);
            apcInjections.store(other.apcInjections.load(std::memory_order_relaxed), std::memory_order_relaxed);
            appInitInjections.store(other.appInitInjections.load(std::memory_order_relaxed), std::memory_order_relaxed);
            sideLoadingDetected.store(other.sideLoadingDetected.load(std::memory_order_relaxed), std::memory_order_relaxed);
            comHijackingDetected.store(other.comHijackingDetected.load(std::memory_order_relaxed), std::memory_order_relaxed);
            searchOrderHijacks.store(other.searchOrderHijacks.load(std::memory_order_relaxed), std::memory_order_relaxed);
            loadsBlocked.store(other.loadsBlocked.load(std::memory_order_relaxed), std::memory_order_relaxed);
            injectionsBlocked.store(other.injectionsBlocked.load(std::memory_order_relaxed), std::memory_order_relaxed);
            moduleLoadEventsProcessed.store(other.moduleLoadEventsProcessed.load(std::memory_order_relaxed), std::memory_order_relaxed);
            threadCreateEventsProcessed.store(other.threadCreateEventsProcessed.load(std::memory_order_relaxed), std::memory_order_relaxed);
            hookEventsProcessed.store(other.hookEventsProcessed.load(std::memory_order_relaxed), std::memory_order_relaxed);
            hashLookups.store(other.hashLookups.load(std::memory_order_relaxed), std::memory_order_relaxed);
            hashCacheHits.store(other.hashCacheHits.load(std::memory_order_relaxed), std::memory_order_relaxed);
            whitelistHits.store(other.whitelistHits.load(std::memory_order_relaxed), std::memory_order_relaxed);
            apcEventsProcessed.store(other.apcEventsProcessed.load(std::memory_order_relaxed), std::memory_order_relaxed);
            analysisErrors.store(other.analysisErrors.load(std::memory_order_relaxed), std::memory_order_relaxed);
            accessDeniedErrors.store(other.accessDeniedErrors.load(std::memory_order_relaxed), std::memory_order_relaxed);
        }
        return *this;
    }

    /**
     * @brief Reset all statistics.
     */
    void Reset() noexcept;

    /**
     * @brief Get detection rate (detections per module analyzed).
     */
    [[nodiscard]] double GetDetectionRate() const noexcept;
};

// ============================================================================
// CALLBACK DEFINITIONS
// ============================================================================

/**
 * @brief Callback when DLL injection is detected.
 * @param event Injection event details
 */
using DLLInjectionDetectedCallback = std::function<void(
    const DLLInjectionEvent& event
)>;

/**
 * @brief Callback for module load events.
 * @param dllInfo Information about the loaded DLL
 */
using ModuleLoadCallback = std::function<void(
    const LoadedDLLInfo& dllInfo
)>;

/**
 * @brief Callback before allowing/blocking a load.
 * @param dllInfo DLL being loaded
 * @return True to allow, false to block
 */
using LoadDecisionCallback = std::function<bool(
    const LoadedDLLInfo& dllInfo
)>;

/**
 * @brief Callback when hook is installed.
 * @param hookInfo Hook information
 */
using HookInstalledCallback = std::function<void(
    const HookInfo& hookInfo
)>;

// ============================================================================
// DLL INJECTION DETECTOR CLASS
// ============================================================================

/**
 * @class DLLInjectionDetector
 * @brief Enterprise-grade DLL injection detection engine.
 *
 * Thread-safety: All public methods are thread-safe.
 * Pattern: Singleton with PIMPL for ABI stability.
 *
 * Usage:
 * @code
 * auto& detector = DLLInjectionDetector::Instance();
 * 
 * // Analyze a specific process
 * auto result = detector.AnalyzeProcess(targetPid);
 * for (const auto& injection : result.detectedInjections) {
 *     std::wcout << L"Injection detected: " << injection.dllInfo.dllPath << std::endl;
 * }
 * 
 * // Start real-time monitoring
 * detector.RegisterCallback([](const DLLInjectionEvent& event) {
 *     // Handle injection event
 * });
 * detector.StartMonitoring();
 * @endcode
 */
class DLLInjectionDetector {
public:
    // ========================================================================
    // SINGLETON ACCESS
    // ========================================================================

    /**
     * @brief Get singleton instance.
     * @return Reference to the singleton instance.
     */
    [[nodiscard]] static DLLInjectionDetector& Instance();

    /**
     * @brief Delete copy constructor.
     */
    DLLInjectionDetector(const DLLInjectionDetector&) = delete;

    /**
     * @brief Delete copy assignment.
     */
    DLLInjectionDetector& operator=(const DLLInjectionDetector&) = delete;

    // ========================================================================
    // LIFECYCLE MANAGEMENT
    // ========================================================================

    /**
     * @brief Initialize the detector.
     * @param config Configuration settings.
     * @return True if initialization succeeded.
     */
    [[nodiscard]] bool Initialize(
        const DLLInjectionConfig& config = DLLInjectionConfig::CreateDefault()
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
    bool UpdateConfig(const DLLInjectionConfig& config);

    /**
     * @brief Get current configuration.
     * @return Current configuration.
     */
    [[nodiscard]] DLLInjectionConfig GetConfig() const;

    // ========================================================================
    // MODULE LOAD ANALYSIS
    // ========================================================================

    /**
     * @brief Analyze a recently loaded DLL.
     * @param pid Process ID.
     * @param dllPath Path to the loaded DLL.
     * @return Analysis result for the DLL.
     */
    [[nodiscard]] LoadedDLLInfo AnalyzeLoad(
        uint32_t pid,
        const std::wstring& dllPath
    );

    /**
     * @brief Analyze all modules loaded in a process.
     * @param pid Process ID.
     * @return Complete analysis result.
     */
    [[nodiscard]] InjectionAnalysisResult AnalyzeProcess(uint32_t pid);

    /**
     * @brief Analyze a specific module.
     * @param pid Process ID.
     * @param moduleBase Base address of the module.
     * @return DLL information.
     */
    [[nodiscard]] LoadedDLLInfo AnalyzeModule(
        uint32_t pid,
        uintptr_t moduleBase
    );

    /**
     * @brief Check if a DLL load is suspicious.
     * @param pid Process ID.
     * @param dllPath DLL path.
     * @return True if suspicious.
     */
    [[nodiscard]] bool IsSuspiciousLoad(
        uint32_t pid,
        const std::wstring& dllPath
    );

    /**
     * @brief Get trust level for a DLL.
     * @param dllPath DLL path.
     * @return Trust level.
     */
    [[nodiscard]] TrustLevel GetTrustLevel(const std::wstring& dllPath);

    // ========================================================================
    // INJECTION DETECTION
    // ========================================================================

    /**
     * @brief Detect injected DLLs in a process.
     * @param pid Process ID.
     * @return Vector of detected injections.
     */
    [[nodiscard]] std::vector<DLLInjectionEvent> DetectInjections(uint32_t pid);

    /**
     * @brief Check if a specific DLL was injected.
     * @param pid Process ID.
     * @param dllPath DLL path.
     * @return True if injected.
     */
    [[nodiscard]] bool IsInjected(uint32_t pid, const std::wstring& dllPath);

    /**
     * @brief Find the injector process.
     * @param pid Target process ID.
     * @param dllPath Injected DLL path.
     * @return Injector PID, or 0 if unknown.
     */
    [[nodiscard]] uint32_t FindInjector(
        uint32_t pid,
        const std::wstring& dllPath
    );

    /**
     * @brief Detect remote thread injection.
     * @param pid Process ID.
     * @return Injection events.
     */
    [[nodiscard]] std::vector<DLLInjectionEvent> DetectRemoteThreadInjection(
        uint32_t pid
    );

    /**
     * @brief Detect APC-based injection.
     * @param pid Process ID.
     * @return Injection events.
     */
    [[nodiscard]] std::vector<DLLInjectionEvent> DetectAPCInjection(uint32_t pid);

    // ========================================================================
    // HOOK DETECTION
    // ========================================================================

    /**
     * @brief Enumerate all installed hooks in the system.
     * @return Vector of hook information.
     */
    [[nodiscard]] std::vector<HookInfo> EnumerateHooks();

    /**
     * @brief Get hooks installed by a specific process.
     * @param pid Process ID.
     * @return Vector of hooks.
     */
    [[nodiscard]] std::vector<HookInfo> GetProcessHooks(uint32_t pid);

    /**
     * @brief Check for suspicious global hooks.
     * @return Vector of suspicious hooks.
     */
    [[nodiscard]] std::vector<HookInfo> FindSuspiciousHooks();

    /**
     * @brief Detect hook-based injection targeting a process.
     * @param pid Target process ID.
     * @return Injection events.
     */
    [[nodiscard]] std::vector<DLLInjectionEvent> DetectHookInjection(uint32_t pid);

    // ========================================================================
    // REGISTRY-BASED VECTORS
    // ========================================================================

    /**
     * @brief Check AppInit_DLLs registry for injection.
     * @return Registry injection vectors.
     */
    [[nodiscard]] std::vector<RegistryInjectionVector> CheckAppInitDLLs();

    /**
     * @brief Check Image File Execution Options.
     * @return Registry injection vectors.
     */
    [[nodiscard]] std::vector<RegistryInjectionVector> CheckIFEO();

    /**
     * @brief Check all registry-based injection vectors.
     * @return All registry vectors.
     */
    [[nodiscard]] std::vector<RegistryInjectionVector> CheckAllRegistryVectors();

    /**
     * @brief Monitor registry keys for injection vectors.
     * @param callback Callback for changes.
     * @return True if monitoring started.
     */
    bool MonitorRegistryVectors(
        std::function<void(const RegistryInjectionVector&)> callback
    );

    // ========================================================================
    // SIDE-LOADING DETECTION
    // ========================================================================

    /**
     * @brief Detect potential DLL side-loading.
     * @param pid Process ID.
     * @return Side-load information.
     */
    [[nodiscard]] std::vector<SideLoadInfo> DetectSideLoading(uint32_t pid);

    /**
     * @brief Check if a DLL is being side-loaded.
     * @param executablePath Executable loading the DLL.
     * @param dllPath DLL being loaded.
     * @return True if side-loading.
     */
    [[nodiscard]] bool IsSideLoaded(
        const std::wstring& executablePath,
        const std::wstring& dllPath
    );

    /**
     * @brief Detect search order hijacking.
     * @param pid Process ID.
     * @return Injection events.
     */
    [[nodiscard]] std::vector<DLLInjectionEvent> DetectSearchOrderHijack(
        uint32_t pid
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
     * @brief Set monitoring mode.
     * @param mode New monitoring mode.
     */
    void SetMonitoringMode(DLLMonitoringMode mode);

    /**
     * @brief Get current monitoring mode.
     * @return Current mode.
     */
    [[nodiscard]] DLLMonitoringMode GetMonitoringMode() const noexcept;

    // ========================================================================
    // EVENT HANDLERS (from kernel/ETW)
    // ========================================================================

    /**
     * @brief Notify of module load event.
     * @param pid Process ID.
     * @param dllPath DLL path.
     * @param baseAddress Base address.
     * @param size Module size.
     */
    void OnModuleLoad(
        uint32_t pid,
        const std::wstring& dllPath,
        uintptr_t baseAddress,
        size_t size
    );

    /**
     * @brief Notify of thread creation.
     * @param targetPid Target process ID.
     * @param creatorPid Creator process ID.
     * @param startAddress Thread start address.
     */
    void OnThreadCreate(
        uint32_t targetPid,
        uint32_t creatorPid,
        uintptr_t startAddress
    );

    /**
     * @brief Notify of APC queue.
     * @param targetPid Target process ID.
     * @param targetTid Target thread ID.
     * @param queuedBy Queuing process ID.
     * @param apcRoutine APC routine address.
     */
    void OnAPCQueue(
        uint32_t targetPid,
        uint32_t targetTid,
        uint32_t queuedBy,
        uintptr_t apcRoutine
    );

    /**
     * @brief Notify of hook installation.
     * @param hookType Hook type.
     * @param threadId Target thread ID.
     * @param hookProc Hook procedure address.
     * @param installerPid Installer process ID.
     */
    void OnHookInstall(
        int hookType,
        uint32_t threadId,
        uintptr_t hookProc,
        uint32_t installerPid
    );

    // ========================================================================
    // CALLBACK REGISTRATION
    // ========================================================================

    /**
     * @brief Register callback for injection detection.
     * @param callback Callback function.
     * @return Callback ID.
     */
    uint64_t RegisterCallback(DLLInjectionDetectedCallback callback);

    /**
     * @brief Register callback for module loads.
     * @param callback Callback function.
     * @return Callback ID.
     */
    uint64_t RegisterModuleCallback(ModuleLoadCallback callback);

    /**
     * @brief Register callback for load decisions.
     * @param callback Callback function.
     * @return Callback ID.
     */
    uint64_t RegisterDecisionCallback(LoadDecisionCallback callback);

    /**
     * @brief Register callback for hook installations.
     * @param callback Callback function.
     * @return Callback ID.
     */
    uint64_t RegisterHookCallback(HookInstalledCallback callback);

    /**
     * @brief Unregister a callback.
     * @param callbackId Callback ID.
     */
    void UnregisterCallback(uint64_t callbackId);

    // ========================================================================
    // WHITELIST MANAGEMENT
    // ========================================================================

    /**
     * @brief Add DLL to whitelist.
     * @param dllPath DLL path.
     */
    void AddToWhitelist(const std::wstring& dllPath);

    /**
     * @brief Remove DLL from whitelist.
     * @param dllPath DLL path.
     */
    void RemoveFromWhitelist(const std::wstring& dllPath);

    /**
     * @brief Check if DLL is whitelisted.
     * @param dllPath DLL path.
     * @return True if whitelisted.
     */
    [[nodiscard]] bool IsWhitelisted(const std::wstring& dllPath) const;

    /**
     * @brief Add process to exclusion list.
     * @param processName Process name.
     */
    void ExcludeProcess(const std::wstring& processName);

    /**
     * @brief Remove process from exclusion list.
     * @param processName Process name.
     */
    void IncludeProcess(const std::wstring& processName);

    // ========================================================================
    // EXTERNAL STORE INJECTION (called by orchestrator after Initialize)
    // ========================================================================

    /**
     * @brief Connect an external HashStore for threat-intel hash lookups.
     * @param store Non-owning pointer; caller must ensure lifetime >= detector.
     */
    void SetHashStore(HashStore::HashStore* store) noexcept;

    /**
     * @brief Connect an external WhitelistStore for path whitelist checks.
     * @param store Non-owning pointer; caller must ensure lifetime >= detector.
     */
    void SetWhitelistStore(Whitelist::WhitelistStore* store) noexcept;

    // ========================================================================
    // STATISTICS
    // ========================================================================

    /**
     * @brief Get detector statistics.
     * @return Current statistics.
     */
    [[nodiscard]] DLLInjectionStatistics GetStatistics() const;

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
     * @brief Convert injection type to string.
     * @param type Injection type.
     * @return String representation.
     */
    [[nodiscard]] static std::wstring InjectionTypeToString(
        DLLInjectionType type
    ) noexcept;

    /**
     * @brief Convert trust level to string.
     * @param level Trust level.
     * @return String representation.
     */
    [[nodiscard]] static std::wstring TrustLevelToString(
        TrustLevel level
    ) noexcept;

private:
    // ========================================================================
    // PRIVATE CONSTRUCTOR (SINGLETON)
    // ========================================================================

    DLLInjectionDetector();
    ~DLLInjectionDetector();

    // ========================================================================
    // IMPLEMENTATION
    // ========================================================================

    std::unique_ptr<DLLInjectionDetectorImpl> m_impl;
};

} // namespace Process
} // namespace Core
} // namespace ShadowStrike
