/**
 * @file ProcessEvasionDetector.hpp
 * @brief Enterprise-grade detection of process-based evasion techniques
 *
 * ShadowStrike AntiEvasion - Process Evasion Detection Module
 * Copyright (c) 2026 ShadowStrike Security Suite. All rights reserved.
 *
 * This module provides comprehensive detection of malware using process manipulation
 * and injection techniques to evade detection and analysis.
 *
 * =============================================================================
 * DETECTED TECHNIQUES (MITRE ATT&CK T1055 - Process Injection)
 * =============================================================================
 *
 * 1. PROCESS INJECTION:
 *    - Classic DLL injection (CreateRemoteThread + LoadLibrary)
 *    - Reflective DLL injection (manual PE loading)
 *    - Process hollowing (RunPE technique)
 *    - Thread hijacking (SuspendThread + SetThreadContext)
 *    - APC injection (QueueUserAPC)
 *    - AtomBombing (NtQueueApcThread + GlobalAddAtom)
 *    - Process Doppelgänging (NTFS transactions)
 *    - Process Herpaderping (obscure file mapping)
 *
 * 2. CODE INJECTION DETECTION:
 *    - Suspicious memory allocations (VirtualAllocEx with RWX)
 *    - Cross-process memory writes (WriteProcessMemory)
 *    - Remote thread creation (CreateRemoteThread, NtCreateThreadEx)
 *    - Shellcode pattern detection in process memory
 *    - Hook detection in system DLLs
 *    - IAT (Import Address Table) hooking
 *    - Inline hooking (function prologue modification)
 *
 * 3. PROCESS MASQUERADING:
 *    - Legitimate process name abuse (svchost.exe, explorer.exe)
 *    - Parent process spoofing (wrong parent PID)
 *    - Process path anomalies (svchost.exe not in System32)
 *    - Command line inconsistencies
 *    - Digital signature validation failures
 *
 * 4. ANTI-DEBUGGING:
 *    - IsDebuggerPresent checks
 *    - CheckRemoteDebuggerPresent usage
 *    - NtQueryInformationProcess (ProcessDebugPort)
 *    - Debug object detection (NtQueryObject)
 *    - Hardware breakpoint detection (debug registers DR0-DR7)
 *    - Software breakpoint detection (0xCC opcode scanning)
 *    - Timing-based debugger detection
 *    - Parent process debugger check
 *
 * 5. PROCESS ENUMERATION EVASION:
 *    - Hidden processes (rootkit techniques)
 *    - DKOM (Direct Kernel Object Manipulation)
 *    - PEB (Process Environment Block) manipulation
 *    - Process name randomization
 *    - Temporary process creation/deletion
 *
 * 6. PRIVILEGE ESCALATION:
 *    - SeDebugPrivilege acquisition
 *    - Token manipulation (impersonation)
 *    - UAC bypass techniques
 *    - Process integrity level anomalies
 *    - SYSTEM process impersonation
 *
 * =============================================================================
 * ARCHITECTURE
 * =============================================================================
 *
 * ┌─────────────────────────────────────────────────────────────────────────┐
 * │                     ProcessEvasionDetector                              │
 * ├─────────────────────────────────────────────────────────────────────────┤
 * │  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐         │
 * │  │ Injection       │  │ Masquerading    │  │ Anti-Debug      │         │
 * │  │ - DLL inject    │  │ - Name abuse    │  │ - Debugger chk  │         │
 * │  │ - Hollowing     │  │ - Parent spoof  │  │ - Breakpoints   │         │
 * │  │ - APC/Atom      │  │ - Path anomaly  │  │ - Timing        │         │
 * │  └─────────────────┘  └─────────────────┘  └─────────────────┘         │
 * │           │                   │                   │                     │
 * │  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐         │
 * │  │ Code Injection  │  │ Privilege Esc   │  │ Enumeration     │         │
 * │  │ - RWX memory    │  │ - SeDebug       │  │ - Hidden proc   │         │
 * │  │ - Remote thread │  │ - Token manip   │  │ - PEB manip     │         │
 * │  │ - Hooks (IAT)   │  │ - UAC bypass    │  │ - DKOM          │         │
 * │  └─────────────────┘  └─────────────────┘  └─────────────────┘         │
 * │           │                   │                   │                     │
 * │           └───────────────────┼───────────────────┘                     │
 * │                               ▼                                         │
 * │                    ┌─────────────────────┐                              │
 * │                    │   Scoring Engine    │                              │
 * │                    │  - Weight system    │                              │
 * │                    │  - Correlation      │                              │
 * │                    │  - Threshold calc   │                              │
 * │                    └─────────────────────┘                              │
 * │                               │                                         │
 * │                               ▼                                         │
 * │                    ┌─────────────────────┐                              │
 * │                    │  Result Aggregator  │                              │
 * │                    │  - MITRE mapping    │                              │
 * │                    │  - Severity         │                              │
 * │                    └─────────────────────┘                              │
 * └─────────────────────────────────────────────────────────────────────────┘
 *
 * @note Thread-safe for all public methods.
 * @note Requires administrator privileges for full detection capabilities.
 *
 * @author ShadowStrike Security Team
 * @copyright (c) 2026 ShadowStrike Security Suite. All rights reserved.
 */

#pragma once

// ============================================================================
// INFRASTRUCTURE INCLUDES
// ============================================================================
#include "../Utils/ProcessUtils.hpp"
#include "../Utils/SystemUtils.hpp"
#include "../Utils/FileUtils.hpp"

// ============================================================================
// STANDARD LIBRARY INCLUDES
// ============================================================================
#include <atomic>
#include <array>
#include <bitset>
#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <shared_mutex>
#include <span>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
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

namespace ShadowStrike::AntiEvasion {

    // ========================================================================
    // FORWARD DECLARATIONS
    // ========================================================================

    class ProcessEvasionDetector;
    struct ProcessEvasionResult;
    struct ProcessInjectionInfo;

    // ========================================================================
    // CONSTANTS
    // ========================================================================

    namespace ProcessEvasionConstants {
        /// @brief Maximum processes to track
        inline constexpr size_t MAX_TRACKED_PROCESSES = 10000;

        /// @brief Maximum detections per process
        inline constexpr size_t MAX_DETECTIONS_PER_PROCESS = 100;

        /// @brief Cache TTL (seconds)
        inline constexpr uint32_t CACHE_TTL_SECONDS = 300;

        /// @brief Minimum evasion score for detection
        inline constexpr float MIN_EVASION_SCORE = 50.0f;

        /// @brief High confidence threshold
        inline constexpr float HIGH_CONFIDENCE_THRESHOLD = 80.0f;
    }

    // ========================================================================
    // ENUMERATIONS
    // ========================================================================

    /**
     * @brief Process evasion technique categories
     */
    enum class ProcessEvasionTechnique : uint16_t {
        Unknown = 0,

        // Injection (1-50)
        INJ_ClassicDLLInjection = 1,
        INJ_ReflectiveDLLInjection = 2,
        INJ_ProcessHollowing = 3,
        INJ_ThreadHijacking = 4,
        INJ_APCInjection = 5,
        INJ_AtomBombing = 6,
        INJ_ProcessDoppelganging = 7,
        INJ_ProcessHerpaderping = 8,
        INJ_EarlyBirdInjection = 9,
        INJ_ExtraWindowMemory = 10,

        // Code Injection Detection (51-100)
        CODE_SuspiciousMemoryAlloc = 51,
        CODE_CrossProcessWrite = 52,
        CODE_RemoteThreadCreation = 53,
        CODE_ShellcodePattern = 54,
        CODE_IATHooking = 55,
        CODE_InlineHooking = 56,
        CODE_VEHHooking = 57,
        CODE_TrampolineHook = 58,

        // Masquerading (101-150)
        MASK_LegitProcessNameAbuse = 101,
        MASK_ParentProcessSpoofing = 102,
        MASK_PathAnomaly = 103,
        MASK_CommandLineInconsistency = 104,
        MASK_SignatureValidationFailure = 105,
        MASK_DoubleExtension = 106,
        MASK_IconMismatch = 107,

        // Anti-Debugging (151-200)
        ANTI_IsDebuggerPresent = 151,
        ANTI_CheckRemoteDebugger = 152,
        ANTI_NtQueryInformationProcess = 153,
        ANTI_DebugObjectDetection = 154,
        ANTI_HardwareBreakpointDetection = 155,
        ANTI_SoftwareBreakpointDetection = 156,
        ANTI_TimingBasedDebuggerDetection = 157,
        ANTI_ParentProcessDebugger = 158,
        ANTI_SEHAntiDebug = 159,
        ANTI_OutputDebugString = 160,

        // Privilege Escalation (201-250)
        PRIV_SeDebugPrivilege = 201,
        PRIV_TokenManipulation = 202,
        PRIV_UACBypass = 203,
        PRIV_IntegrityLevelAnomaly = 204,
        PRIV_ImpersonationToken = 205,

        // Enumeration Evasion (251-300)
        ENUM_HiddenProcess = 251,
        ENUM_DKOM = 252,
        ENUM_PEBManipulation = 253,
        ENUM_ProcessNameRandomization = 254,
        ENUM_TemporaryProcessCreation = 255,
    };

    /**
     * @brief Injection method types
     */
    enum class InjectionMethod : uint8_t {
        Unknown = 0,
        ClassicDLL = 1,
        ReflectiveDLL = 2,
        ProcessHollowing = 3,
        ThreadHijacking = 4,
        APC = 5,
        AtomBombing = 6,
        Doppelganging = 7,
        Herpaderping = 8,
    };

    /**
     * @brief Process evasion severity
     */
    enum class ProcessEvasionSeverity : uint8_t {
        Low = 0,
        Medium = 1,
        High = 2,
        Critical = 3,
    };

    /**
     * @brief Analysis configuration flags
     */
    enum class ProcessAnalysisFlags : uint32_t {
        None = 0,
        CheckInjection = 1 << 0,
        CheckMasquerading = 1 << 1,
        CheckAntiDebug = 1 << 2,
        CheckPrivilegeEscalation = 1 << 3,
        CheckEnumeration = 1 << 4,
        CheckMemory = 1 << 5,
        CheckThreads = 1 << 6,
        CheckModules = 1 << 7,
        EnableCaching = 1 << 8,
        DeepAnalysis = 1 << 9,

        All = 0xFFFFFFFF,
        Default = CheckInjection | CheckMasquerading | CheckAntiDebug | EnableCaching,
    };

    // Bitwise operations for flags
    [[nodiscard]] constexpr ProcessAnalysisFlags operator|(ProcessAnalysisFlags a, ProcessAnalysisFlags b) noexcept {
        return static_cast<ProcessAnalysisFlags>(static_cast<uint32_t>(a) | static_cast<uint32_t>(b));
    }

    [[nodiscard]] constexpr ProcessAnalysisFlags operator&(ProcessAnalysisFlags a, ProcessAnalysisFlags b) noexcept {
        return static_cast<ProcessAnalysisFlags>(static_cast<uint32_t>(a) & static_cast<uint32_t>(b));
    }

    [[nodiscard]] constexpr bool HasFlag(ProcessAnalysisFlags flags, ProcessAnalysisFlags flag) noexcept {
        return (flags & flag) == flag;
    }

    // ========================================================================
    // STRUCTURES
    // ========================================================================

    /**
     * @brief Error information for process evasion operations
     */
    struct ProcessEvasionError {
        DWORD win32Code = 0;
        std::wstring message;
        std::wstring context;

        [[nodiscard]] bool IsError() const noexcept {
            return win32Code != 0 || !message.empty();
        }

        void Reset() noexcept {
            win32Code = 0;
            message.clear();
            context.clear();
        }
    };

    /**
     * @brief Detected evasion technique
     */
    struct DetectedTechnique {
        ProcessEvasionTechnique technique = ProcessEvasionTechnique::Unknown;
        ProcessEvasionSeverity severity = ProcessEvasionSeverity::Low;
        double confidence = 0.0;
        std::wstring description;
        std::wstring technicalDetails;
        std::chrono::system_clock::time_point timestamp;

        DetectedTechnique() = default;
        explicit DetectedTechnique(ProcessEvasionTechnique tech) : technique(tech) {
            timestamp = std::chrono::system_clock::now();
        }
    };

    /**
     * @brief Process injection detection information
     */
    struct ProcessInjectionInfo {
        bool hasInjection = false;
        InjectionMethod method = InjectionMethod::Unknown;
        uint32_t injectedThreadCount = 0;
        uint64_t suspiciousMemoryRegions = 0;
        std::vector<uint64_t> rwxMemoryAddresses;
        std::vector<std::wstring> injectedDLLs;
        bool hasRemoteThreads = false;
        bool hasHollowedImage = false;
        bool valid = false;
    };

    /**
     * @brief Process masquerading information
     */
    struct ProcessMasqueradingInfo {
        bool isMasquerading = false;
        std::wstring expectedPath;
        std::wstring actualPath;
        std::wstring expectedParent;
        std::wstring actualParent;
        bool hasPathAnomaly = false;
        bool hasParentSpoof = false;
        bool hasSignatureFailure = false;
        bool valid = false;
    };

    /**
     * @brief Anti-debugging detection information
     */
    struct AntiDebugInfo {
        bool hasAntiDebug = false;
        bool isDebuggerPresent = false;
        bool hasDebugPrivilege = false;
        bool hasHardwareBreakpoints = false;
        bool hasSoftwareBreakpoints = false;
        std::vector<std::wstring> detectedTechniques;
        bool valid = false;
    };

    /**
     * @brief Memory region information
     */
    struct MemoryRegionInfo {
        uint64_t baseAddress = 0;
        uint64_t size = 0;
        uint32_t protection = 0;
        uint32_t type = 0;
        bool isExecutable = false;
        bool isWritable = false;
        bool isReadable = false;
        bool isSuspicious = false;
        std::wstring description;
    };

    /**
     * @brief Analysis configuration
     */
    struct ProcessAnalysisConfig {
        ProcessAnalysisFlags flags = ProcessAnalysisFlags::Default;
        uint32_t cacheTtlSeconds = ProcessEvasionConstants::CACHE_TTL_SECONDS;
        bool enableDeepScan = false;
        bool checkAllThreads = true;
        bool checkAllModules = true;
    };

    /**
     * @brief Process evasion analysis result
     */
    struct ProcessEvasionResult {
        // Process information
        uint32_t processId = 0;
        std::wstring processName;
        std::wstring processPath;
        uint32_t parentProcessId = 0;
        std::wstring parentProcessName;

        // Detection results
        bool isEvasive = false;
        float evasionScore = 0.0f;
        ProcessEvasionSeverity maxSeverity = ProcessEvasionSeverity::Low;
        std::wstring confidenceLevel;

        // Specific detection info
        ProcessInjectionInfo injectionInfo;
        ProcessMasqueradingInfo masqueradingInfo;
        AntiDebugInfo antiDebugInfo;
        std::vector<MemoryRegionInfo> suspiciousMemoryRegions;

        // Detected techniques
        std::vector<DetectedTechnique> detectedTechniques;
        uint32_t totalDetections = 0;
        uint32_t detectedCategories = 0; // Bitmask

        // Analysis metadata
        ProcessAnalysisConfig config;
        std::chrono::system_clock::time_point analysisStartTime;
        std::chrono::system_clock::time_point analysisEndTime;
        uint64_t analysisDurationMs = 0;
        bool analysisComplete = false;
        bool fromCache = false;

        /**
         * @brief Get technique with highest confidence
         */
        [[nodiscard]] const DetectedTechnique* GetHighestConfidence() const noexcept {
            if (detectedTechniques.empty()) return nullptr;

            const auto* best = &detectedTechniques[0];
            for (const auto& tech : detectedTechniques) {
                if (tech.confidence > best->confidence) {
                    best = &tech;
                }
            }
            return best;
        }
    };

    // ========================================================================
    // CALLBACKS
    // ========================================================================

    using ProcessDetectionCallback = std::function<void(uint32_t processId, const DetectedTechnique& technique)>;

    // ========================================================================
    // MAIN DETECTOR CLASS
    // ========================================================================

    /**
     * @brief Enterprise-grade process evasion detector
     *
     * Thread-safe detector for process-based evasion techniques including
     * injection, masquerading, anti-debugging, and privilege escalation.
     */
    class ProcessEvasionDetector final {
    public:
        // ====================================================================
        // CONSTRUCTION / DESTRUCTION
        // ====================================================================

        ProcessEvasionDetector() noexcept;
        ~ProcessEvasionDetector();

        // Non-copyable, movable
        ProcessEvasionDetector(const ProcessEvasionDetector&) = delete;
        ProcessEvasionDetector& operator=(const ProcessEvasionDetector&) = delete;
        ProcessEvasionDetector(ProcessEvasionDetector&&) noexcept;
        ProcessEvasionDetector& operator=(ProcessEvasionDetector&&) noexcept;

        // ====================================================================
        // INITIALIZATION
        // ====================================================================

        /**
         * @brief Initialize detector
         */
        [[nodiscard]] bool Initialize(ProcessEvasionError* err = nullptr) noexcept;

        /**
         * @brief Shutdown detector
         */
        void Shutdown() noexcept;

        /**
         * @brief Check if initialized
         */
        [[nodiscard]] bool IsInitialized() const noexcept;

        // ====================================================================
        // PROCESS ANALYSIS
        // ====================================================================

        /**
         * @brief Analyze process for evasion techniques
         */
        [[nodiscard]] ProcessEvasionResult AnalyzeProcess(
            uint32_t processId,
            const ProcessAnalysisConfig& config = ProcessAnalysisConfig{},
            ProcessEvasionError* err = nullptr
        ) noexcept;

        /**
         * @brief Analyze process by handle
         */
        [[nodiscard]] ProcessEvasionResult AnalyzeProcess(
            HANDLE hProcess,
            const ProcessAnalysisConfig& config = ProcessAnalysisConfig{},
            ProcessEvasionError* err = nullptr
        ) noexcept;

        /**
         * @brief Analyze multiple processes
         */
        [[nodiscard]] std::vector<ProcessEvasionResult> AnalyzeProcesses(
            const std::vector<uint32_t>& processIds,
            const ProcessAnalysisConfig& config = ProcessAnalysisConfig{},
            ProcessEvasionError* err = nullptr
        ) noexcept;

        // ====================================================================
        // SPECIFIC DETECTION METHODS
        // ====================================================================

        /**
         * @brief Detect process injection
         */
        [[nodiscard]] bool DetectInjection(
            uint32_t processId,
            ProcessInjectionInfo& outInfo,
            ProcessEvasionError* err = nullptr
        ) noexcept;

        /**
         * @brief Detect process masquerading
         */
        [[nodiscard]] bool DetectMasquerading(
            uint32_t processId,
            ProcessMasqueradingInfo& outInfo,
            ProcessEvasionError* err = nullptr
        ) noexcept;

        /**
         * @brief Detect anti-debugging techniques
         */
        [[nodiscard]] bool DetectAntiDebug(
            uint32_t processId,
            AntiDebugInfo& outInfo,
            ProcessEvasionError* err = nullptr
        ) noexcept;

        /**
         * @brief Scan process memory for suspicious regions
         */
        [[nodiscard]] bool ScanMemory(
            uint32_t processId,
            std::vector<MemoryRegionInfo>& outRegions,
            ProcessEvasionError* err = nullptr
        ) noexcept;

        // ====================================================================
        // CALLBACKS
        // ====================================================================

        void SetDetectionCallback(ProcessDetectionCallback callback) noexcept;
        void ClearDetectionCallback() noexcept;

        // ====================================================================
        // CACHING
        // ====================================================================

        [[nodiscard]] std::optional<ProcessEvasionResult> GetCachedResult(uint32_t processId) const noexcept;
        void InvalidateCache(uint32_t processId) noexcept;
        void ClearCache() noexcept;
        [[nodiscard]] size_t GetCacheSize() const noexcept;

        // ====================================================================
        // STATISTICS
        // ====================================================================

        struct Statistics {
            std::atomic<uint64_t> totalAnalyses{ 0 };
            std::atomic<uint64_t> evasiveProcesses{ 0 };
            std::atomic<uint64_t> injectionsDetected{ 0 };
            std::atomic<uint64_t> masqueradingDetected{ 0 };
            std::atomic<uint64_t> antiDebugDetected{ 0 };
            std::atomic<uint64_t> totalDetections{ 0 };
            std::atomic<uint64_t> cacheHits{ 0 };
            std::atomic<uint64_t> cacheMisses{ 0 };
            std::atomic<uint64_t> analysisErrors{ 0 };
            std::atomic<uint64_t> totalAnalysisTimeUs{ 0 };
            std::array<std::atomic<uint64_t>, 8> categoryDetections{};

            void Reset() noexcept {
                totalAnalyses = 0;
                evasiveProcesses = 0;
                injectionsDetected = 0;
                masqueradingDetected = 0;
                antiDebugDetected = 0;
                totalDetections = 0;
                cacheHits = 0;
                cacheMisses = 0;
                analysisErrors = 0;
                totalAnalysisTimeUs = 0;
                for (auto& cat : categoryDetections) cat = 0;
            }

            [[nodiscard]] double GetAverageAnalysisTimeMs() const noexcept {
                const uint64_t total = totalAnalyses.load();
                if (total == 0) return 0.0;
                return static_cast<double>(totalAnalysisTimeUs.load()) / (total * 1000.0);
            }
        };

        [[nodiscard]] const Statistics& GetStatistics() const noexcept;
        void ResetStatistics() noexcept;

    private:
        // ====================================================================
        // PIMPL
        // ====================================================================

        class Impl;
        std::unique_ptr<Impl> m_impl;

        // Internal methods
        void AnalyzeProcessInternal(
            HANDLE hProcess,
            uint32_t processId,
            const ProcessAnalysisConfig& config,
            ProcessEvasionResult& result
        ) noexcept;

        void CheckInjectionTechniques(
            HANDLE hProcess,
            ProcessEvasionResult& result
        ) noexcept;

        void CheckMasqueradingTechniques(
            HANDLE hProcess,
            uint32_t processId,
            ProcessEvasionResult& result
        ) noexcept;

        void CheckAntiDebugTechniques(
            HANDLE hProcess,
            ProcessEvasionResult& result
        ) noexcept;

        void CalculateEvasionScore(ProcessEvasionResult& result) noexcept;

        void AddDetection(
            ProcessEvasionResult& result,
            DetectedTechnique detection
        ) noexcept;

        void UpdateCache(
            uint32_t processId,
            const ProcessEvasionResult& result
        ) noexcept;
    };

} // namespace ShadowStrike::AntiEvasion
