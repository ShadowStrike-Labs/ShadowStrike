/**
 * @file ProcessEvasionDetector.cpp
 * @brief Enterprise-grade detection of process-based evasion techniques
 *
 * ShadowStrike AntiEvasion - Process Evasion Detection Module
 * Copyright (c) 2026 ShadowStrike Security Suite. All rights reserved.
 *
 * This module provides comprehensive detection of malware using process manipulation
 * and injection techniques to evade detection and analysis.
 *
 * Implementation follows enterprise C++20 standards:
 * - PIMPL pattern for ABI stability
 * - Thread-safe with std::shared_mutex
 * - Exception-safe with comprehensive error handling
 * - Statistics tracking for all operations
 * - Memory-safe with smart pointers only
 * - Infrastructure reuse (Utils/, PatternStore, PEParser)
 * - Zydis disassembler for advanced code analysis
 */

#include "pch.h"
#include "ProcessEvasionDetector.hpp"

// ============================================================================
// STANDARD LIBRARY INCLUDES
// ============================================================================

#include <algorithm>
#include <cmath>
#include <execution>
#include <numeric>
#include <queue>
#include <sstream>
#include <format>

// ============================================================================
// WINDOWS SDK INCLUDES
// ============================================================================

#include <psapi.h>
#pragma comment(lib, "psapi.lib")

#include <tlhelp32.h>
#include <wintrust.h>
#include <softpub.h>
#pragma comment(lib, "wintrust.lib")

// ============================================================================
// ZYDIS DISASSEMBLER
// ============================================================================

#include <Zydis/Zydis.h>

// ============================================================================
// SHADOWSTRIKE INTERNAL INCLUDES
// ============================================================================

#include "../Utils/StringUtils.hpp"
#include "../Utils/Logger.hpp"
#include "../Utils/ProcessUtils.hpp"
#include "../Utils/SystemUtils.hpp"
#include "../Utils/FileUtils.hpp"
#include "../Utils/MemoryUtils.hpp"
#include "../PatternStore/PatternStore.hpp"
#include "../PEParser/PEParser.hpp"

// ============================================================================
// INTERNAL DEFINITIONS
// ============================================================================

#ifndef ThreadQuerySetWin32StartAddress
#define ThreadQuerySetWin32StartAddress 9
#endif

#ifndef ProcessDebugPort
#define ProcessDebugPort 7
#endif

#ifndef ProcessDebugObjectHandle
#define ProcessDebugObjectHandle 30
#endif

#ifndef ProcessDebugFlags
#define ProcessDebugFlags 31
#endif

typedef NTSTATUS(WINAPI* NtQueryInformationThreadPtr)(
    HANDLE ThreadHandle,
    THREADINFOCLASS ThreadInformationClass,
    PVOID ThreadInformation,
    ULONG ThreadInformationLength,
    PULONG ReturnLength
);

typedef NTSTATUS(WINAPI* NtQueryInformationProcessPtr)(
    HANDLE ProcessHandle,
    PROCESSINFOCLASS ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength
);

namespace ShadowStrike::AntiEvasion {

    // ========================================================================
    // LOGGING CATEGORY
    // ========================================================================

    static constexpr const wchar_t* LOG_CATEGORY = L"ProcessEvasion";

    // ========================================================================
    // INTERNAL CONSTANTS
    // ========================================================================

    namespace {
        /// Maximum bytes to read for hook analysis
        constexpr size_t MAX_HOOK_SCAN_BYTES = 64;

        /// Maximum instructions to disassemble per function
        constexpr size_t MAX_INSTRUCTIONS_PER_FUNCTION = 32;

        /// Memory scan buffer size
        constexpr size_t MEMORY_SCAN_BUFFER_SIZE = 4096;

        /// Maximum modules to enumerate
        constexpr size_t MAX_MODULES = 2048;

        /// Suspicious API patterns for anti-debug detection
        const std::vector<std::string> ANTI_DEBUG_APIS = {
            "IsDebuggerPresent",
            "CheckRemoteDebuggerPresent",
            "NtQueryInformationProcess",
            "NtSetInformationThread",
            "NtQuerySystemInformation",
            "OutputDebugStringA",
            "OutputDebugStringW",
            "GetTickCount",
            "GetTickCount64",
            "QueryPerformanceCounter",
            "rdtsc"
        };

        /// Suspicious API patterns for injection detection
        const std::vector<std::string> INJECTION_APIS = {
            "VirtualAllocEx",
            "VirtualProtectEx",
            "WriteProcessMemory",
            "CreateRemoteThread",
            "CreateRemoteThreadEx",
            "NtCreateThreadEx",
            "RtlCreateUserThread",
            "QueueUserAPC",
            "NtQueueApcThread",
            "SetThreadContext",
            "NtSetContextThread",
            "NtMapViewOfSection",
            "NtUnmapViewOfSection"
        };

        /// Suspicious API patterns for privilege escalation
        const std::vector<std::string> PRIVILEGE_APIS = {
            "AdjustTokenPrivileges",
            "LookupPrivilegeValueW",
            "OpenProcessToken",
            "DuplicateTokenEx",
            "ImpersonateLoggedOnUser",
            "SetTokenInformation",
            "CreateProcessAsUserW",
            "CreateProcessWithTokenW"
        };

        /// Known shellcode byte patterns (common prologues)
        const std::vector<std::vector<uint8_t>> SHELLCODE_PATTERNS = {
            // GetPC via CALL $+5
            {0xE8, 0x00, 0x00, 0x00, 0x00, 0x58},           // call $+5; pop eax
            {0xE8, 0x00, 0x00, 0x00, 0x00, 0x5B},           // call $+5; pop ebx
            // Windows API hash resolution pattern
            {0x60, 0xFC, 0x31, 0xD2, 0x64, 0x8B},           // pushad; cld; xor edx,edx; mov ... fs:[...]
            // Metasploit-style patterns
            {0xFC, 0xE8, 0x82, 0x00, 0x00, 0x00},           // cld; call $+0x87
            {0xFC, 0xE8, 0x89, 0x00, 0x00, 0x00},           // cld; call $+0x8e
            // Cobalt Strike beacon patterns
            {0x4D, 0x5A, 0x41, 0x52, 0x55, 0x48},           // MZ header in memory (reflective)
        };
    }

    // ========================================================================
    // HELPER FUNCTIONS
    // ========================================================================

    /**
     * @brief Get display name for evasion technique
     */
    [[nodiscard]] const wchar_t* ProcessEvasionTechniqueToString(ProcessEvasionTechnique technique) noexcept {
        switch (technique) {
            // Injection
        case ProcessEvasionTechnique::INJ_ClassicDLLInjection: return L"Classic DLL Injection";
        case ProcessEvasionTechnique::INJ_ReflectiveDLLInjection: return L"Reflective DLL Injection";
        case ProcessEvasionTechnique::INJ_ProcessHollowing: return L"Process Hollowing";
        case ProcessEvasionTechnique::INJ_ThreadHijacking: return L"Thread Hijacking";
        case ProcessEvasionTechnique::INJ_APCInjection: return L"APC Injection";
        case ProcessEvasionTechnique::INJ_AtomBombing: return L"AtomBombing";
        case ProcessEvasionTechnique::INJ_ProcessDoppelganging: return L"Process Doppelgänging";
        case ProcessEvasionTechnique::INJ_ProcessHerpaderping: return L"Process Herpaderping";
        case ProcessEvasionTechnique::INJ_EarlyBirdInjection: return L"Early Bird Injection";
        case ProcessEvasionTechnique::INJ_ExtraWindowMemory: return L"Extra Window Memory Injection";

            // Code Injection Detection
        case ProcessEvasionTechnique::CODE_SuspiciousMemoryAlloc: return L"Suspicious Memory Allocation (RWX)";
        case ProcessEvasionTechnique::CODE_CrossProcessWrite: return L"Cross-Process Memory Write";
        case ProcessEvasionTechnique::CODE_RemoteThreadCreation: return L"Remote Thread Creation";
        case ProcessEvasionTechnique::CODE_ShellcodePattern: return L"Shellcode Pattern Detected";
        case ProcessEvasionTechnique::CODE_IATHooking: return L"IAT Hooking";
        case ProcessEvasionTechnique::CODE_InlineHooking: return L"Inline Hooking";
        case ProcessEvasionTechnique::CODE_VEHHooking: return L"VEH Hooking";
        case ProcessEvasionTechnique::CODE_TrampolineHook: return L"Trampoline Hook";

            // Masquerading
        case ProcessEvasionTechnique::MASK_LegitProcessNameAbuse: return L"Legitimate Process Name Abuse";
        case ProcessEvasionTechnique::MASK_ParentProcessSpoofing: return L"Parent Process Spoofing";
        case ProcessEvasionTechnique::MASK_PathAnomaly: return L"Process Path Anomaly";
        case ProcessEvasionTechnique::MASK_CommandLineInconsistency: return L"Command Line Inconsistency";
        case ProcessEvasionTechnique::MASK_SignatureValidationFailure: return L"Signature Validation Failure";
        case ProcessEvasionTechnique::MASK_DoubleExtension: return L"Double Extension";
        case ProcessEvasionTechnique::MASK_IconMismatch: return L"Icon Mismatch";

            // Anti-Debugging
        case ProcessEvasionTechnique::ANTI_IsDebuggerPresent: return L"IsDebuggerPresent Check";
        case ProcessEvasionTechnique::ANTI_CheckRemoteDebugger: return L"CheckRemoteDebuggerPresent";
        case ProcessEvasionTechnique::ANTI_NtQueryInformationProcess: return L"NtQueryInformationProcess (Debug Port)";
        case ProcessEvasionTechnique::ANTI_DebugObjectDetection: return L"Debug Object Detection";
        case ProcessEvasionTechnique::ANTI_HardwareBreakpointDetection: return L"Hardware Breakpoint Detection";
        case ProcessEvasionTechnique::ANTI_SoftwareBreakpointDetection: return L"Software Breakpoint Detection";
        case ProcessEvasionTechnique::ANTI_TimingBasedDebuggerDetection: return L"Timing-Based Debugger Detection";
        case ProcessEvasionTechnique::ANTI_ParentProcessDebugger: return L"Parent Process Debugger Check";
        case ProcessEvasionTechnique::ANTI_SEHAntiDebug: return L"SEH Anti-Debug";
        case ProcessEvasionTechnique::ANTI_OutputDebugString: return L"OutputDebugString Anti-Debug";

            // Privilege Escalation
        case ProcessEvasionTechnique::PRIV_SeDebugPrivilege: return L"SeDebugPrivilege Acquisition";
        case ProcessEvasionTechnique::PRIV_TokenManipulation: return L"Token Manipulation";
        case ProcessEvasionTechnique::PRIV_UACBypass: return L"UAC Bypass";
        case ProcessEvasionTechnique::PRIV_IntegrityLevelAnomaly: return L"Integrity Level Anomaly";
        case ProcessEvasionTechnique::PRIV_ImpersonationToken: return L"Impersonation Token";

            // Enumeration Evasion
        case ProcessEvasionTechnique::ENUM_HiddenProcess: return L"Hidden Process";
        case ProcessEvasionTechnique::ENUM_DKOM: return L"DKOM (Direct Kernel Object Manipulation)";
        case ProcessEvasionTechnique::ENUM_PEBManipulation: return L"PEB Manipulation";
        case ProcessEvasionTechnique::ENUM_ProcessNameRandomization: return L"Process Name Randomization";
        case ProcessEvasionTechnique::ENUM_TemporaryProcessCreation: return L"Temporary Process Creation";

        default: return L"Unknown";
        }
    }

    /**
     * @brief Get display name for injection method
     */
    [[nodiscard]] const wchar_t* InjectionMethodToString(InjectionMethod method) noexcept {
        switch (method) {
        case InjectionMethod::ClassicDLL: return L"Classic DLL Injection";
        case InjectionMethod::ReflectiveDLL: return L"Reflective DLL Injection";
        case InjectionMethod::ProcessHollowing: return L"Process Hollowing";
        case InjectionMethod::ThreadHijacking: return L"Thread Hijacking";
        case InjectionMethod::APC: return L"APC Injection";
        case InjectionMethod::AtomBombing: return L"AtomBombing";
        case InjectionMethod::Doppelganging: return L"Process Doppelgänging";
        case InjectionMethod::Herpaderping: return L"Process Herpaderping";
        default: return L"Unknown";
        }
    }

    /**
     * @brief Get MITRE ATT&CK ID for technique
     */
    [[nodiscard]] const char* ProcessEvasionTechniqueToMitre(ProcessEvasionTechnique technique) noexcept {
        switch (technique) {
        case ProcessEvasionTechnique::INJ_ClassicDLLInjection:
        case ProcessEvasionTechnique::INJ_ReflectiveDLLInjection:
            return "T1055.001";  // DLL Injection
        case ProcessEvasionTechnique::INJ_ProcessHollowing:
            return "T1055.012";  // Process Hollowing
        case ProcessEvasionTechnique::INJ_ThreadHijacking:
            return "T1055.003";  // Thread Execution Hijacking
        case ProcessEvasionTechnique::INJ_APCInjection:
            return "T1055.004";  // Asynchronous Procedure Call
        case ProcessEvasionTechnique::INJ_AtomBombing:
            return "T1055";      // Process Injection
        case ProcessEvasionTechnique::INJ_ProcessDoppelganging:
            return "T1055.013";  // Process Doppelgänging
        case ProcessEvasionTechnique::INJ_ProcessHerpaderping:
            return "T1055";      // Process Injection
        case ProcessEvasionTechnique::MASK_LegitProcessNameAbuse:
        case ProcessEvasionTechnique::MASK_PathAnomaly:
            return "T1036.005";  // Masquerading: Match Legitimate Name
        case ProcessEvasionTechnique::MASK_ParentProcessSpoofing:
            return "T1134.004";  // Parent PID Spoofing
        case ProcessEvasionTechnique::ANTI_IsDebuggerPresent:
        case ProcessEvasionTechnique::ANTI_CheckRemoteDebugger:
        case ProcessEvasionTechnique::ANTI_NtQueryInformationProcess:
        case ProcessEvasionTechnique::ANTI_HardwareBreakpointDetection:
        case ProcessEvasionTechnique::ANTI_SoftwareBreakpointDetection:
        case ProcessEvasionTechnique::ANTI_TimingBasedDebuggerDetection:
            return "T1622";      // Debugger Evasion
        case ProcessEvasionTechnique::PRIV_SeDebugPrivilege:
        case ProcessEvasionTechnique::PRIV_TokenManipulation:
        case ProcessEvasionTechnique::PRIV_ImpersonationToken:
            return "T1134";      // Access Token Manipulation
        case ProcessEvasionTechnique::PRIV_UACBypass:
            return "T1548.002";  // Bypass User Account Control
        default:
            return "T1055";      // Process Injection (generic)
        }
    }

    // ========================================================================
    // PIMPL IMPLEMENTATION CLASS
    // ========================================================================

    class ProcessEvasionDetector::Impl {
    public:
        // ====================================================================
        // MEMBERS
        // ====================================================================

        /// Thread synchronization
        mutable std::shared_mutex m_mutex;

        /// Initialization state
        std::atomic<bool> m_initialized{ false };

        /// Detection callback
        ProcessDetectionCallback m_detectionCallback;

        /// Statistics
        ProcessEvasionDetector::Statistics m_stats;

        /// Result cache
        struct CacheEntry {
            ProcessEvasionResult result;
            std::chrono::steady_clock::time_point timestamp;
        };
        std::unordered_map<uint32_t, CacheEntry> m_resultCache;

        /// Pattern Store for shellcode detection
        std::shared_ptr<ShadowStrike::PatternStore::PatternStore> m_patternStore;

        /// Zydis decoder for 64-bit code
        ZydisDecoder m_decoder64{};

        /// Zydis decoder for 32-bit code
        ZydisDecoder m_decoder32{};

        /// Zydis formatter
        ZydisFormatter m_formatter{};

        /// Zydis initialized flag
        bool m_zydisInitialized = false;

        /// NtQueryInformationProcess function pointer
        NtQueryInformationProcessPtr m_pNtQueryInformationProcess = nullptr;

        /// NtQueryInformationThread function pointer
        NtQueryInformationThreadPtr m_pNtQueryInformationThread = nullptr;

        /// Known legitimate process paths (for masquerading detection)
        std::unordered_map<std::wstring, std::wstring> m_legitimateProcessPaths = {
            {L"svchost.exe", L"C:\\Windows\\System32\\svchost.exe"},
            {L"explorer.exe", L"C:\\Windows\\explorer.exe"},
            {L"lsass.exe", L"C:\\Windows\\System32\\lsass.exe"},
            {L"csrss.exe", L"C:\\Windows\\System32\\csrss.exe"},
            {L"winlogon.exe", L"C:\\Windows\\System32\\winlogon.exe"},
            {L"services.exe", L"C:\\Windows\\System32\\services.exe"},
            {L"smss.exe", L"C:\\Windows\\System32\\smss.exe"},
            {L"wininit.exe", L"C:\\Windows\\System32\\wininit.exe"},
            {L"spoolsv.exe", L"C:\\Windows\\System32\\spoolsv.exe"},
            {L"lsm.exe", L"C:\\Windows\\System32\\lsm.exe"},
            {L"conhost.exe", L"C:\\Windows\\System32\\conhost.exe"},
            {L"taskhost.exe", L"C:\\Windows\\System32\\taskhost.exe"},
            {L"taskhostw.exe", L"C:\\Windows\\System32\\taskhostw.exe"},
            {L"dwm.exe", L"C:\\Windows\\System32\\dwm.exe"},
            {L"RuntimeBroker.exe", L"C:\\Windows\\System32\\RuntimeBroker.exe"},
        };

        /// Expected parent processes (for parent spoofing detection)
        /// CRITICAL FIX (Issue #8): Added legitimate edge cases to reduce false positives
        /// - sihost.exe: Shell Infrastructure Host on Windows 10/11
        /// - taskmgr.exe: When user clicks "Restart Explorer" in Task Manager
        /// - explorer.exe: When Explorer restarts itself
        std::unordered_map<std::wstring, std::vector<std::wstring>> m_expectedParents = {
            {L"services.exe", {L"wininit.exe"}},
            {L"svchost.exe", {L"services.exe"}},
            {L"lsass.exe", {L"wininit.exe"}},
            {L"csrss.exe", {L"smss.exe"}},
            {L"winlogon.exe", {L"smss.exe"}},
            {L"wininit.exe", {L"smss.exe"}},
            {L"smss.exe", {L"System"}},
            // Explorer can be started by multiple legitimate parents:
            // - userinit.exe: Normal logon
            // - winlogon.exe: Session 0 scenarios
            // - sihost.exe: Shell Infrastructure Host (Windows 10/11 fast user switching)
            // - taskmgr.exe: "Restart Explorer" from Task Manager
            // - explorer.exe: Self-restart
            // - dllhost.exe: COM activation scenarios
            {L"explorer.exe", {L"userinit.exe", L"winlogon.exe", L"sihost.exe", 
                              L"taskmgr.exe", L"explorer.exe", L"dllhost.exe"}},
            {L"taskhost.exe", {L"svchost.exe"}},
            {L"taskhostw.exe", {L"svchost.exe"}},
            {L"RuntimeBroker.exe", {L"svchost.exe"}},
            // Windows Defender can spawn from multiple service hosts
            {L"msmpeng.exe", {L"services.exe", L"svchost.exe"}},
            // Windows Update
            {L"trustedinstaller.exe", {L"services.exe", L"svchost.exe"}},
        };

        // ====================================================================
        // METHODS
        // ====================================================================

        Impl() = default;
        ~Impl() = default;

        [[nodiscard]] bool Initialize(ProcessEvasionError* err) noexcept;
        void Shutdown() noexcept;
        void InitializeZydis() noexcept;
        void InitializeNtFunctions() noexcept;

        // Process information helpers
        [[nodiscard]] std::wstring GetProcessName(uint32_t processId) const noexcept;
        [[nodiscard]] std::wstring GetProcessPath(uint32_t processId) const noexcept;
        [[nodiscard]] uint32_t GetParentProcessId(uint32_t processId) const noexcept;
        [[nodiscard]] bool IsProcess64Bit(HANDLE hProcess) const noexcept;

        // Memory scanning
        [[nodiscard]] bool ScanProcessMemory(HANDLE hProcess, std::vector<MemoryRegionInfo>& regions) const noexcept;
        [[nodiscard]] bool IsMemoryRegionSuspicious(const MEMORY_BASIC_INFORMATION& mbi) const noexcept;
        [[nodiscard]] bool DetectShellcodePatterns(const uint8_t* data, size_t size, std::wstring& patternName) const noexcept;

        // Injection detection helpers
        [[nodiscard]] bool HasRemoteThreads(HANDLE hProcess, uint32_t& threadCount, std::vector<std::wstring>& details) const noexcept;
        [[nodiscard]] bool HasSuspiciousDLLs(HANDLE hProcess, std::vector<std::wstring>& suspiciousDLLs) const noexcept;
        [[nodiscard]] bool DetectProcessHollowing(HANDLE hProcess, uint32_t processId) const noexcept;
        [[nodiscard]] bool DetectReflectiveDLLInjection(HANDLE hProcess, std::vector<MemoryRegionInfo>& regions) const noexcept;

        // Hook detection using Zydis
        [[nodiscard]] bool DetectInlineHooks(HANDLE hProcess, bool is64Bit, std::vector<std::wstring>& hookedFunctions) const noexcept;
        [[nodiscard]] bool DetectIATHooks(HANDLE hProcess, const std::wstring& modulePath, std::vector<std::wstring>& hookedImports) const noexcept;
        [[nodiscard]] bool AnalyzeFunctionPrologue(const uint8_t* code, size_t size, bool is64Bit, std::wstring& hookType) const noexcept;

        // Anti-debug detection using Zydis
        [[nodiscard]] bool DetectAntiDebugInstructions(HANDLE hProcess, const std::wstring& modulePath, std::vector<std::wstring>& techniques) const noexcept;
        [[nodiscard]] bool HasAntiDebugAPIs(const std::wstring& modulePath, std::vector<std::wstring>& apis) const noexcept;

        // TLS callback analysis using PEParser
        [[nodiscard]] bool AnalyzeTLSCallbacks(const std::wstring& modulePath, std::vector<uint64_t>& callbacks) const noexcept;

        // Import analysis using PEParser
        [[nodiscard]] bool AnalyzeSuspiciousImports(const std::wstring& modulePath, std::vector<std::wstring>& suspiciousImports) const noexcept;

        // Masquerading detection helpers
        [[nodiscard]] bool IsPathAnomaly(std::wstring_view processName, std::wstring_view actualPath) const noexcept;
        [[nodiscard]] bool IsParentSpoofed(std::wstring_view processName, std::wstring_view actualParent) const noexcept;
        [[nodiscard]] bool IsSignatureValid(std::wstring_view filePath) const noexcept;

        // Anti-debugging detection helpers
        [[nodiscard]] bool CheckDebuggerPresent(HANDLE hProcess) const noexcept;
        [[nodiscard]] bool CheckHardwareBreakpoints(HANDLE hProcess) const noexcept;
        [[nodiscard]] bool CheckDebugPort(HANDLE hProcess) const noexcept;
        [[nodiscard]] bool CheckDebugFlags(HANDLE hProcess) const noexcept;

        // Privilege analysis
        [[nodiscard]] bool CheckSeDebugPrivilege(HANDLE hProcess) const noexcept;
        [[nodiscard]] bool CheckTokenIntegrity(HANDLE hProcess, std::wstring& integrityLevel) const noexcept;

        // Zydis decoder access
        [[nodiscard]] ZydisDecoder* GetDecoder(bool is64Bit) noexcept {
            return is64Bit ? &m_decoder64 : &m_decoder32;
        }
    };

    // ========================================================================
    // IMPL: INITIALIZATION
    // ========================================================================

    bool ProcessEvasionDetector::Impl::Initialize(ProcessEvasionError* err) noexcept {
        try {
            if (m_initialized.exchange(true)) {
                return true; // Already initialized
            }

            SS_LOG_INFO(LOG_CATEGORY, L"ProcessEvasionDetector: Initializing...");

            // Initialize Zydis disassembler
            InitializeZydis();

            // Initialize NT function pointers
            InitializeNtFunctions();

            // Initialize PatternStore for shellcode detection
            m_patternStore = std::make_shared<ShadowStrike::PatternStore::PatternStore>();

            // Enterprise: Attempt to load signature database if present
            std::wstring sigPath = L"signatures.db";
            if (ShadowStrike::Utils::FileUtils::Exists(sigPath)) {
                (void)m_patternStore->Initialize(sigPath);
                SS_LOG_INFO(LOG_CATEGORY, L"Loaded shellcode signatures from %ls", sigPath.c_str());
            }
            else {
                SS_LOG_WARN(LOG_CATEGORY, L"Signature database %ls not found, running with heuristics only", sigPath.c_str());
            }

            SS_LOG_INFO(LOG_CATEGORY, L"ProcessEvasionDetector: Initialized successfully");
            return true;

        }
        catch (const std::exception& e) {
            SS_LOG_ERROR(LOG_CATEGORY, L"ProcessEvasionDetector initialization failed: %hs", e.what());

            if (err) {
                err->win32Code = ERROR_INTERNAL_ERROR;
                err->message = L"Initialization failed";
                err->context = Utils::StringUtils::ToWide(e.what());
            }

            m_initialized = false;
            return false;
        }
        catch (...) {
            SS_LOG_FATAL(LOG_CATEGORY, L"ProcessEvasionDetector: Unknown initialization error");

            if (err) {
                err->win32Code = ERROR_INTERNAL_ERROR;
                err->message = L"Unknown initialization error";
            }

            m_initialized = false;
            return false;
        }
    }

    void ProcessEvasionDetector::Impl::InitializeZydis() noexcept {
        if (m_zydisInitialized) return;

        // Initialize 64-bit decoder (primary platform)
        ZydisDecoderInit(&m_decoder64, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);

        // Initialize 32-bit decoder (for WoW64 processes)
        ZydisDecoderInit(&m_decoder32, ZYDIS_MACHINE_MODE_LEGACY_32, ZYDIS_STACK_WIDTH_32);

        // Initialize formatter for disassembly output
        ZydisFormatterInit(&m_formatter, ZYDIS_FORMATTER_STYLE_INTEL);

        m_zydisInitialized = true;
        SS_LOG_DEBUG(LOG_CATEGORY, L"Zydis disassembler initialized (64-bit and 32-bit modes)");
    }

    void ProcessEvasionDetector::Impl::InitializeNtFunctions() noexcept {
        HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
        if (hNtdll) {
            m_pNtQueryInformationProcess = reinterpret_cast<NtQueryInformationProcessPtr>(
                GetProcAddress(hNtdll, "NtQueryInformationProcess"));

            m_pNtQueryInformationThread = reinterpret_cast<NtQueryInformationThreadPtr>(
                GetProcAddress(hNtdll, "NtQueryInformationThread"));

            SS_LOG_DEBUG(LOG_CATEGORY, L"NT functions resolved: NtQueryInformationProcess=%p, NtQueryInformationThread=%p",
                m_pNtQueryInformationProcess, m_pNtQueryInformationThread);
        }
    }

    void ProcessEvasionDetector::Impl::Shutdown() noexcept {
        try {
            std::unique_lock lock(m_mutex);

            if (!m_initialized.exchange(false)) {
                return; // Already shutdown
            }

            SS_LOG_INFO(LOG_CATEGORY, L"ProcessEvasionDetector: Shutting down...");

            // Clear caches
            m_resultCache.clear();

            // Clear callback
            m_detectionCallback = nullptr;

            // Clear pattern store
            m_patternStore.reset();

            SS_LOG_INFO(LOG_CATEGORY, L"ProcessEvasionDetector: Shutdown complete");
        }
        catch (...) {
            SS_LOG_ERROR(LOG_CATEGORY, L"ProcessEvasionDetector: Exception during shutdown");
        }
    }

    // ========================================================================
    // IMPL: PROCESS INFORMATION HELPERS
    // ========================================================================

    std::wstring ProcessEvasionDetector::Impl::GetProcessName(uint32_t processId) const noexcept {
        try {
            HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, processId);
            if (!hProcess) {
                return L"";
            }

            wchar_t processName[MAX_PATH] = {};
            DWORD size = MAX_PATH;
            if (QueryFullProcessImageNameW(hProcess, 0, processName, &size)) {
                CloseHandle(hProcess);

                // Extract just the filename
                std::wstring fullPath(processName);
                const size_t lastSlash = fullPath.find_last_of(L"\\/");
                if (lastSlash != std::wstring::npos) {
                    return fullPath.substr(lastSlash + 1);
                }
                return fullPath;
            }

            CloseHandle(hProcess);
            return L"";
        }
        catch (...) {
            return L"";
        }
    }

    std::wstring ProcessEvasionDetector::Impl::GetProcessPath(uint32_t processId) const noexcept {
        try {
            HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, processId);
            if (!hProcess) {
                return L"";
            }

            wchar_t processPath[MAX_PATH] = {};
            DWORD size = MAX_PATH;
            if (QueryFullProcessImageNameW(hProcess, 0, processPath, &size)) {
                CloseHandle(hProcess);
                return std::wstring(processPath);
            }

            CloseHandle(hProcess);
            return L"";
        }
        catch (...) {
            return L"";
        }
    }

    uint32_t ProcessEvasionDetector::Impl::GetParentProcessId(uint32_t processId) const noexcept {
        try {
            HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if (hSnapshot == INVALID_HANDLE_VALUE) {
                return 0;
            }

            PROCESSENTRY32W pe32 = {};
            pe32.dwSize = sizeof(pe32);

            if (Process32FirstW(hSnapshot, &pe32)) {
                do {
                    if (pe32.th32ProcessID == processId) {
                        CloseHandle(hSnapshot);
                        return pe32.th32ParentProcessID;
                    }
                } while (Process32NextW(hSnapshot, &pe32));
            }

            CloseHandle(hSnapshot);
            return 0;
        }
        catch (...) {
            return 0;
        }
    }

    bool ProcessEvasionDetector::Impl::IsProcess64Bit(HANDLE hProcess) const noexcept {
        BOOL isWow64 = FALSE;
        if (IsWow64Process(hProcess, &isWow64)) {
            // If running as WoW64, it's a 32-bit process on 64-bit Windows
            return !isWow64;
        }
        // Default to matching our architecture
#ifdef _WIN64
        return true;
#else
        return false;
#endif
    }

    // ========================================================================
    // IMPL: MEMORY SCANNING
    // ========================================================================

    bool ProcessEvasionDetector::Impl::ScanProcessMemory(
        HANDLE hProcess,
        std::vector<MemoryRegionInfo>& regions
    ) const noexcept {
        try {
            regions.clear();

            MEMORY_BASIC_INFORMATION mbi = {};
            uint8_t* address = nullptr;

            // Buffer for memory content scanning
            std::vector<uint8_t> buffer(MEMORY_SCAN_BUFFER_SIZE);

            // Enterprise-grade limits to prevent DoS and resource exhaustion
            constexpr size_t MAX_SCAN_ITERATIONS = 500000;    // Cap iterations (128TB / 256KB average)
            constexpr uint64_t MAX_TOTAL_SCAN_SIZE = 16ULL * 1024 * 1024 * 1024; // 16 GB cap
            constexpr size_t MAX_SUSPICIOUS_REGIONS = 10000;  // Cap suspicious region count
            
            size_t iterations = 0;
            uint64_t totalScannedSize = 0;

            while (VirtualQueryEx(hProcess, address, &mbi, sizeof(mbi)) == sizeof(mbi)) {
                // Check iteration limit to prevent infinite loops
                if (++iterations > MAX_SCAN_ITERATIONS) {
                    SS_LOG_WARN(LOG_CATEGORY, L"Memory scan iteration limit reached (%zu)", MAX_SCAN_ITERATIONS);
                    break;
                }

                // Check total scanned size limit
                if (totalScannedSize > MAX_TOTAL_SCAN_SIZE) {
                    SS_LOG_WARN(LOG_CATEGORY, L"Memory scan size limit reached (%.2f GB)", 
                        static_cast<double>(totalScannedSize) / (1024.0 * 1024.0 * 1024.0));
                    break;
                }

                // Check suspicious regions limit
                if (regions.size() >= MAX_SUSPICIOUS_REGIONS) {
                    SS_LOG_WARN(LOG_CATEGORY, L"Suspicious region limit reached (%zu)", MAX_SUSPICIOUS_REGIONS);
                    break;
                }

                if (mbi.State == MEM_COMMIT) {
                    totalScannedSize += mbi.RegionSize;

                    MemoryRegionInfo region;
                    region.baseAddress = reinterpret_cast<uint64_t>(mbi.BaseAddress);
                    region.size = mbi.RegionSize;
                    region.protection = mbi.Protect;
                    region.type = mbi.Type;

                    region.isExecutable = (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ |
                        PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
                    region.isWritable = (mbi.Protect & (PAGE_READWRITE | PAGE_WRITECOPY |
                        PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
                    region.isReadable = (mbi.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY |
                        PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;

                    region.isSuspicious = IsMemoryRegionSuspicious(mbi);

                    // If region is suspicious, scan content
                    if (region.isSuspicious) {
                        if (region.isExecutable && region.isWritable) {
                            region.description = L"RWX memory (Write + Execute) - highly suspicious";
                        }
                        else if (mbi.Type == MEM_PRIVATE && region.isExecutable) {
                            region.description = L"Private executable memory - potential shellcode";
                        }

                        // Content Scan
                        SIZE_T bytesRead = 0;
                        size_t scanSize = std::min(static_cast<size_t>(mbi.RegionSize), MEMORY_SCAN_BUFFER_SIZE);
                        if (ReadProcessMemory(hProcess, mbi.BaseAddress, buffer.data(), scanSize, &bytesRead)) {
                            // 1. Check PatternStore
                            if (m_patternStore) {
                                std::span<const uint8_t> data(buffer.data(), bytesRead);
                                auto matches = m_patternStore->Scan(data);
                                if (!matches.empty()) {
                                    region.description += L" [MALWARE SIGNATURE: ";
                                    for (size_t k = 0; k < matches.size() && k < 3; ++k) {
                                        region.description += Utils::StringUtils::ToWide(matches[k].signatureName);
                                        if (k < matches.size() - 1 && k < 2) region.description += L", ";
                                    }
                                    region.description += L"]";
                                }
                            }

                            // 2. Check for shellcode patterns
                            std::wstring patternName;
                            if (DetectShellcodePatterns(buffer.data(), bytesRead, patternName)) {
                                region.description += L" [" + patternName + L"]";
                            }

                            // 3. Check for MZ header (Reflective DLL/floating PE)
                            if (bytesRead > 2 && buffer[0] == 'M' && buffer[1] == 'Z') {
                                region.description += L" [Floating PE Header Detected]";
                            }

                            // 4. NOP Sled detection
                            int nopCount = 0;
                            int maxNopRun = 0;
                            for (size_t i = 0; i < bytesRead; ++i) {
                                if (buffer[i] == 0x90) {
                                    nopCount++;
                                }
                                else {
                                    maxNopRun = std::max(maxNopRun, nopCount);
                                    nopCount = 0;
                                }
                            }
                            maxNopRun = std::max(maxNopRun, nopCount);

                            if (maxNopRun > 16) {
                                region.description += L" [NOP Sled Detected]";
                            }
                        }
                    }

                    regions.push_back(region);
                }

                // CRITICAL FIX: Check for pointer arithmetic overflow before advancing
                // This prevents infinite loops when BaseAddress + RegionSize wraps around
                uintptr_t baseAddr = reinterpret_cast<uintptr_t>(mbi.BaseAddress);
                if (mbi.RegionSize > UINTPTR_MAX - baseAddr) {
                    // Would overflow - we've reached the end of address space
                    SS_LOG_DEBUG(LOG_CATEGORY, L"Address space boundary reached at 0x%p", mbi.BaseAddress);
                    break;
                }
                address = static_cast<uint8_t*>(mbi.BaseAddress) + mbi.RegionSize;
                
                // Additional safety: if address wrapped to zero or went backwards, stop
                if (address <= static_cast<uint8_t*>(mbi.BaseAddress)) {
                    SS_LOG_DEBUG(LOG_CATEGORY, L"Address wraparound detected, stopping scan");
                    break;
                }
            }

            return true;
        }
        catch (const std::exception& e) {
            SS_LOG_ERROR(LOG_CATEGORY, L"ScanProcessMemory failed: %hs", e.what());
            return false;
        }
        catch (...) {
            SS_LOG_ERROR(LOG_CATEGORY, L"ScanProcessMemory: Unknown error");
            return false;
        }
    }

    bool ProcessEvasionDetector::Impl::IsMemoryRegionSuspicious(const MEMORY_BASIC_INFORMATION& mbi) const noexcept {
        // RWX (Read-Write-Execute) memory is very suspicious
        if ((mbi.Protect & PAGE_EXECUTE_READWRITE) != 0) {
            return true;
        }

        // Private executable memory (not backed by a file) is suspicious
        if (mbi.Type == MEM_PRIVATE && (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE)) != 0) {
            return true;
        }

        return false;
    }

    bool ProcessEvasionDetector::Impl::DetectShellcodePatterns(
        const uint8_t* data,
        size_t size,
        std::wstring& patternName
    ) const noexcept {
        for (const auto& pattern : SHELLCODE_PATTERNS) {
            if (size >= pattern.size()) {
                for (size_t i = 0; i <= size - pattern.size(); ++i) {
                    bool match = true;
                    for (size_t j = 0; j < pattern.size(); ++j) {
                        if (data[i + j] != pattern[j]) {
                            match = false;
                            break;
                        }
                    }
                    if (match) {
                        // Determine pattern type
                        if (pattern[0] == 0xE8 && pattern[1] == 0x00) {
                            patternName = L"GetPC via CALL $+5";
                        }
                        else if (pattern[0] == 0x60 && pattern[1] == 0xFC) {
                            patternName = L"Windows API Hash Resolution";
                        }
                        else if (pattern[0] == 0xFC && pattern[1] == 0xE8) {
                            patternName = L"Metasploit Shellcode Pattern";
                        }
                        else if (pattern[0] == 0x4D && pattern[1] == 0x5A) {
                            patternName = L"Reflective PE/DLL Pattern";
                        }
                        else {
                            patternName = L"Known Shellcode Pattern";
                        }
                        return true;
                    }
                }
            }
        }
        return false;
    }

    // ========================================================================
    // IMPL: INJECTION DETECTION HELPERS
    // ========================================================================

    bool ProcessEvasionDetector::Impl::HasRemoteThreads(
        HANDLE hProcess,
        uint32_t& threadCount,
        std::vector<std::wstring>& details
    ) const noexcept {
        try {
            threadCount = 0;
            details.clear();
            uint32_t suspiciousThreads = 0;

            const DWORD processId = GetProcessId(hProcess);
            if (processId == 0) {
                return false;
            }

            if (!m_pNtQueryInformationThread) return false;

            HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
            if (hSnapshot == INVALID_HANDLE_VALUE) {
                return false;
            }

            THREADENTRY32 te32 = {};
            te32.dwSize = sizeof(te32);

            // Get LoadLibrary addresses for comparison
            HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
            FARPROC pLoadLibraryA = hKernel32 ? GetProcAddress(hKernel32, "LoadLibraryA") : nullptr;
            FARPROC pLoadLibraryW = hKernel32 ? GetProcAddress(hKernel32, "LoadLibraryW") : nullptr;

            if (Thread32First(hSnapshot, &te32)) {
                do {
                    if (te32.th32OwnerProcessID == processId) {
                        HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION, FALSE, te32.th32ThreadID);
                        if (hThread) {
                            PVOID startAddress = nullptr;
                            ULONG returnLength = 0;

                            NTSTATUS status = m_pNtQueryInformationThread(
                                hThread,
                                (THREADINFOCLASS)ThreadQuerySetWin32StartAddress,
                                &startAddress,
                                sizeof(startAddress),
                                &returnLength
                            );

                            if (status >= 0 && startAddress) {
                                MEMORY_BASIC_INFORMATION mbi = {};
                                if (VirtualQueryEx(hProcess, startAddress, &mbi, sizeof(mbi))) {
                                    // Thread starting in private RWX memory is suspicious
                                    if (mbi.Type == MEM_PRIVATE && (mbi.Protect & PAGE_EXECUTE_READWRITE)) {
                                        suspiciousThreads++;
                                        details.push_back(std::format(L"Thread {} starts in private RWX memory at 0x{:X}",
                                            te32.th32ThreadID, reinterpret_cast<uintptr_t>(startAddress)));
                                    }

                                    // Thread starting at LoadLibrary indicates DLL injection
                                    if ((pLoadLibraryA && startAddress == (PVOID)pLoadLibraryA) ||
                                        (pLoadLibraryW && startAddress == (PVOID)pLoadLibraryW)) {
                                        suspiciousThreads++;
                                        details.push_back(std::format(L"Thread {} starts at LoadLibrary (DLL injection indicator)",
                                            te32.th32ThreadID));
                                    }
                                }
                            }

                            CloseHandle(hThread);
                        }
                        threadCount++;
                    }
                } while (Thread32Next(hSnapshot, &te32));
            }

            CloseHandle(hSnapshot);

            return (suspiciousThreads > 0);
        }
        catch (...) {
            return false;
        }
    }

    bool ProcessEvasionDetector::Impl::HasSuspiciousDLLs(
        HANDLE hProcess,
        std::vector<std::wstring>& suspiciousDLLs
    ) const noexcept {
        try {
            suspiciousDLLs.clear();

            HMODULE hModules[MAX_MODULES] = {};
            DWORD cbNeeded = 0;

            if (!EnumProcessModules(hProcess, hModules, sizeof(hModules), &cbNeeded)) {
                return false;
            }

            const DWORD moduleCount = cbNeeded / sizeof(HMODULE);

            for (DWORD i = 0; i < moduleCount && i < MAX_MODULES; ++i) {
                wchar_t modulePath[MAX_PATH] = {};
                if (GetModuleFileNameExW(hProcess, hModules[i], modulePath, MAX_PATH) > 0) {
                    std::wstring modulePathStr(modulePath);
                    std::wstring lowerPath = modulePathStr;
                    std::transform(lowerPath.begin(), lowerPath.end(), lowerPath.begin(), ::towlower);

                    // DLLs loaded from temp directories are suspicious
                    if (lowerPath.find(L"\\temp\\") != std::wstring::npos ||
                        lowerPath.find(L"\\tmp\\") != std::wstring::npos ||
                        lowerPath.find(L"\\appdata\\local\\temp\\") != std::wstring::npos) {
                        suspiciousDLLs.push_back(modulePathStr + L" [Loaded from temp directory]");
                    }

                    // CRITICAL FIX (Issue #7): Whitelist legitimate user directory paths
                    // Many legitimate applications install plugins/extensions to user directories
                    // This reduces false positives for: Python, Node.js, Electron apps, Java, etc.
                    static const std::vector<std::wstring> LEGITIMATE_USER_PATHS = {
                        L"\\appdata\\local\\programs\\",       // Electron apps (VS Code, Discord, Slack)
                        L"\\appdata\\roaming\\npm\\",          // Node.js native modules
                        L"\\appdata\\local\\npm\\",            // Node.js (alternate location)
                        L"\\appdata\\local\\python",           // Python packages (.pyd files)
                        L"\\appdata\\roaming\\python",         // Python packages (alternate)
                        L"\\.m2\\repository\\",                // Maven Java dependencies
                        L"\\.gradle\\",                        // Gradle Java dependencies
                        L"\\.nuget\\",                         // NuGet .NET packages
                        L"\\appdata\\local\\jetbrains\\",      // JetBrains IDE plugins
                        L"\\appdata\\roaming\\code\\",         // VS Code extensions
                        L"\\programdata\\",                    // Shared application data
                        L"\\appdata\\local\\microsoft\\",      // Microsoft apps
                        L"\\appdata\\roaming\\microsoft\\",    // Microsoft apps
                        L"\\appdata\\local\\google\\",         // Chrome, etc.
                        L"\\appdata\\local\\mozilla\\",        // Firefox
                        L"\\.vscode\\",                        // VS Code extensions
                        L"\\.docker\\",                        // Docker components
                        L"\\appdata\\local\\docker\\",         // Docker Desktop
                    };

                    // Check if path is in a known legitimate location
                    bool isWhitelistedPath = false;
                    for (const auto& legitPath : LEGITIMATE_USER_PATHS) {
                        if (lowerPath.find(legitPath) != std::wstring::npos) {
                            isWhitelistedPath = true;
                            break;
                        }
                    }

                    // DLLs with unusual paths - only flag if NOT in whitelisted directories
                    if (!isWhitelistedPath &&
                        lowerPath.find(L"\\windows\\") == std::wstring::npos &&
                        lowerPath.find(L"\\program files") == std::wstring::npos &&
                        lowerPath.find(L"\\winsxs\\") == std::wstring::npos) {
                        // Check if it's an unsigned DLL from user directory
                        if (lowerPath.find(L"\\users\\") != std::wstring::npos) {
                            if (!IsSignatureValid(modulePathStr)) {
                                // Additional check: only flag if extension is .dll, not common plugin formats
                                bool isPluginExtension = 
                                    lowerPath.ends_with(L".pyd") ||    // Python
                                    lowerPath.ends_with(L".node") ||   // Node.js native addon
                                    lowerPath.ends_with(L".vsix") ||   // VS Code extension
                                    lowerPath.ends_with(L".jar");      // Java (shouldn't load as DLL but safety)
                                
                                if (!isPluginExtension) {
                                    suspiciousDLLs.push_back(modulePathStr + L" [Unsigned DLL from user directory]");
                                }
                            }
                        }
                    }
                }
            }

            return !suspiciousDLLs.empty();
        }
        catch (...) {
            return false;
        }
    }

    bool ProcessEvasionDetector::Impl::DetectProcessHollowing(HANDLE hProcess, uint32_t processId) const noexcept {
        try {
            // Get the main module's base address
            HMODULE hModules[1] = {};
            DWORD cbNeeded = 0;

            if (!EnumProcessModules(hProcess, hModules, sizeof(hModules), &cbNeeded) || cbNeeded == 0) {
                return false;
            }

            // Read the PE header from memory
            constexpr size_t HEADER_BUFFER_SIZE = 4096;
            uint8_t headerBuffer[HEADER_BUFFER_SIZE] = {};
            SIZE_T bytesRead = 0;

            if (!ReadProcessMemory(hProcess, hModules[0], headerBuffer, sizeof(headerBuffer), &bytesRead)) {
                return false;
            }

            if (bytesRead < sizeof(PEParser::DosHeader)) {
                return false;
            }

            // Validate DOS header
            const auto* dosHeader = reinterpret_cast<const PEParser::DosHeader*>(headerBuffer);
            if (dosHeader->e_magic != 0x5A4D) { // "MZ"
                // No MZ header - could be hollowed
                return true;
            }

            // CRITICAL FIX (Issue #4): Validate e_lfanew is within our buffer bounds
            // e_lfanew is attacker-controlled from process memory - must validate
            constexpr size_t MIN_PE_HEADER_SPACE = sizeof(uint32_t) + sizeof(PEParser::FileHeader) + 256;
            if (dosHeader->e_lfanew < sizeof(PEParser::DosHeader) ||
                dosHeader->e_lfanew >= HEADER_BUFFER_SIZE - MIN_PE_HEADER_SPACE) {
                SS_LOG_WARN(LOG_CATEGORY, L"Invalid e_lfanew value: 0x%lX (buffer size: %zu)",
                    static_cast<unsigned long>(dosHeader->e_lfanew), HEADER_BUFFER_SIZE);
                // Invalid e_lfanew could indicate corruption or hollowing
                return true;
            }

            // Additional bounds check: ensure we read enough bytes
            if (bytesRead <= static_cast<size_t>(dosHeader->e_lfanew) + MIN_PE_HEADER_SPACE) {
                return false; // Not enough data read
            }

            // CRITICAL FIX (Issue #2): TOCTOU mitigation for disk file comparison
            // Open file handle FIRST, then read from it - prevents file replacement attacks
            std::wstring processPath = GetProcessPath(processId);
            if (processPath.empty()) {
                return false;
            }

            // Open file with exclusive read to prevent modification during analysis
            HANDLE hFile = CreateFileW(
                processPath.c_str(),
                GENERIC_READ,
                FILE_SHARE_READ,  // Allow other readers but no writers
                nullptr,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN,
                nullptr
            );

            if (hFile == INVALID_HANDLE_VALUE) {
                // Cannot open file - might be locked or deleted
                SS_LOG_DEBUG(LOG_CATEGORY, L"Cannot open process file for hollowing check: %ls", processPath.c_str());
                return false;
            }

            // RAII guard for file handle
            auto fileGuard = [](HANDLE h) { if (h != INVALID_HANDLE_VALUE) CloseHandle(h); };
            std::unique_ptr<void, decltype(fileGuard)> fileHandleGuard(hFile, fileGuard);

            // Read disk file PE headers directly from handle (not path - prevents TOCTOU)
            uint8_t diskHeaderBuffer[HEADER_BUFFER_SIZE] = {};
            DWORD diskBytesRead = 0;

            if (!ReadFile(hFile, diskHeaderBuffer, sizeof(diskHeaderBuffer), &diskBytesRead, nullptr) ||
                diskBytesRead < sizeof(PEParser::DosHeader)) {
                return false;
            }

            const auto* diskDosHeader = reinterpret_cast<const PEParser::DosHeader*>(diskHeaderBuffer);
            if (diskDosHeader->e_magic != 0x5A4D) {
                return false; // Disk file is not a valid PE
            }

            // Validate disk e_lfanew
            if (diskDosHeader->e_lfanew < sizeof(PEParser::DosHeader) ||
                diskDosHeader->e_lfanew >= diskBytesRead - MIN_PE_HEADER_SPACE) {
                return false;
            }

            // Compare PE signatures
            const auto* memPeSignature = reinterpret_cast<const uint32_t*>(headerBuffer + dosHeader->e_lfanew);
            const auto* diskPeSignature = reinterpret_cast<const uint32_t*>(diskHeaderBuffer + diskDosHeader->e_lfanew);

            if (*memPeSignature != 0x00004550) { // "PE\0\0"
                // Invalid PE signature in memory - hollowed
                return true;
            }

            if (*diskPeSignature != 0x00004550) {
                return false; // Disk file invalid
            }

            // Parse optional headers to get entry points
            const auto* memFileHeader = reinterpret_cast<const PEParser::FileHeader*>(
                headerBuffer + dosHeader->e_lfanew + 4);
            const auto* diskFileHeader = reinterpret_cast<const PEParser::FileHeader*>(
                diskHeaderBuffer + diskDosHeader->e_lfanew + 4);

            const auto* memOptMagic = reinterpret_cast<const uint16_t*>(
                headerBuffer + dosHeader->e_lfanew + 4 + sizeof(PEParser::FileHeader));
            const auto* diskOptMagic = reinterpret_cast<const uint16_t*>(
                diskHeaderBuffer + diskDosHeader->e_lfanew + 4 + sizeof(PEParser::FileHeader));

            uint32_t memoryEntryPoint = 0;
            uint32_t diskEntryPoint = 0;

            // Extract memory entry point
            if (*memOptMagic == 0x20B) { // PE32+
                const auto* opt64 = reinterpret_cast<const PEParser::OptionalHeader64*>(memOptMagic);
                memoryEntryPoint = opt64->AddressOfEntryPoint;
            }
            else if (*memOptMagic == 0x10B) { // PE32
                const auto* opt32 = reinterpret_cast<const PEParser::OptionalHeader32*>(memOptMagic);
                memoryEntryPoint = opt32->AddressOfEntryPoint;
            }

            // Extract disk entry point
            if (*diskOptMagic == 0x20B) { // PE32+
                const auto* opt64 = reinterpret_cast<const PEParser::OptionalHeader64*>(diskOptMagic);
                diskEntryPoint = opt64->AddressOfEntryPoint;
            }
            else if (*diskOptMagic == 0x10B) { // PE32
                const auto* opt32 = reinterpret_cast<const PEParser::OptionalHeader32*>(diskOptMagic);
                diskEntryPoint = opt32->AddressOfEntryPoint;
            }

            // Compare entry points - mismatch indicates hollowing
            if (memoryEntryPoint != 0 && diskEntryPoint != 0 && memoryEntryPoint != diskEntryPoint) {
                SS_LOG_WARN(LOG_CATEGORY, L"Process hollowing detected: Entry point mismatch (memory: 0x%X, disk: 0x%X)",
                    memoryEntryPoint, diskEntryPoint);
                return true;
            }

            // Compare section counts - significant difference indicates hollowing
            if (memFileHeader->NumberOfSections != diskFileHeader->NumberOfSections) {
                SS_LOG_WARN(LOG_CATEGORY, L"Process hollowing detected: Section count mismatch (memory: %u, disk: %u)",
                    memFileHeader->NumberOfSections, diskFileHeader->NumberOfSections);
                return true;
            }

            return false;
        }
        catch (...) {
            return false;
        }
    }

    bool ProcessEvasionDetector::Impl::DetectReflectiveDLLInjection(
        HANDLE hProcess,
        std::vector<MemoryRegionInfo>& regions
    ) const noexcept {
        // Already detected in ScanProcessMemory - check for floating PE headers
        for (const auto& region : regions) {
            if (region.description.find(L"Floating PE Header") != std::wstring::npos) {
                return true;
            }
        }
        return false;
    }

    // ========================================================================
    // IMPL: HOOK DETECTION USING ZYDIS
    // ========================================================================

    bool ProcessEvasionDetector::Impl::DetectInlineHooks(
        HANDLE hProcess,
        bool is64Bit,
        std::vector<std::wstring>& hookedFunctions
    ) const noexcept {
        try {
            hookedFunctions.clear();

            if (!m_zydisInitialized) {
                return false;
            }

            // Check critical APIs in ntdll and kernel32
            const std::pair<const wchar_t*, std::vector<const char*>> criticalModules[] = {
                {L"ntdll.dll", {"NtQueryInformationProcess", "NtCreateThreadEx", "NtAllocateVirtualMemory",
                               "NtProtectVirtualMemory", "NtWriteVirtualMemory", "NtReadVirtualMemory",
                               "NtOpenProcess", "NtClose", "NtQuerySystemInformation"}},
                {L"kernel32.dll", {"VirtualAlloc", "VirtualProtect", "CreateRemoteThread",
                                  "WriteProcessMemory", "ReadProcessMemory", "OpenProcess",
                                  "IsDebuggerPresent", "GetTickCount"}}
            };

            for (const auto& [moduleName, functions] : criticalModules) {
                HMODULE hMod = GetModuleHandleW(moduleName);
                if (!hMod) continue;

                for (const char* funcName : functions) {
                    FARPROC proc = GetProcAddress(hMod, funcName);
                    if (!proc) continue;

                    // Read function prologue from target process
                    uint8_t codeBuffer[MAX_HOOK_SCAN_BYTES] = {};
                    SIZE_T bytesRead = 0;

                    if (!ReadProcessMemory(hProcess, proc, codeBuffer, MAX_HOOK_SCAN_BYTES, &bytesRead)) {
                        continue;
                    }

                    // Analyze prologue with Zydis
                    std::wstring hookType;
                    if (AnalyzeFunctionPrologue(codeBuffer, bytesRead, is64Bit, hookType)) {
                        std::wstring funcInfo = std::format(L"{}!{} - {}",
                            moduleName,
                            Utils::StringUtils::ToWide(funcName),
                            hookType);
                        hookedFunctions.push_back(funcInfo);
                    }
                }
            }

            return !hookedFunctions.empty();
        }
        catch (...) {
            return false;
        }
    }

    bool ProcessEvasionDetector::Impl::AnalyzeFunctionPrologue(
        const uint8_t* code,
        size_t size,
        bool is64Bit,
        std::wstring& hookType
    ) const noexcept {
        if (!m_zydisInitialized || size == 0) {
            return false;
        }

        ZydisDecoder* decoder = is64Bit ?
            const_cast<ZydisDecoder*>(&m_decoder64) :
            const_cast<ZydisDecoder*>(&m_decoder32);

        ZydisDecodedInstruction instruction;
        ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];

        // Decode the first instruction
        if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(decoder, code, size, &instruction, operands))) {
            return false;
        }

        // Check for common hook patterns
        switch (instruction.mnemonic) {
        case ZYDIS_MNEMONIC_JMP:
            // Any JMP as first instruction is suspicious
            if (instruction.length == 5 && code[0] == 0xE9) {
                hookType = L"JMP rel32 (5-byte inline hook)";
            }
            else if (instruction.length == 6 && code[0] == 0xFF && code[1] == 0x25) {
                hookType = L"JMP [RIP+disp32] (indirect hook)";
            }
            else if (instruction.length == 2 && code[0] == 0xEB) {
                hookType = L"JMP rel8 (short jump hook)";
            }
            else {
                hookType = L"JMP instruction (inline hook)";
            }
            return true;

        case ZYDIS_MNEMONIC_CALL:
            // CALL as first instruction is suspicious
            hookType = L"CALL instruction (detour hook)";
            return true;

        case ZYDIS_MNEMONIC_PUSH:
            // Check for PUSH addr; RET pattern
            if (instruction.operand_count > 0 &&
                operands[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
                // Decode next instruction
                ZydisDecodedInstruction nextInstr;
                ZydisDecodedOperand nextOps[ZYDIS_MAX_OPERAND_COUNT];
                if (ZYAN_SUCCESS(ZydisDecoderDecodeFull(
                    decoder,
                    code + instruction.length,
                    size - instruction.length,
                    &nextInstr,
                    nextOps))) {
                    if (nextInstr.mnemonic == ZYDIS_MNEMONIC_RET) {
                        hookType = L"PUSH/RET gadget (trampoline hook)";
                        return true;
                    }
                }
            }
            break;

        case ZYDIS_MNEMONIC_INT3:
            hookType = L"INT3 (breakpoint hook)";
            return true;

        case ZYDIS_MNEMONIC_INT:
            if (instruction.operand_count > 0 &&
                operands[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE &&
                operands[0].imm.value.u == 0x2D) {
                hookType = L"INT 2D (debug hook)";
                return true;
            }
            break;

        case ZYDIS_MNEMONIC_MOV:
            // Check for MOV RAX, imm64; JMP RAX pattern
            if (is64Bit && instruction.operand_count >= 2 &&
                operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                operands[0].reg.value == ZYDIS_REGISTER_RAX &&
                operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
                // Look for subsequent JMP RAX
                size_t offset = instruction.length;
                for (int i = 0; i < 3 && offset < size; ++i) {
                    ZydisDecodedInstruction scanInstr;
                    ZydisDecodedOperand scanOps[ZYDIS_MAX_OPERAND_COUNT];
                    if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(
                        decoder, code + offset, size - offset, &scanInstr, scanOps))) {
                        break;
                    }
                    if (scanInstr.mnemonic == ZYDIS_MNEMONIC_JMP &&
                        scanOps[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                        scanOps[0].reg.value == ZYDIS_REGISTER_RAX) {
                        hookType = L"MOV RAX, imm64; JMP RAX (12-byte trampoline)";
                        return true;
                    }
                    offset += scanInstr.length;
                }
            }
            break;

        default:
            break;
        }

        return false;
    }

    bool ProcessEvasionDetector::Impl::DetectIATHooks(
        HANDLE hProcess,
        const std::wstring& modulePath,
        std::vector<std::wstring>& hookedImports
    ) const noexcept {
        try {
            hookedImports.clear();

            // Parse the PE file to get expected IAT entries
            PEParser::PEParser parser;
            PEParser::PEInfo peInfo;

            if (!parser.ParseFile(modulePath, peInfo, nullptr)) {
                return false;
            }

            std::vector<PEParser::ImportInfo> imports;
            if (!parser.ParseImports(imports, nullptr)) {
                return false;
            }

            // Get the module base in the target process
            HMODULE hModules[MAX_MODULES] = {};
            DWORD cbNeeded = 0;

            if (!EnumProcessModules(hProcess, hModules, sizeof(hModules), &cbNeeded)) {
                return false;
            }

            HMODULE targetModule = nullptr;
            const DWORD moduleCount = cbNeeded / sizeof(HMODULE);

            for (DWORD i = 0; i < moduleCount && i < MAX_MODULES; ++i) {
                wchar_t modPath[MAX_PATH] = {};
                if (GetModuleFileNameExW(hProcess, hModules[i], modPath, MAX_PATH)) {
                    if (_wcsicmp(modPath, modulePath.c_str()) == 0) {
                        targetModule = hModules[i];
                        break;
                    }
                }
            }

            if (!targetModule) {
                return false;
            }

            // For each imported DLL, check if IAT entries point to expected modules
            for (const auto& importDll : imports) {
                HMODULE hImportDll = GetModuleHandleW(importDll.dllName.c_str());
                if (!hImportDll) continue;

                MODULEINFO modInfo = {};
                if (!GetModuleInformation(GetCurrentProcess(), hImportDll, &modInfo, sizeof(modInfo))) {
                    continue;
                }

                for (const auto& func : importDll.functions) {
                    if (func.byOrdinal) continue;

                    // Read IAT entry from target process
                    uint64_t iatValue = 0;
                    SIZE_T bytesRead = 0;

                    void* iatAddress = reinterpret_cast<void*>(
                        reinterpret_cast<uintptr_t>(targetModule) + func.iatRva);

                    if (!ReadProcessMemory(hProcess, iatAddress, &iatValue,
                        peInfo.is64Bit ? 8 : 4, &bytesRead)) {
                        continue;
                    }

                    // Check if IAT value points outside the expected module
                    uintptr_t modBase = reinterpret_cast<uintptr_t>(modInfo.lpBaseOfDll);
                    uintptr_t modEnd = modBase + modInfo.SizeOfImage;

                    if (iatValue != 0 && (iatValue < modBase || iatValue >= modEnd)) {
                        std::wstring hookInfo = std::format(L"{}!{} -> 0x{:X} (outside {})",
                            importDll.dllName,
                            Utils::StringUtils::ToWide(func.name),
                            iatValue,
                            importDll.dllName);
                        hookedImports.push_back(hookInfo);
                    }
                }
            }

            return !hookedImports.empty();
        }
        catch (...) {
            return false;
        }
    }

    // ========================================================================
    // IMPL: ANTI-DEBUG DETECTION USING ZYDIS
    // ========================================================================

    bool ProcessEvasionDetector::Impl::DetectAntiDebugInstructions(
        HANDLE hProcess,
        const std::wstring& modulePath,
        std::vector<std::wstring>& techniques
    ) const noexcept {
        try {
            techniques.clear();

            if (!m_zydisInitialized) {
                return false;
            }

            // Parse PE to find code sections
            PEParser::PEParser parser;
            PEParser::PEInfo peInfo;

            if (!parser.ParseFile(modulePath, peInfo, nullptr)) {
                return false;
            }

            // Get module base in target process
            HMODULE hModules[1] = {};
            DWORD cbNeeded = 0;

            if (!EnumProcessModules(hProcess, hModules, sizeof(hModules), &cbNeeded) || cbNeeded == 0) {
                return false;
            }

            // Scan code sections for anti-debug instructions
            for (const auto& section : peInfo.sections) {
                if (!section.hasCode) continue;

                size_t scanSize = std::min(section.rawSize, static_cast<uint32_t>(1024 * 1024)); // Max 1MB
                std::vector<uint8_t> codeBuffer(scanSize);
                SIZE_T bytesRead = 0;

                void* sectionAddress = reinterpret_cast<void*>(
                    reinterpret_cast<uintptr_t>(hModules[0]) + section.virtualAddress);

                if (!ReadProcessMemory(hProcess, sectionAddress, codeBuffer.data(), scanSize, &bytesRead)) {
                    continue;
                }

                // Use Zydis to scan for suspicious instructions
                ZydisDecoder* decoder = peInfo.is64Bit ?
                    const_cast<ZydisDecoder*>(&m_decoder64) :
                    const_cast<ZydisDecoder*>(&m_decoder32);

                ZydisDecodedInstruction instruction;
                ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];
                ZyanUSize offset = 0;
                size_t instructionCount = 0;
                constexpr size_t MAX_INSTRUCTIONS = 100000;

                uint32_t rdtscCount = 0;
                uint32_t int2dCount = 0;
                uint32_t int3Count = 0;

                while (offset < bytesRead && instructionCount < MAX_INSTRUCTIONS) {
                    if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(decoder,
                        codeBuffer.data() + offset, bytesRead - offset,
                        &instruction, operands))) {
                        ++offset;
                        continue;
                    }

                    switch (instruction.mnemonic) {
                    case ZYDIS_MNEMONIC_RDTSC:
                    case ZYDIS_MNEMONIC_RDTSCP:
                        ++rdtscCount;
                        break;

                    case ZYDIS_MNEMONIC_INT3:
                        ++int3Count;
                        break;

                    case ZYDIS_MNEMONIC_INT:
                        if (instruction.operand_count > 0 &&
                            operands[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
                            if (operands[0].imm.value.u == 0x2D) {
                                ++int2dCount;
                            }
                        }
                        break;

                    default:
                        break;
                    }

                    offset += instruction.length;
                    ++instructionCount;
                }

                // Report findings - CRITICAL FIX (Issue #6): Raised thresholds to reduce false positives
                // RDTSC is commonly used by: browsers (performance.now), games, profilers, databases
                // Only flag when count is extremely high AND combined with other indicators
                constexpr uint32_t RDTSC_WARNING_THRESHOLD = 50;   // Informational
                constexpr uint32_t RDTSC_SUSPICIOUS_THRESHOLD = 200; // Suspicious when combined
                
                if (rdtscCount > RDTSC_SUSPICIOUS_THRESHOLD && (int2dCount > 0 || int3Count > 5)) {
                    // High RDTSC WITH other anti-debug indicators = suspicious
                    techniques.push_back(std::format(L"RDTSC/RDTSCP with anti-debug: {} occurrences + {} INT2D + {} INT3",
                        rdtscCount, int2dCount, int3Count));
                }
                else if (rdtscCount > RDTSC_WARNING_THRESHOLD && rdtscCount <= RDTSC_SUSPICIOUS_THRESHOLD) {
                    // Moderate RDTSC count - only log, don't flag as technique
                    SS_LOG_DEBUG(LOG_CATEGORY, L"Process has %u RDTSC instructions (below suspicious threshold)", rdtscCount);
                }
                
                // INT 2D is always suspicious - used almost exclusively for anti-debugging
                if (int2dCount > 0) {
                    techniques.push_back(std::format(L"INT 2D instructions detected: {} occurrences (debugger detection)",
                        int2dCount));
                }
                
                // INT3 threshold raised - debuggers and instrumentation use many breakpoints
                constexpr uint32_t INT3_THRESHOLD = 50;
                if (int3Count > INT3_THRESHOLD) {
                    techniques.push_back(std::format(L"Excessive INT3 instructions: {} occurrences (possible anti-debug or obfuscation)",
                        int3Count));
                }
            }

            return !techniques.empty();
        }
        catch (...) {
            return false;
        }
    }

    bool ProcessEvasionDetector::Impl::HasAntiDebugAPIs(
        const std::wstring& modulePath,
        std::vector<std::wstring>& apis
    ) const noexcept {
        try {
            apis.clear();

            PEParser::PEParser parser;
            PEParser::PEInfo peInfo;

            if (!parser.ParseFile(modulePath, peInfo, nullptr)) {
                return false;
            }

            std::vector<PEParser::ImportInfo> imports;
            if (!parser.ParseImports(imports, nullptr)) {
                return false;
            }

            for (const auto& dll : imports) {
                for (const auto& func : dll.functions) {
                    for (const auto& antiDbgApi : ANTI_DEBUG_APIS) {
                        if (func.name == antiDbgApi) {
                            apis.push_back(std::format(L"{}!{}",
                                dll.dllName,
                                Utils::StringUtils::ToWide(func.name)));
                        }
                    }
                }
            }

            return !apis.empty();
        }
        catch (...) {
            return false;
        }
    }

    // ========================================================================
    // IMPL: TLS CALLBACK ANALYSIS
    // ========================================================================

    bool ProcessEvasionDetector::Impl::AnalyzeTLSCallbacks(
        const std::wstring& modulePath,
        std::vector<uint64_t>& callbacks
    ) const noexcept {
        try {
            callbacks.clear();

            PEParser::PEParser parser;
            PEParser::PEInfo peInfo;

            if (!parser.ParseFile(modulePath, peInfo, nullptr)) {
                return false;
            }

            PEParser::TLSInfo tlsInfo;
            if (!parser.ParseTLS(tlsInfo, nullptr)) {
                return false; // No TLS
            }

            callbacks = tlsInfo.callbacks;

            // TLS callbacks are often used by malware for anti-debug
            return !callbacks.empty();
        }
        catch (...) {
            return false;
        }
    }

    // ========================================================================
    // IMPL: IMPORT ANALYSIS
    // ========================================================================

    bool ProcessEvasionDetector::Impl::AnalyzeSuspiciousImports(
        const std::wstring& modulePath,
        std::vector<std::wstring>& suspiciousImports
    ) const noexcept {
        try {
            suspiciousImports.clear();

            PEParser::PEParser parser;
            PEParser::PEInfo peInfo;

            if (!parser.ParseFile(modulePath, peInfo, nullptr)) {
                return false;
            }

            std::vector<PEParser::ImportInfo> imports;
            if (!parser.ParseImports(imports, nullptr)) {
                return false;
            }

            uint32_t injectionApiCount = 0;
            uint32_t antiDebugApiCount = 0;
            uint32_t privilegeApiCount = 0;

            for (const auto& dll : imports) {
                for (const auto& func : dll.functions) {
                    // Check injection APIs
                    for (const auto& injApi : INJECTION_APIS) {
                        if (func.name == injApi) {
                            suspiciousImports.push_back(std::format(L"[INJECTION] {}!{}",
                                dll.dllName, Utils::StringUtils::ToWide(func.name)));
                            ++injectionApiCount;
                        }
                    }

                    // Check anti-debug APIs
                    for (const auto& antiApi : ANTI_DEBUG_APIS) {
                        if (func.name == antiApi) {
                            suspiciousImports.push_back(std::format(L"[ANTI-DEBUG] {}!{}",
                                dll.dllName, Utils::StringUtils::ToWide(func.name)));
                            ++antiDebugApiCount;
                        }
                    }

                    // Check privilege APIs
                    for (const auto& privApi : PRIVILEGE_APIS) {
                        if (func.name == privApi) {
                            suspiciousImports.push_back(std::format(L"[PRIVILEGE] {}!{}",
                                dll.dllName, Utils::StringUtils::ToWide(func.name)));
                            ++privilegeApiCount;
                        }
                    }
                }
            }

            // High counts indicate potential malware
            if (injectionApiCount >= 3) {
                suspiciousImports.insert(suspiciousImports.begin(),
                    std::format(L"[WARNING] {} injection-related APIs detected", injectionApiCount));
            }
            if (antiDebugApiCount >= 2) {
                suspiciousImports.insert(suspiciousImports.begin(),
                    std::format(L"[WARNING] {} anti-debug APIs detected", antiDebugApiCount));
            }

            return !suspiciousImports.empty();
        }
        catch (...) {
            return false;
        }
    }

    // ========================================================================
    // IMPL: MASQUERADING DETECTION HELPERS
    // ========================================================================

    bool ProcessEvasionDetector::Impl::IsPathAnomaly(
        std::wstring_view processName,
        std::wstring_view actualPath
    ) const noexcept {
        try {
            std::wstring lowerName(processName);
            std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(), ::towlower);

            std::wstring lowerPath(actualPath);
            std::transform(lowerPath.begin(), lowerPath.end(), lowerPath.begin(), ::towlower);

            // Check against known legitimate paths
            auto it = m_legitimateProcessPaths.find(lowerName);
            if (it != m_legitimateProcessPaths.end()) {
                std::wstring expectedPath = it->second;
                std::transform(expectedPath.begin(), expectedPath.end(), expectedPath.begin(), ::towlower);

                if (lowerPath != expectedPath) {
                    return true; // Path anomaly detected
                }
            }

            return false;
        }
        catch (...) {
            return false;
        }
    }

    bool ProcessEvasionDetector::Impl::IsParentSpoofed(
        std::wstring_view processName,
        std::wstring_view actualParent
    ) const noexcept {
        try {
            std::wstring lowerName(processName);
            std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(), ::towlower);

            std::wstring lowerParent(actualParent);
            std::transform(lowerParent.begin(), lowerParent.end(), lowerParent.begin(), ::towlower);

            // Check against expected parents
            auto it = m_expectedParents.find(lowerName);
            if (it != m_expectedParents.end()) {
                const auto& expectedParents = it->second;
                bool found = false;
                for (const auto& expected : expectedParents) {
                    std::wstring lowerExpected = expected;
                    std::transform(lowerExpected.begin(), lowerExpected.end(), lowerExpected.begin(), ::towlower);
                    if (lowerParent == lowerExpected) {
                        found = true;
                        break;
                    }
                }
                if (!found) {
                    return true; // Parent spoofing detected
                }
            }

            return false;
        }
        catch (...) {
            return false;
        }
    }

    bool ProcessEvasionDetector::Impl::IsSignatureValid(std::wstring_view filePath) const noexcept {
        try {
            if (filePath.empty()) return false;

            WINTRUST_FILE_INFO fileInfo = {};
            fileInfo.cbStruct = sizeof(fileInfo);
            fileInfo.pcwszFilePath = filePath.data();
            fileInfo.hFile = NULL;
            fileInfo.pgKnownSubject = NULL;

            GUID policyGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;

            WINTRUST_DATA trustData = {};
            trustData.cbStruct = sizeof(trustData);
            trustData.pPolicyCallbackData = NULL;
            trustData.pSIPClientData = NULL;
            trustData.dwUIChoice = WTD_UI_NONE;
            trustData.fdwRevocationChecks = WTD_REVOKE_NONE;
            trustData.dwUnionChoice = WTD_CHOICE_FILE;
            trustData.dwStateAction = WTD_STATEACTION_VERIFY;
            trustData.hWVTStateData = NULL;
            trustData.pwszURLReference = NULL;
            trustData.dwProvFlags = WTD_SAFER_FLAG;
            trustData.dwUIContext = 0;
            trustData.pFile = &fileInfo;

            LONG status = WinVerifyTrust(NULL, &policyGUID, &trustData);

            trustData.dwStateAction = WTD_STATEACTION_CLOSE;
            WinVerifyTrust(NULL, &policyGUID, &trustData);

            return (status == ERROR_SUCCESS);
        }
        catch (...) {
            return false;
        }
    }

    // ========================================================================
    // IMPL: ANTI-DEBUGGING DETECTION HELPERS
    // ========================================================================

    bool ProcessEvasionDetector::Impl::CheckDebuggerPresent(HANDLE hProcess) const noexcept {
        try {
            BOOL isBeingDebugged = FALSE;
            if (CheckRemoteDebuggerPresent(hProcess, &isBeingDebugged)) {
                return isBeingDebugged != FALSE;
            }
            return false;
        }
        catch (...) {
            return false;
        }
    }

    bool ProcessEvasionDetector::Impl::CheckDebugPort(HANDLE hProcess) const noexcept {
        if (!m_pNtQueryInformationProcess) {
            return false;
        }

        try {
            DWORD_PTR debugPort = 0;
            ULONG returnLength = 0;

            NTSTATUS status = m_pNtQueryInformationProcess(
                hProcess,
                (PROCESSINFOCLASS)ProcessDebugPort,
                &debugPort,
                sizeof(debugPort),
                &returnLength
            );

            if (status >= 0 && debugPort != 0) {
                return true; // Debug port is set
            }

            return false;
        }
        catch (...) {
            return false;
        }
    }

    bool ProcessEvasionDetector::Impl::CheckDebugFlags(HANDLE hProcess) const noexcept {
        if (!m_pNtQueryInformationProcess) {
            return false;
        }

        try {
            DWORD debugFlags = 0;
            ULONG returnLength = 0;

            NTSTATUS status = m_pNtQueryInformationProcess(
                hProcess,
                (PROCESSINFOCLASS)ProcessDebugFlags,
                &debugFlags,
                sizeof(debugFlags),
                &returnLength
            );

            if (status >= 0 && debugFlags == 0) {
                return true; // NoDebugInherit flag is cleared (being debugged)
            }

            return false;
        }
        catch (...) {
            return false;
        }
    }

    bool ProcessEvasionDetector::Impl::CheckHardwareBreakpoints(HANDLE hProcess) const noexcept {
        try {
            DWORD processId = GetProcessId(hProcess);
            if (processId == 0) return false;

            HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
            if (hSnapshot == INVALID_HANDLE_VALUE) return false;

            // RAII guard for snapshot handle - ensures cleanup on all exit paths
            auto snapshotGuard = [](HANDLE h) { if (h != INVALID_HANDLE_VALUE) CloseHandle(h); };
            std::unique_ptr<void, decltype(snapshotGuard)> snapshotCleanup(hSnapshot, snapshotGuard);

            THREADENTRY32 te32 = {};
            te32.dwSize = sizeof(te32);

            bool detected = false;
            size_t threadsChecked = 0;
            constexpr size_t MAX_THREADS_TO_CHECK = 1000; // Prevent excessive thread enumeration

            if (Thread32First(hSnapshot, &te32)) {
                do {
                    if (te32.th32OwnerProcessID == processId) {
                        // Limit threads checked to prevent DoS
                        if (++threadsChecked > MAX_THREADS_TO_CHECK) {
                            SS_LOG_WARN(LOG_CATEGORY, L"Thread enumeration limit reached for PID %lu", processId);
                            break;
                        }

                        HANDLE hThread = OpenThread(THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME | THREAD_QUERY_INFORMATION, FALSE, te32.th32ThreadID);
                        if (hThread != nullptr) {
                            // RAII guard for thread handle - CRITICAL FIX (Issue #3)
                            // Ensures handle is closed regardless of SuspendThread success
                            auto threadGuard = [](HANDLE h) { if (h) CloseHandle(h); };
                            std::unique_ptr<void, decltype(threadGuard)> threadCleanup(hThread, threadGuard);

                            DWORD suspendResult = SuspendThread(hThread);
                            if (suspendResult != static_cast<DWORD>(-1)) {
                                CONTEXT ctx = {};
                                ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

                                if (GetThreadContext(hThread, &ctx)) {
                                    // Check if any debug registers are set
                                    if (ctx.Dr0 != 0 || ctx.Dr1 != 0 || ctx.Dr2 != 0 || ctx.Dr3 != 0) {
                                        detected = true;
                                    }
                                    // Also check DR7 for enabled breakpoints
                                    if ((ctx.Dr7 & 0xFF) != 0) {
                                        detected = true;
                                    }
                                }
                                ResumeThread(hThread);
                            }
                            // Thread handle automatically closed by RAII guard
                        }
                    }
                } while (!detected && Thread32Next(hSnapshot, &te32));
            }

            // Snapshot handle automatically closed by RAII guard
            return detected;
        }
        catch (...) {
            return false;
        }
    }

    bool ProcessEvasionDetector::Impl::CheckSeDebugPrivilege(HANDLE hProcess) const noexcept {
        try {
            HANDLE hToken = nullptr;
            if (!OpenProcessToken(hProcess, TOKEN_QUERY, &hToken)) {
                return false;
            }

            DWORD returnLength = 0;
            GetTokenInformation(hToken, TokenPrivileges, nullptr, 0, &returnLength);

            if (returnLength == 0) {
                CloseHandle(hToken);
                return false;
            }

            std::vector<uint8_t> buffer(returnLength);
            TOKEN_PRIVILEGES* privileges = reinterpret_cast<TOKEN_PRIVILEGES*>(buffer.data());

            if (!GetTokenInformation(hToken, TokenPrivileges, privileges, returnLength, &returnLength)) {
                CloseHandle(hToken);
                return false;
            }

            LUID luid;
            if (!LookupPrivilegeValueW(NULL, L"SeDebugPrivilege", &luid)) {
                CloseHandle(hToken);
                return false;
            }

            bool hasDebugPrivilege = false;
            for (DWORD i = 0; i < privileges->PrivilegeCount; i++) {
                if (privileges->Privileges[i].Luid.LowPart == luid.LowPart &&
                    privileges->Privileges[i].Luid.HighPart == luid.HighPart) {
                    if (privileges->Privileges[i].Attributes & (SE_PRIVILEGE_ENABLED | SE_PRIVILEGE_ENABLED_BY_DEFAULT)) {
                        hasDebugPrivilege = true;
                    }
                    break;
                }
            }

            CloseHandle(hToken);
            return hasDebugPrivilege;
        }
        catch (...) {
            return false;
        }
    }

    bool ProcessEvasionDetector::Impl::CheckTokenIntegrity(HANDLE hProcess, std::wstring& integrityLevel) const noexcept {
        try {
            HANDLE hToken = nullptr;
            if (!OpenProcessToken(hProcess, TOKEN_QUERY, &hToken)) {
                return false;
            }

            DWORD returnLength = 0;
            GetTokenInformation(hToken, TokenIntegrityLevel, nullptr, 0, &returnLength);

            if (returnLength == 0) {
                CloseHandle(hToken);
                return false;
            }

            std::vector<uint8_t> buffer(returnLength);
            TOKEN_MANDATORY_LABEL* tml = reinterpret_cast<TOKEN_MANDATORY_LABEL*>(buffer.data());

            if (!GetTokenInformation(hToken, TokenIntegrityLevel, tml, returnLength, &returnLength)) {
                CloseHandle(hToken);
                return false;
            }

            DWORD integrityLevelValue = *GetSidSubAuthority(tml->Label.Sid,
                (DWORD)(UCHAR)(*GetSidSubAuthorityCount(tml->Label.Sid) - 1));

            if (integrityLevelValue >= SECURITY_MANDATORY_SYSTEM_RID) {
                integrityLevel = L"System";
            }
            else if (integrityLevelValue >= SECURITY_MANDATORY_HIGH_RID) {
                integrityLevel = L"High";
            }
            else if (integrityLevelValue >= SECURITY_MANDATORY_MEDIUM_RID) {
                integrityLevel = L"Medium";
            }
            else if (integrityLevelValue >= SECURITY_MANDATORY_LOW_RID) {
                integrityLevel = L"Low";
            }
            else {
                integrityLevel = L"Untrusted";
            }

            CloseHandle(hToken);
            return true;
        }
        catch (...) {
            return false;
        }
    }

    // ========================================================================
    // PUBLIC API IMPLEMENTATION
    // ========================================================================

    ProcessEvasionDetector::ProcessEvasionDetector() noexcept
        : m_impl(std::make_unique<Impl>()) {
    }

    ProcessEvasionDetector::~ProcessEvasionDetector() {
        if (m_impl) {
            m_impl->Shutdown();
        }
    }

    ProcessEvasionDetector::ProcessEvasionDetector(ProcessEvasionDetector&&) noexcept = default;
    ProcessEvasionDetector& ProcessEvasionDetector::operator=(ProcessEvasionDetector&&) noexcept = default;

    bool ProcessEvasionDetector::Initialize(ProcessEvasionError* err) noexcept {
        if (!m_impl) {
            if (err) {
                err->win32Code = ERROR_INVALID_HANDLE;
                err->message = L"Invalid detector instance";
            }
            return false;
        }
        return m_impl->Initialize(err);
    }

    void ProcessEvasionDetector::Shutdown() noexcept {
        if (m_impl) {
            m_impl->Shutdown();
        }
    }

    bool ProcessEvasionDetector::IsInitialized() const noexcept {
        return m_impl && m_impl->m_initialized.load();
    }

    // ========================================================================
    // PROCESS ANALYSIS
    // ========================================================================

    ProcessEvasionResult ProcessEvasionDetector::AnalyzeProcess(
        uint32_t processId,
        const ProcessAnalysisConfig& config,
        ProcessEvasionError* err
    ) noexcept {
        ProcessEvasionResult result;
        result.processId = processId;
        result.config = config;

        try {
            if (!IsInitialized()) {
                if (err) {
                    err->win32Code = ERROR_NOT_READY;
                    err->message = L"Detector not initialized";
                }
                return result;
            }

            const auto startTime = std::chrono::high_resolution_clock::now();
            result.analysisStartTime = std::chrono::system_clock::now();

            // Check cache first
            if (HasFlag(config.flags, ProcessAnalysisFlags::EnableCaching)) {
                std::shared_lock lock(m_impl->m_mutex);
                auto it = m_impl->m_resultCache.find(processId);

                if (it != m_impl->m_resultCache.end()) {
                    const auto age = std::chrono::steady_clock::now() - it->second.timestamp;
                    const auto maxAge = std::chrono::seconds(config.cacheTtlSeconds);

                    if (age < maxAge) {
                        m_impl->m_stats.cacheHits++;
                        result = it->second.result;
                        result.fromCache = true;
                        return result;
                    }
                }
                m_impl->m_stats.cacheMisses++;
            }

            // Open process handle
            HANDLE hProcess = OpenProcess(
                PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                FALSE,
                processId
            );

            if (!hProcess) {
                if (err) {
                    err->win32Code = GetLastError();
                    err->message = L"Failed to open process";
                }
                m_impl->m_stats.analysisErrors++;
                return result;
            }

            // Gather process information
            result.processName = m_impl->GetProcessName(processId);
            result.processPath = m_impl->GetProcessPath(processId);
            result.parentProcessId = m_impl->GetParentProcessId(processId);
            result.parentProcessName = m_impl->GetProcessName(result.parentProcessId);

            // Perform analysis
            AnalyzeProcessInternal(hProcess, processId, config, result);

            CloseHandle(hProcess);

            const auto endTime = std::chrono::high_resolution_clock::now();
            const auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime);

            result.analysisDurationMs = duration.count();
            result.analysisEndTime = std::chrono::system_clock::now();
            result.analysisComplete = true;

            m_impl->m_stats.totalAnalyses++;
            m_impl->m_stats.totalAnalysisTimeUs += std::chrono::duration_cast<std::chrono::microseconds>(duration).count();

            if (result.isEvasive) {
                m_impl->m_stats.evasiveProcesses++;
            }

            // Update cache
            if (HasFlag(config.flags, ProcessAnalysisFlags::EnableCaching)) {
                UpdateCache(processId, result);
            }

            return result;
        }
        catch (const std::exception& e) {
            SS_LOG_ERROR(LOG_CATEGORY, L"AnalyzeProcess failed: %hs", e.what());

            if (err) {
                err->win32Code = ERROR_INTERNAL_ERROR;
                err->message = L"Analysis failed";
                err->context = Utils::StringUtils::ToWide(e.what());
            }

            m_impl->m_stats.analysisErrors++;
            return result;
        }
        catch (...) {
            SS_LOG_FATAL(LOG_CATEGORY, L"AnalyzeProcess: Unknown error");

            if (err) {
                err->win32Code = ERROR_INTERNAL_ERROR;
                err->message = L"Unknown analysis error";
            }

            m_impl->m_stats.analysisErrors++;
            return result;
        }
    }

    ProcessEvasionResult ProcessEvasionDetector::AnalyzeProcess(
        HANDLE hProcess,
        const ProcessAnalysisConfig& config,
        ProcessEvasionError* err
    ) noexcept {
        ProcessEvasionResult result;
        result.config = config;

        try {
            if (!IsInitialized()) {
                if (err) {
                    err->win32Code = ERROR_NOT_READY;
                    err->message = L"Detector not initialized";
                }
                return result;
            }

            const uint32_t processId = GetProcessId(hProcess);
            if (processId == 0) {
                if (err) {
                    err->win32Code = ERROR_INVALID_HANDLE;
                    err->message = L"Invalid process handle";
                }
                return result;
            }

            result.processId = processId;

            const auto startTime = std::chrono::high_resolution_clock::now();
            result.analysisStartTime = std::chrono::system_clock::now();

            // Gather process information
            result.processName = m_impl->GetProcessName(processId);
            result.processPath = m_impl->GetProcessPath(processId);
            result.parentProcessId = m_impl->GetParentProcessId(processId);
            result.parentProcessName = m_impl->GetProcessName(result.parentProcessId);

            // Perform analysis
            AnalyzeProcessInternal(hProcess, processId, config, result);

            const auto endTime = std::chrono::high_resolution_clock::now();
            const auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime);

            result.analysisDurationMs = duration.count();
            result.analysisEndTime = std::chrono::system_clock::now();
            result.analysisComplete = true;

            m_impl->m_stats.totalAnalyses++;
            m_impl->m_stats.totalAnalysisTimeUs += std::chrono::duration_cast<std::chrono::microseconds>(duration).count();

            if (result.isEvasive) {
                m_impl->m_stats.evasiveProcesses++;
            }

            return result;
        }
        catch (const std::exception& e) {
            SS_LOG_ERROR(LOG_CATEGORY, L"AnalyzeProcess (by handle) failed: %hs", e.what());

            if (err) {
                err->win32Code = ERROR_INTERNAL_ERROR;
                err->message = L"Analysis failed";
            }

            m_impl->m_stats.analysisErrors++;
            return result;
        }
        catch (...) {
            if (err) {
                err->win32Code = ERROR_INTERNAL_ERROR;
                err->message = L"Unknown error";
            }
            m_impl->m_stats.analysisErrors++;
            return result;
        }
    }

    std::vector<ProcessEvasionResult> ProcessEvasionDetector::AnalyzeProcesses(
        const std::vector<uint32_t>& processIds,
        const ProcessAnalysisConfig& config,
        ProcessEvasionError* err
    ) noexcept {
        std::vector<ProcessEvasionResult> results;
        results.reserve(processIds.size());

        for (const auto processId : processIds) {
            auto result = AnalyzeProcess(processId, config, err);
            results.push_back(std::move(result));
        }

        return results;
    }

    // ========================================================================
    // SPECIFIC DETECTION METHODS
    // ========================================================================

    bool ProcessEvasionDetector::DetectInjection(
        uint32_t processId,
        ProcessInjectionInfo& outInfo,
        ProcessEvasionError* err
    ) noexcept {
        try {
            outInfo = ProcessInjectionInfo{};

            HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);
            if (!hProcess) {
                if (err) {
                    err->win32Code = GetLastError();
                    err->message = L"Failed to open process";
                }
                return false;
            }

            bool is64Bit = m_impl->IsProcess64Bit(hProcess);

            // Check for remote threads
            uint32_t threadCount = 0;
            std::vector<std::wstring> threadDetails;
            if (m_impl->HasRemoteThreads(hProcess, threadCount, threadDetails)) {
                outInfo.hasInjection = true;
                outInfo.injectedThreadCount = threadCount;
                outInfo.hasRemoteThreads = true;
            }

            // Scan memory for suspicious regions
            std::vector<MemoryRegionInfo> regions;
            if (m_impl->ScanProcessMemory(hProcess, regions)) {
                for (const auto& region : regions) {
                    if (region.isSuspicious) {
                        outInfo.suspiciousMemoryRegions++;
                        if (region.isExecutable && region.isWritable) {
                            outInfo.rwxMemoryAddresses.push_back(region.baseAddress);
                        }
                    }
                }

                if (outInfo.suspiciousMemoryRegions > 0) {
                    outInfo.hasInjection = true;
                }

                // Check for reflective DLL injection
                if (m_impl->DetectReflectiveDLLInjection(hProcess, regions)) {
                    outInfo.hasInjection = true;
                    outInfo.method = InjectionMethod::ReflectiveDLL;
                }
            }

            // Check for suspicious DLLs
            if (m_impl->HasSuspiciousDLLs(hProcess, outInfo.injectedDLLs)) {
                outInfo.hasInjection = true;
            }

            // Check for process hollowing
            if (m_impl->DetectProcessHollowing(hProcess, processId)) {
                outInfo.hasInjection = true;
                outInfo.hasHollowedImage = true;
                outInfo.method = InjectionMethod::ProcessHollowing;
            }

            // Check for inline hooks
            std::vector<std::wstring> hookedFunctions;
            if (m_impl->DetectInlineHooks(hProcess, is64Bit, hookedFunctions)) {
                outInfo.hasInjection = true;
                // Could add hook details to outInfo if needed
            }

            CloseHandle(hProcess);

            outInfo.valid = true;

            if (outInfo.hasInjection) {
                m_impl->m_stats.injectionsDetected++;
            }

            return outInfo.hasInjection;
        }
        catch (const std::exception& e) {
            SS_LOG_ERROR(LOG_CATEGORY, L"DetectInjection failed: %hs", e.what());

            if (err) {
                err->win32Code = ERROR_INTERNAL_ERROR;
                err->message = L"Injection detection failed";
            }
            return false;
        }
        catch (...) {
            if (err) {
                err->win32Code = ERROR_INTERNAL_ERROR;
                err->message = L"Unknown error";
            }
            return false;
        }
    }

    bool ProcessEvasionDetector::DetectMasquerading(
        uint32_t processId,
        ProcessMasqueradingInfo& outInfo,
        ProcessEvasionError* err
    ) noexcept {
        try {
            outInfo = ProcessMasqueradingInfo{};

            const std::wstring processName = m_impl->GetProcessName(processId);
            const std::wstring processPath = m_impl->GetProcessPath(processId);
            const uint32_t parentPid = m_impl->GetParentProcessId(processId);
            const std::wstring parentName = m_impl->GetProcessName(parentPid);

            outInfo.actualPath = processPath;
            outInfo.actualParent = parentName;

            // Check for path anomaly
            if (m_impl->IsPathAnomaly(processName, processPath)) {
                outInfo.isMasquerading = true;
                outInfo.hasPathAnomaly = true;

                std::wstring lowerName = processName;
                std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(), ::towlower);
                auto it = m_impl->m_legitimateProcessPaths.find(lowerName);
                if (it != m_impl->m_legitimateProcessPaths.end()) {
                    outInfo.expectedPath = it->second;
                }
            }

            // Check for parent spoofing
            if (m_impl->IsParentSpoofed(processName, parentName)) {
                outInfo.isMasquerading = true;
                outInfo.hasParentSpoof = true;

                std::wstring lowerName = processName;
                std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(), ::towlower);
                auto it = m_impl->m_expectedParents.find(lowerName);
                if (it != m_impl->m_expectedParents.end() && !it->second.empty()) {
                    outInfo.expectedParent = it->second[0];
                }
            }

            // Check digital signature
            if (!m_impl->IsSignatureValid(processPath)) {
                outInfo.hasSignatureFailure = true;

                // If masquerading as system process but unsigned
                if (outInfo.hasPathAnomaly || outInfo.hasParentSpoof) {
                    outInfo.isMasquerading = true;
                }
            }

            outInfo.valid = true;

            if (outInfo.isMasquerading) {
                m_impl->m_stats.masqueradingDetected++;
            }

            return outInfo.isMasquerading;
        }
        catch (const std::exception& e) {
            SS_LOG_ERROR(LOG_CATEGORY, L"DetectMasquerading failed: %hs", e.what());

            if (err) {
                err->win32Code = ERROR_INTERNAL_ERROR;
                err->message = L"Masquerading detection failed";
            }
            return false;
        }
        catch (...) {
            if (err) {
                err->win32Code = ERROR_INTERNAL_ERROR;
                err->message = L"Unknown error";
            }
            return false;
        }
    }

    bool ProcessEvasionDetector::DetectAntiDebug(
        uint32_t processId,
        AntiDebugInfo& outInfo,
        ProcessEvasionError* err
    ) noexcept {
        try {
            outInfo = AntiDebugInfo{};

            HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);
            if (!hProcess) {
                if (err) {
                    err->win32Code = GetLastError();
                    err->message = L"Failed to open process";
                }
                return false;
            }

            // Check for debugger presence
            if (m_impl->CheckDebuggerPresent(hProcess)) {
                outInfo.hasAntiDebug = true;
                outInfo.isDebuggerPresent = true;
                outInfo.detectedTechniques.push_back(L"Debugger detected via CheckRemoteDebuggerPresent");
            }

            // Check debug port
            if (m_impl->CheckDebugPort(hProcess)) {
                outInfo.hasAntiDebug = true;
                outInfo.detectedTechniques.push_back(L"Debug port detected via NtQueryInformationProcess");
            }

            // Check debug flags
            if (m_impl->CheckDebugFlags(hProcess)) {
                outInfo.hasAntiDebug = true;
                outInfo.detectedTechniques.push_back(L"Debug flags indicate debugging via NtQueryInformationProcess");
            }

            // Check for debug privileges
            if (m_impl->CheckSeDebugPrivilege(hProcess)) {
                outInfo.hasDebugPrivilege = true;
                outInfo.detectedTechniques.push_back(L"SeDebugPrivilege enabled");
            }

            // Check for hardware breakpoints
            if (m_impl->CheckHardwareBreakpoints(hProcess)) {
                outInfo.hasAntiDebug = true;
                outInfo.hasHardwareBreakpoints = true;
                outInfo.detectedTechniques.push_back(L"Hardware breakpoints detected");
            }

            // Check for anti-debug APIs in imports
            std::wstring processPath = m_impl->GetProcessPath(processId);
            if (!processPath.empty()) {
                std::vector<std::wstring> antiDebugApis;
                if (m_impl->HasAntiDebugAPIs(processPath, antiDebugApis)) {
                    outInfo.hasAntiDebug = true;
                    for (const auto& api : antiDebugApis) {
                        outInfo.detectedTechniques.push_back(L"Anti-debug API imported: " + api);
                    }
                }

                // Check for anti-debug instructions
                std::vector<std::wstring> asmTechniques;
                if (m_impl->DetectAntiDebugInstructions(hProcess, processPath, asmTechniques)) {
                    outInfo.hasAntiDebug = true;
                    for (const auto& tech : asmTechniques) {
                        outInfo.detectedTechniques.push_back(tech);
                    }
                }

                // Check for TLS callbacks (often used for anti-debug)
                std::vector<uint64_t> tlsCallbacks;
                if (m_impl->AnalyzeTLSCallbacks(processPath, tlsCallbacks)) {
                    outInfo.hasAntiDebug = true;
                    outInfo.detectedTechniques.push_back(
                        std::format(L"TLS callbacks detected: {} callbacks (potential anti-debug)", tlsCallbacks.size()));
                }
            }

            CloseHandle(hProcess);

            outInfo.valid = true;

            if (outInfo.hasAntiDebug) {
                m_impl->m_stats.antiDebugDetected++;
            }

            return outInfo.hasAntiDebug;
        }
        catch (const std::exception& e) {
            SS_LOG_ERROR(LOG_CATEGORY, L"DetectAntiDebug failed: %hs", e.what());

            if (err) {
                err->win32Code = ERROR_INTERNAL_ERROR;
                err->message = L"Anti-debug detection failed";
            }
            return false;
        }
        catch (...) {
            if (err) {
                err->win32Code = ERROR_INTERNAL_ERROR;
                err->message = L"Unknown error";
            }
            return false;
        }
    }

    bool ProcessEvasionDetector::ScanMemory(
        uint32_t processId,
        std::vector<MemoryRegionInfo>& outRegions,
        ProcessEvasionError* err
    ) noexcept {
        try {
            outRegions.clear();

            HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);
            if (!hProcess) {
                if (err) {
                    err->win32Code = GetLastError();
                    err->message = L"Failed to open process";
                }
                return false;
            }

            const bool success = m_impl->ScanProcessMemory(hProcess, outRegions);

            CloseHandle(hProcess);

            return success;
        }
        catch (const std::exception& e) {
            SS_LOG_ERROR(LOG_CATEGORY, L"ScanMemory failed: %hs", e.what());

            if (err) {
                err->win32Code = ERROR_INTERNAL_ERROR;
                err->message = L"Memory scan failed";
            }
            return false;
        }
        catch (...) {
            if (err) {
                err->win32Code = ERROR_INTERNAL_ERROR;
                err->message = L"Unknown error";
            }
            return false;
        }
    }

    // ========================================================================
    // CALLBACKS
    // ========================================================================

    void ProcessEvasionDetector::SetDetectionCallback(ProcessDetectionCallback callback) noexcept {
        std::unique_lock lock(m_impl->m_mutex);
        m_impl->m_detectionCallback = std::move(callback);
    }

    void ProcessEvasionDetector::ClearDetectionCallback() noexcept {
        std::unique_lock lock(m_impl->m_mutex);
        m_impl->m_detectionCallback = nullptr;
    }

    // ========================================================================
    // CACHING
    // ========================================================================

    std::optional<ProcessEvasionResult> ProcessEvasionDetector::GetCachedResult(uint32_t processId) const noexcept {
        std::shared_lock lock(m_impl->m_mutex);

        auto it = m_impl->m_resultCache.find(processId);
        if (it != m_impl->m_resultCache.end()) {
            return it->second.result;
        }

        return std::nullopt;
    }

    void ProcessEvasionDetector::InvalidateCache(uint32_t processId) noexcept {
        std::unique_lock lock(m_impl->m_mutex);
        m_impl->m_resultCache.erase(processId);
    }

    void ProcessEvasionDetector::ClearCache() noexcept {
        std::unique_lock lock(m_impl->m_mutex);
        m_impl->m_resultCache.clear();
    }

    size_t ProcessEvasionDetector::GetCacheSize() const noexcept {
        std::shared_lock lock(m_impl->m_mutex);
        return m_impl->m_resultCache.size();
    }

    // ========================================================================
    // STATISTICS
    // ========================================================================

    const ProcessEvasionDetector::Statistics& ProcessEvasionDetector::GetStatistics() const noexcept {
        return m_impl->m_stats;
    }

    void ProcessEvasionDetector::ResetStatistics() noexcept {
        m_impl->m_stats.Reset();
    }

    // ========================================================================
    // INTERNAL ANALYSIS METHODS
    // ========================================================================

    void ProcessEvasionDetector::AnalyzeProcessInternal(
        HANDLE hProcess,
        uint32_t processId,
        const ProcessAnalysisConfig& config,
        ProcessEvasionResult& result
    ) noexcept {
        try {
            bool is64Bit = m_impl->IsProcess64Bit(hProcess);

            // Injection detection
            if (HasFlag(config.flags, ProcessAnalysisFlags::CheckInjection)) {
                if (DetectInjection(processId, result.injectionInfo, nullptr)) {
                    CheckInjectionTechniques(hProcess, result);
                }
            }

            // Masquerading detection
            if (HasFlag(config.flags, ProcessAnalysisFlags::CheckMasquerading)) {
                if (DetectMasquerading(processId, result.masqueradingInfo, nullptr)) {
                    CheckMasqueradingTechniques(hProcess, processId, result);
                }
            }

            // Anti-debugging detection
            if (HasFlag(config.flags, ProcessAnalysisFlags::CheckAntiDebug)) {
                if (DetectAntiDebug(processId, result.antiDebugInfo, nullptr)) {
                    CheckAntiDebugTechniques(hProcess, result);
                }
            }

            // Memory scanning
            if (HasFlag(config.flags, ProcessAnalysisFlags::CheckMemory)) {
                (void)ScanMemory(processId, result.suspiciousMemoryRegions, nullptr);
            }

            // Deep analysis - additional checks
            if (config.enableDeepScan || HasFlag(config.flags, ProcessAnalysisFlags::DeepAnalysis)) {
                // Check for inline hooks
                std::vector<std::wstring> hookedFunctions;
                if (m_impl->DetectInlineHooks(hProcess, is64Bit, hookedFunctions)) {
                    for (const auto& hook : hookedFunctions) {
                        DetectedTechnique detection(ProcessEvasionTechnique::CODE_InlineHooking);
                        detection.severity = ProcessEvasionSeverity::High;
                        detection.confidence = 0.85;
                        detection.description = L"Inline hook detected";
                        detection.technicalDetails = hook;
                        AddDetection(result, std::move(detection));
                    }
                }

                // Analyze suspicious imports
                if (!result.processPath.empty()) {
                    std::vector<std::wstring> suspiciousImports;
                    if (m_impl->AnalyzeSuspiciousImports(result.processPath, suspiciousImports)) {
                        for (const auto& imp : suspiciousImports) {
                            if (imp.find(L"[INJECTION]") != std::wstring::npos) {
                                DetectedTechnique detection(ProcessEvasionTechnique::CODE_CrossProcessWrite);
                                detection.severity = ProcessEvasionSeverity::Medium;
                                detection.confidence = 0.6;
                                detection.description = L"Injection-related API imported";
                                detection.technicalDetails = imp;
                                AddDetection(result, std::move(detection));
                            }
                        }
                    }
                }
            }

            // Calculate final evasion score
            CalculateEvasionScore(result);
        }
        catch (...) {
            SS_LOG_ERROR(LOG_CATEGORY, L"AnalyzeProcessInternal: Exception");
        }
    }

    void ProcessEvasionDetector::CheckInjectionTechniques(
        HANDLE hProcess,
        ProcessEvasionResult& result
    ) noexcept {
        try {
            // Classic DLL injection
            if (result.injectionInfo.hasRemoteThreads && !result.injectionInfo.injectedDLLs.empty()) {
                DetectedTechnique detection(ProcessEvasionTechnique::INJ_ClassicDLLInjection);
                detection.severity = ProcessEvasionSeverity::High;
                detection.confidence = 0.85;
                detection.description = L"Classic DLL injection detected";
                detection.technicalDetails = std::format(L"{} remote threads, {} suspicious DLLs",
                    result.injectionInfo.injectedThreadCount,
                    result.injectionInfo.injectedDLLs.size());

                AddDetection(result, std::move(detection));
            }

            // RWX memory regions (shellcode)
            if (!result.injectionInfo.rwxMemoryAddresses.empty()) {
                DetectedTechnique detection(ProcessEvasionTechnique::CODE_SuspiciousMemoryAlloc);
                detection.severity = ProcessEvasionSeverity::Critical;
                detection.confidence = 0.95;
                detection.description = L"RWX memory regions detected (potential shellcode)";
                detection.technicalDetails = std::format(L"{} RWX regions found",
                    result.injectionInfo.rwxMemoryAddresses.size());

                AddDetection(result, std::move(detection));
            }

            // Process hollowing
            if (result.injectionInfo.hasHollowedImage) {
                DetectedTechnique detection(ProcessEvasionTechnique::INJ_ProcessHollowing);
                detection.severity = ProcessEvasionSeverity::Critical;
                detection.confidence = 0.9;
                detection.description = L"Process hollowing detected";
                detection.technicalDetails = L"Process image appears to be replaced";

                AddDetection(result, std::move(detection));
            }

            // Reflective DLL injection
            if (result.injectionInfo.method == InjectionMethod::ReflectiveDLL) {
                DetectedTechnique detection(ProcessEvasionTechnique::INJ_ReflectiveDLLInjection);
                detection.severity = ProcessEvasionSeverity::Critical;
                detection.confidence = 0.9;
                detection.description = L"Reflective DLL injection detected";
                detection.technicalDetails = L"Floating PE header found in private memory";

                AddDetection(result, std::move(detection));
            }
        }
        catch (...) {
            SS_LOG_ERROR(LOG_CATEGORY, L"CheckInjectionTechniques: Exception");
        }
    }

    void ProcessEvasionDetector::CheckMasqueradingTechniques(
        HANDLE hProcess,
        uint32_t processId,
        ProcessEvasionResult& result
    ) noexcept {
        try {
            // Path anomaly
            if (result.masqueradingInfo.hasPathAnomaly) {
                DetectedTechnique detection(ProcessEvasionTechnique::MASK_PathAnomaly);
                detection.severity = ProcessEvasionSeverity::High;
                detection.confidence = 0.9;
                detection.description = L"Process path anomaly detected";
                detection.technicalDetails = std::format(L"Expected: {}, Actual: {}",
                    result.masqueradingInfo.expectedPath,
                    result.masqueradingInfo.actualPath);

                AddDetection(result, std::move(detection));
            }

            // Parent spoofing
            if (result.masqueradingInfo.hasParentSpoof) {
                DetectedTechnique detection(ProcessEvasionTechnique::MASK_ParentProcessSpoofing);
                detection.severity = ProcessEvasionSeverity::High;
                detection.confidence = 0.85;
                detection.description = L"Parent process spoofing detected";
                detection.technicalDetails = std::format(L"Expected parent: {}, Actual: {}",
                    result.masqueradingInfo.expectedParent,
                    result.masqueradingInfo.actualParent);

                AddDetection(result, std::move(detection));
            }

            // Signature failure
            if (result.masqueradingInfo.hasSignatureFailure) {
                DetectedTechnique detection(ProcessEvasionTechnique::MASK_SignatureValidationFailure);
                detection.severity = ProcessEvasionSeverity::Medium;
                detection.confidence = 0.7;
                detection.description = L"Digital signature validation failed";

                AddDetection(result, std::move(detection));
            }
        }
        catch (...) {
            SS_LOG_ERROR(LOG_CATEGORY, L"CheckMasqueradingTechniques: Exception");
        }
    }

    void ProcessEvasionDetector::CheckAntiDebugTechniques(
        HANDLE hProcess,
        ProcessEvasionResult& result
    ) noexcept {
        try {
            // Debugger present
            if (result.antiDebugInfo.isDebuggerPresent) {
                DetectedTechnique detection(ProcessEvasionTechnique::ANTI_CheckRemoteDebugger);
                detection.severity = ProcessEvasionSeverity::Medium;
                detection.confidence = 0.8;
                detection.description = L"Debugger presence check detected";

                AddDetection(result, std::move(detection));
            }

            // Hardware breakpoints
            if (result.antiDebugInfo.hasHardwareBreakpoints) {
                DetectedTechnique detection(ProcessEvasionTechnique::ANTI_HardwareBreakpointDetection);
                detection.severity = ProcessEvasionSeverity::Medium;
                detection.confidence = 0.75;
                detection.description = L"Hardware breakpoint detection";

                AddDetection(result, std::move(detection));
            }

            // Debug privilege
            if (result.antiDebugInfo.hasDebugPrivilege) {
                DetectedTechnique detection(ProcessEvasionTechnique::PRIV_SeDebugPrivilege);
                detection.severity = ProcessEvasionSeverity::High;
                detection.confidence = 0.8;
                detection.description = L"SeDebugPrivilege acquisition detected";

                AddDetection(result, std::move(detection));
            }

            // Add detected techniques from deep analysis
            for (const auto& tech : result.antiDebugInfo.detectedTechniques) {
                if (tech.find(L"RDTSC") != std::wstring::npos) {
                    DetectedTechnique detection(ProcessEvasionTechnique::ANTI_TimingBasedDebuggerDetection);
                    detection.severity = ProcessEvasionSeverity::High;
                    detection.confidence = 0.8;
                    detection.description = L"Timing-based debugger detection";
                    detection.technicalDetails = tech;
                    AddDetection(result, std::move(detection));
                }
                else if (tech.find(L"TLS callbacks") != std::wstring::npos) {
                    DetectedTechnique detection(ProcessEvasionTechnique::ANTI_SEHAntiDebug);
                    detection.severity = ProcessEvasionSeverity::Medium;
                    detection.confidence = 0.7;
                    detection.description = L"TLS callbacks detected (potential anti-debug)";
                    detection.technicalDetails = tech;
                    AddDetection(result, std::move(detection));
                }
            }
        }
        catch (...) {
            SS_LOG_ERROR(LOG_CATEGORY, L"CheckAntiDebugTechniques: Exception");
        }
    }

    void ProcessEvasionDetector::CalculateEvasionScore(ProcessEvasionResult& result) noexcept {
        try {
            float score = 0.0f;

            // Weight by technique severity
            for (const auto& detection : result.detectedTechniques) {
                float severityWeight = 1.0f;
                switch (detection.severity) {
                case ProcessEvasionSeverity::Low: severityWeight = 10.0f; break;
                case ProcessEvasionSeverity::Medium: severityWeight = 25.0f; break;
                case ProcessEvasionSeverity::High: severityWeight = 50.0f; break;
                case ProcessEvasionSeverity::Critical: severityWeight = 75.0f; break;
                }

                score += (severityWeight * static_cast<float>(detection.confidence));
            }

            result.evasionScore = std::min(score, 100.0f);
            result.isEvasive = (result.evasionScore >= ProcessEvasionConstants::MIN_EVASION_SCORE);
            result.totalDetections = static_cast<uint32_t>(result.detectedTechniques.size());

            // Determine max severity
            for (const auto& detection : result.detectedTechniques) {
                if (detection.severity > result.maxSeverity) {
                    result.maxSeverity = detection.severity;
                }
            }

            // Determine confidence level
            if (result.evasionScore >= ProcessEvasionConstants::HIGH_CONFIDENCE_THRESHOLD) {
                result.confidenceLevel = L"High";
            }
            else if (result.evasionScore >= ProcessEvasionConstants::MIN_EVASION_SCORE) {
                result.confidenceLevel = L"Medium";
            }
            else if (result.evasionScore >= 30.0f) {
                result.confidenceLevel = L"Low";
            }
            else {
                result.confidenceLevel = L"Very Low";
            }
        }
        catch (...) {
            SS_LOG_ERROR(LOG_CATEGORY, L"CalculateEvasionScore: Exception");
        }
    }

    void ProcessEvasionDetector::AddDetection(
        ProcessEvasionResult& result,
        DetectedTechnique detection
    ) noexcept {
        try {
            // Set category bit
            const auto techIdx = static_cast<uint32_t>(detection.technique);
            if (techIdx < 256) {
                result.detectedCategories |= (1u << (techIdx / 50)); // Category index
            }

            // Update statistics
            m_impl->m_stats.totalDetections++;

            const auto catIdx = (techIdx / 50) % 8;
            m_impl->m_stats.categoryDetections[catIdx]++;

            // Invoke callback if set
            if (m_impl->m_detectionCallback) {
                try {
                    m_impl->m_detectionCallback(result.processId, detection);
                }
                catch (...) {
                    // Swallow callback exceptions
                }
            }

            result.detectedTechniques.push_back(std::move(detection));
        }
        catch (...) {
            SS_LOG_ERROR(LOG_CATEGORY, L"AddDetection: Exception");
        }
    }

    void ProcessEvasionDetector::UpdateCache(
        uint32_t processId,
        const ProcessEvasionResult& result
    ) noexcept {
        try {
            std::unique_lock lock(m_impl->m_mutex);

            // Enforce cache size limit
            if (m_impl->m_resultCache.size() >= ProcessEvasionConstants::MAX_TRACKED_PROCESSES) {
                // Remove oldest entry
                auto oldest = m_impl->m_resultCache.begin();
                for (auto it = m_impl->m_resultCache.begin(); it != m_impl->m_resultCache.end(); ++it) {
                    if (it->second.timestamp < oldest->second.timestamp) {
                        oldest = it;
                    }
                }
                m_impl->m_resultCache.erase(oldest);
            }

            Impl::CacheEntry entry;
            entry.result = result;
            entry.timestamp = std::chrono::steady_clock::now();

            m_impl->m_resultCache[processId] = std::move(entry);
        }
        catch (...) {
            // Cache update failure is non-fatal
        }
    }

} // namespace ShadowStrike::AntiEvasion
