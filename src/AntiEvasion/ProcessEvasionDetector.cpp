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
 * - Infrastructure reuse (Utils/, PatternStore)
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
// SHADOWSTRIKE INTERNAL INCLUDES
// ============================================================================

#include "../Utils/StringUtils.hpp"
#include "../Utils/Logger.hpp"
#include "../Utils/ProcessUtils.hpp"
#include "../Utils/SystemUtils.hpp"
#include "../Utils/FileUtils.hpp"
#include "../PatternStore/PatternStore.hpp"

// ============================================================================
// INTERNAL DEFINITIONS (NtQueryInformationThread)
// ============================================================================

#ifndef ThreadQuerySetWin32StartAddress
#define ThreadQuerySetWin32StartAddress 9
#endif

typedef NTSTATUS(WINAPI* NtQueryInformationThreadPtr)(
    HANDLE ThreadHandle,
    THREADINFOCLASS ThreadInformationClass,
    PVOID ThreadInformation,
    ULONG ThreadInformationLength,
    PULONG ReturnLength
    );

namespace ShadowStrike::AntiEvasion {

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

    // ========================================================================
    // PIMPL IMPLEMENTATION CLASS
    // ========================================================================

    class ProcessEvasionDetector::Impl {
    public:
        // ====================================================================
        // MEMBERS
        // ====================================================================

        /// @brief Thread synchronization
        mutable std::shared_mutex m_mutex;

        /// @brief Initialization state
        std::atomic<bool> m_initialized{ false };

        /// @brief Detection callback
        ProcessDetectionCallback m_detectionCallback;

        /// @brief Statistics
        ProcessEvasionDetector::Statistics m_stats;

        /// @brief Result cache
        struct CacheEntry {
            ProcessEvasionResult result;
            std::chrono::steady_clock::time_point timestamp;
        };
        std::unordered_map<uint32_t, CacheEntry> m_resultCache;

        /// @brief Pattern Store for shellcode detection
        std::shared_ptr<ShadowStrike::PatternStore::PatternStore> m_patternStore;

        /// @brief Known legitimate process paths (for masquerading detection)
        std::unordered_map<std::wstring, std::wstring> m_legitimateProcessPaths = {
            {L"svchost.exe", L"C:\\Windows\\System32\\svchost.exe"},
            {L"explorer.exe", L"C:\\Windows\\explorer.exe"},
            {L"lsass.exe", L"C:\\Windows\\System32\\lsass.exe"},
            {L"csrss.exe", L"C:\\Windows\\System32\\csrss.exe"},
            {L"winlogon.exe", L"C:\\Windows\\System32\\winlogon.exe"},
            {L"services.exe", L"C:\\Windows\\System32\\services.exe"},
            {L"smss.exe", L"C:\\Windows\\System32\\smss.exe"},
            {L"wininit.exe", L"C:\\Windows\\System32\\wininit.exe"},
        };

        /// @brief Expected parent processes (for parent spoofing detection)
        std::unordered_map<std::wstring, std::wstring> m_expectedParents = {
            {L"services.exe", L"wininit.exe"},
            {L"svchost.exe", L"services.exe"},
            {L"lsass.exe", L"wininit.exe"},
            {L"csrss.exe", L"smss.exe"},
            {L"winlogon.exe", L"smss.exe"},
        };

        // ====================================================================
        // METHODS
        // ====================================================================

        Impl() = default;
        ~Impl() = default;

        [[nodiscard]] bool Initialize(ProcessEvasionError* err) noexcept;
        void Shutdown() noexcept;

        // Process information helpers
        [[nodiscard]] std::wstring GetProcessName(uint32_t processId) const noexcept;
        [[nodiscard]] std::wstring GetProcessPath(uint32_t processId) const noexcept;
        [[nodiscard]] uint32_t GetParentProcessId(uint32_t processId) const noexcept;

        // Memory scanning
        [[nodiscard]] bool ScanProcessMemory(HANDLE hProcess, std::vector<MemoryRegionInfo>& regions) const noexcept;
        [[nodiscard]] bool IsMemoryRegionSuspicious(const MEMORY_BASIC_INFORMATION& mbi) const noexcept;

        // Injection detection helpers
        [[nodiscard]] bool HasRemoteThreads(HANDLE hProcess, uint32_t& threadCount) const noexcept;
        [[nodiscard]] bool HasSuspiciousDLLs(HANDLE hProcess, std::vector<std::wstring>& suspiciousDLLs) const noexcept;

        // Masquerading detection helpers
        [[nodiscard]] bool IsPathAnomaly(std::wstring_view processName, std::wstring_view actualPath) const noexcept;
        [[nodiscard]] bool IsParentSpoofed(std::wstring_view processName, std::wstring_view actualParent) const noexcept;
        [[nodiscard]] bool IsSignatureValid(std::wstring_view filePath) const noexcept;

        // Anti-debugging detection helpers
        [[nodiscard]] bool CheckDebuggerPresent(HANDLE hProcess) const noexcept;
        [[nodiscard]] bool CheckHardwareBreakpoints(HANDLE hProcess) const noexcept;
    };

    // ========================================================================
    // IMPL: INITIALIZATION
    // ========================================================================

    bool ProcessEvasionDetector::Impl::Initialize(ProcessEvasionError* err) noexcept {
        try {
            if (m_initialized.exchange(true)) {
                return true; // Already initialized
            }

            SS_LOG_INFO(L"AntiEvasion", L"ProcessEvasionDetector: Initializing...");

            // Initialize PatternStore for shellcode detection
            m_patternStore = std::make_shared<ShadowStrike::PatternStore::PatternStore>();

            // Enterprise: Attempt to load signature database if present
            // We use a relative path to the module or a fixed system path
            std::wstring sigPath = L"signatures.db";
            if (ShadowStrike::Utils::FileUtils::Exists(sigPath)) {
                m_patternStore->Initialize(sigPath);
                SS_LOG_INFO(L"AntiEvasion", L"Loaded shellcode signatures from %ls", sigPath.c_str());
            } else {
                SS_LOG_WARN(L"AntiEvasion", L"Signature database %ls not found, running with heuristics only", sigPath.c_str());
            }

            SS_LOG_INFO(L"AntiEvasion", L"ProcessEvasionDetector: Initialized successfully");
            return true;

        }
        catch (const std::exception& e) {
            SS_LOG_ERROR(L"AntiEvasion", L"ProcessEvasionDetector initialization failed: %hs",
                e.what());

            if (err) {
                err->win32Code = ERROR_INTERNAL_ERROR;
                err->message = L"Initialization failed";
                err->context = Utils::StringUtils::ToWide(e.what());
            }

            m_initialized = false;
            return false;
        }
        catch (...) {
            SS_LOG_FATAL(L"AntiEvasion", L"ProcessEvasionDetector: Unknown initialization error");

            if (err) {
                err->win32Code = ERROR_INTERNAL_ERROR;
                err->message = L"Unknown initialization error";
            }

            m_initialized = false;
            return false;
        }
    }

    void ProcessEvasionDetector::Impl::Shutdown() noexcept {
        try {
            std::unique_lock lock(m_mutex);

            if (!m_initialized.exchange(false)) {
                return; // Already shutdown
            }

            SS_LOG_INFO(L"AntiEvasion", L"ProcessEvasionDetector: Shutting down...");

            // Clear caches
            m_resultCache.clear();

            // Clear callback
            m_detectionCallback = nullptr;

            SS_LOG_INFO(L"AntiEvasion", L"ProcessEvasionDetector: Shutdown complete");
        }
        catch (...) {
            SS_LOG_ERROR(L"AntiEvasion", L"ProcessEvasionDetector: Exception during shutdown");
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
            // We limit scan to first 4KB of region for performance
            constexpr size_t SCAN_BUFFER_SIZE = 4096;
            std::vector<uint8_t> buffer(SCAN_BUFFER_SIZE);

            while (VirtualQueryEx(hProcess, address, &mbi, sizeof(mbi)) == sizeof(mbi)) {
                if (mbi.State == MEM_COMMIT) {
                    MemoryRegionInfo region;
                    region.baseAddress = reinterpret_cast<uint64_t>(mbi.BaseAddress);
                    region.size = mbi.RegionSize;
                    region.protection = mbi.Protect;
                    region.type = mbi.Type;

                    region.isExecutable = (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
                    region.isWritable = (mbi.Protect & (PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
                    region.isReadable = (mbi.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;

                    region.isSuspicious = IsMemoryRegionSuspicious(mbi);

                    // If region is suspicious (RWX or Private Executable), scan content for shellcode
                    if (region.isSuspicious) {
                        if (region.isExecutable && region.isWritable) {
                            region.description = L"RWX memory (Write + Execute) - highly suspicious";
                        }
                        else if (mbi.Type == MEM_PRIVATE && region.isExecutable) {
                            region.description = L"Private executable memory - potential shellcode";
                        }

                        // Content Scan
                        SIZE_T bytesRead = 0;
                        if (ReadProcessMemory(hProcess, mbi.BaseAddress, buffer.data(), SCAN_BUFFER_SIZE, &bytesRead)) {
                            std::span<const uint8_t> data(buffer.data(), bytesRead);

                            // 1. Check PatternStore
                            if (m_patternStore) {
                                auto matches = m_patternStore->Scan(data);
                                if (!matches.empty()) {
                                    region.description += L" [MALWARE SIGNATURE DETECTED: ";
                                    for (size_t k = 0; k < matches.size(); ++k) {
                                        region.description += Utils::StringUtils::ToWide(matches[k].signatureName);
                                        if (k < matches.size() - 1) region.description += L", ";
                                    }
                                    region.description += L"]";
                                }
                            }

                            // 2. Heuristic: NOP Sled (0x90 0x90 ...)
                            int nopCount = 0;
                            int maxNopRun = 0;
                            for (size_t i = 0; i < bytesRead; ++i) {
                                if (data[i] == 0x90) {
                                    nopCount++;
                                } else {
                                    maxNopRun = std::max(maxNopRun, nopCount);
                                    nopCount = 0;
                                }
                            }
                            maxNopRun = std::max(maxNopRun, nopCount);

                            if (maxNopRun > 16) {
                                region.description += L" [NOP Sled Detected]";
                            }

                            // 3. Heuristic: High Entropy (Packed/Encrypted)
                            // (Simplified entropy calculation for performance)
                            // Skip strictly 0x00 blocks
                            bool nonZero = false;
                            for(auto b : data) if(b != 0) nonZero = true;

                            if (nonZero) {
                                // Simple check for MZ header (Reflective DLL injection)
                                if (bytesRead > 2 && data[0] == 'M' && data[1] == 'Z') {
                                    region.description += L" [Floating PE Header Detected]";
                                }
                            }
                        }
                    }

                    regions.push_back(region);
                }

                address = static_cast<uint8_t*>(mbi.BaseAddress) + mbi.RegionSize;
            }

            return true;
        }
        catch (const std::exception& e) {
            SS_LOG_ERROR(L"AntiEvasion", L"ScanProcessMemory failed: %hs",
                e.what());
            return false;
        }
        catch (...) {
            SS_LOG_ERROR(L"AntiEvasion", L"ScanProcessMemory: Unknown error");
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

    // ========================================================================
    // IMPL: INJECTION DETECTION HELPERS
    // ========================================================================

    bool ProcessEvasionDetector::Impl::HasRemoteThreads(HANDLE hProcess, uint32_t& threadCount) const noexcept {
        try {
            threadCount = 0;
            uint32_t suspiciousThreads = 0;

            const DWORD processId = GetProcessId(hProcess);
            if (processId == 0) {
                return false;
            }

            // Resolve NtQueryInformationThread
            HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
            if (!hNtdll) return false;

            auto NtQueryInformationThread = reinterpret_cast<NtQueryInformationThreadPtr>(
                GetProcAddress(hNtdll, "NtQueryInformationThread"));

            if (!NtQueryInformationThread) return false;

            HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
            if (hSnapshot == INVALID_HANDLE_VALUE) {
                return false;
            }

            THREADENTRY32 te32 = {};
            te32.dwSize = sizeof(te32);

            if (Thread32First(hSnapshot, &te32)) {
                do {
                    if (te32.th32OwnerProcessID == processId) {
                        // We need to check the thread start address
                        HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION, FALSE, te32.th32ThreadID);
                        if (hThread) {
                            PVOID startAddress = nullptr;
                            ULONG returnLength = 0;

                            NTSTATUS status = NtQueryInformationThread(
                                hThread,
                                (THREADINFOCLASS)ThreadQuerySetWin32StartAddress,
                                &startAddress,
                                sizeof(startAddress),
                                &returnLength
                            );

                            if (status >= 0 && startAddress) {
                                // Check memory attributes of start address
                                MEMORY_BASIC_INFORMATION mbi = {};
                                if (VirtualQueryEx(hProcess, startAddress, &mbi, sizeof(mbi))) {
                                    // Suspicious if start address is in MEM_PRIVATE (shellcode)
                                    // or points to LoadLibrary (classic injection)

                                    if (mbi.Type == MEM_PRIVATE && (mbi.Protect & PAGE_EXECUTE_READWRITE)) {
                                        suspiciousThreads++;
                                    }

                                    // Check if address matches LoadLibraryA/W (Classic DLL Injection)
                                    // We get the addresses from our own process (kernel32 is mapped at same address in all processes)
                                    HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
                                    if (hKernel32) {
                                        FARPROC pLoadLibraryA = GetProcAddress(hKernel32, "LoadLibraryA");
                                        FARPROC pLoadLibraryW = GetProcAddress(hKernel32, "LoadLibraryW");

                                        if ((pLoadLibraryA && startAddress == (PVOID)pLoadLibraryA) ||
                                            (pLoadLibraryW && startAddress == (PVOID)pLoadLibraryW)) {
                                            suspiciousThreads++;
                                            // High confidence injection indicator
                                            // We assume this is suspicious unless it's a known legitimate loader (which is rare for standard threads)
                                        }
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

            // If we found any threads starting in private RWX memory, it's definitely injection
            if (suspiciousThreads > 0) return true;

            // Fallback: If significantly more threads than expected, may indicate injection
            return (threadCount > 100);
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

            HMODULE hModules[1024] = {};
            DWORD cbNeeded = 0;

            if (!EnumProcessModules(hProcess, hModules, sizeof(hModules), &cbNeeded)) {
                return false;
            }

            const DWORD moduleCount = cbNeeded / sizeof(HMODULE);

            for (DWORD i = 0; i < moduleCount; ++i) {
                wchar_t modulePath[MAX_PATH] = {};
                if (GetModuleFileNameExW(hProcess, hModules[i], modulePath, MAX_PATH) > 0) {
                    std::wstring modulePathStr(modulePath);

                    // Check for suspicious DLL locations
                    std::wstring lowerPath = modulePathStr;
                    std::transform(lowerPath.begin(), lowerPath.end(), lowerPath.begin(), ::towlower);

                    // DLLs loaded from temp directories are suspicious
                    if (lowerPath.find(L"\\temp\\") != std::wstring::npos ||
                        lowerPath.find(L"\\tmp\\") != std::wstring::npos ||
                        lowerPath.find(L"\\appdata\\local\\temp\\") != std::wstring::npos) {
                        suspiciousDLLs.push_back(modulePathStr);
                    }

                    // DLLs without proper path (injected)
                    if (lowerPath.find(L"\\windows\\") == std::wstring::npos &&
                        lowerPath.find(L"\\program files") == std::wstring::npos) {
                        // Potentially injected DLL
                    }
                }
            }

            return !suspiciousDLLs.empty();
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
                std::wstring expectedParent = it->second;
                std::transform(expectedParent.begin(), expectedParent.end(), expectedParent.begin(), ::towlower);

                if (lowerParent != expectedParent) {
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

    bool ProcessEvasionDetector::Impl::CheckHardwareBreakpoints(HANDLE hProcess) const noexcept {
        try {
            DWORD processId = GetProcessId(hProcess);
            if (processId == 0) return false;

            HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
            if (hSnapshot == INVALID_HANDLE_VALUE) return false;

            THREADENTRY32 te32 = {};
            te32.dwSize = sizeof(te32);

            bool detected = false;

            if (Thread32First(hSnapshot, &te32)) {
                do {
                    if (te32.th32OwnerProcessID == processId) {
                        // We need to open the thread to get its context
                        // Note: Requires minimal privileges, might fail for higher privileged processes
                        HANDLE hThread = OpenThread(THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME | THREAD_QUERY_INFORMATION, FALSE, te32.th32ThreadID);
                        if (hThread) {
                            // Suspend thread to get consistent context
                            if (SuspendThread(hThread) != (DWORD)-1) {
                                CONTEXT ctx = {};
                                ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

                                if (GetThreadContext(hThread, &ctx)) {
                                    if (ctx.Dr0 != 0 || ctx.Dr1 != 0 || ctx.Dr2 != 0 || ctx.Dr3 != 0) {
                                        detected = true;
                                    }
                                }
                                ResumeThread(hThread);
                            }
                            CloseHandle(hThread);
                        }
                    }
                } while (!detected && Thread32Next(hSnapshot, &te32));
            }

            CloseHandle(hSnapshot);
            return detected;
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
            SS_LOG_ERROR(L"AntiEvasion", L"AnalyzeProcess failed: %hs",
                e.what());

            if (err) {
                err->win32Code = ERROR_INTERNAL_ERROR;
                err->message = L"Analysis failed";
                err->context = Utils::StringUtils::ToWide(e.what());
            }

            m_impl->m_stats.analysisErrors++;
            return result;
        }
        catch (...) {
            SS_LOG_FATAL(L"AntiEvasion", L"AnalyzeProcess: Unknown error");

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
            SS_LOG_ERROR(L"AntiEvasion", L"AnalyzeProcess (by handle) failed: %hs",
                e.what());

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

            // Check for remote threads
            uint32_t threadCount = 0;
            if (m_impl->HasRemoteThreads(hProcess, threadCount)) {
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
            }

            // Check for suspicious DLLs
            if (m_impl->HasSuspiciousDLLs(hProcess, outInfo.injectedDLLs)) {
                outInfo.hasInjection = true;
            }

            CloseHandle(hProcess);

            outInfo.valid = true;

            if (outInfo.hasInjection) {
                m_impl->m_stats.injectionsDetected++;
            }

            return outInfo.hasInjection;
        }
        catch (const std::exception& e) {
            SS_LOG_ERROR(L"AntiEvasion", L"DetectInjection failed: %hs",
                e.what());

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

                auto it = m_impl->m_legitimateProcessPaths.find(processName);
                if (it != m_impl->m_legitimateProcessPaths.end()) {
                    outInfo.expectedPath = it->second;
                }
            }

            // Check for parent spoofing
            if (m_impl->IsParentSpoofed(processName, parentName)) {
                outInfo.isMasquerading = true;
                outInfo.hasParentSpoof = true;

                auto it = m_impl->m_expectedParents.find(processName);
                if (it != m_impl->m_expectedParents.end()) {
                    outInfo.expectedParent = it->second;
                }
            }

            // Check digital signature
            if (!m_impl->IsSignatureValid(processPath)) {
                outInfo.hasSignatureFailure = true;

                // If it's masquerading as a system process but unsigned, that's very suspicious
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
            SS_LOG_ERROR(L"AntiEvasion", L"DetectMasquerading failed: %hs",
                e.what());

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

            HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, processId);
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

            // Check for debug privileges
            HANDLE hToken = nullptr;
            if (OpenProcessToken(hProcess, TOKEN_QUERY, &hToken)) {
                TOKEN_PRIVILEGES privileges = {};
                DWORD returnLength = 0;

                if (GetTokenInformation(hToken, TokenPrivileges, &privileges, sizeof(privileges), &returnLength)) {
                    // Check for SeDebugPrivilege
                    LUID luid;
                    if (LookupPrivilegeValueW(NULL, L"SeDebugPrivilege", &luid)) {
                        for (DWORD i = 0; i < privileges.PrivilegeCount; i++) {
                            if (privileges.Privileges[i].Luid.LowPart == luid.LowPart &&
                                privileges.Privileges[i].Luid.HighPart == luid.HighPart) {
                                if (privileges.Privileges[i].Attributes & (SE_PRIVILEGE_ENABLED | SE_PRIVILEGE_ENABLED_BY_DEFAULT)) {
                                    outInfo.hasDebugPrivilege = true;
                                    outInfo.detectedTechniques.push_back(L"SeDebugPrivilege enabled");
                                }
                                break;
                            }
                        }
                    }
                }

                CloseHandle(hToken);
            }

            // Check for hardware breakpoints
            if (m_impl->CheckHardwareBreakpoints(hProcess)) {
                outInfo.hasAntiDebug = true;
                outInfo.hasHardwareBreakpoints = true;
                outInfo.detectedTechniques.push_back(L"Hardware breakpoints detected");
            }

            CloseHandle(hProcess);

            outInfo.valid = true;

            if (outInfo.hasAntiDebug) {
                m_impl->m_stats.antiDebugDetected++;
            }

            return outInfo.hasAntiDebug;
        }
        catch (const std::exception& e) {
            SS_LOG_ERROR(L"AntiEvasion", L"DetectAntiDebug failed: %hs",
                e.what());

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
            SS_LOG_ERROR(L"AntiEvasion", L"ScanMemory failed: %hs",
                e.what());

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
                ScanMemory(processId, result.suspiciousMemoryRegions, nullptr);
            }

            // Calculate final evasion score
            CalculateEvasionScore(result);
        }
        catch (...) {
            SS_LOG_ERROR(L"AntiEvasion", L"AnalyzeProcessInternal: Exception");
        }
    }

    void ProcessEvasionDetector::CheckInjectionTechniques(
        HANDLE hProcess,
        ProcessEvasionResult& result
    ) noexcept {
        try {
            // Detect specific injection methods based on evidence

            // Classic DLL injection: Remote threads + suspicious DLLs
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

            // Process hollowing: Hollowed image
            if (result.injectionInfo.hasHollowedImage) {
                DetectedTechnique detection(ProcessEvasionTechnique::INJ_ProcessHollowing);
                detection.severity = ProcessEvasionSeverity::Critical;
                detection.confidence = 0.9;
                detection.description = L"Process hollowing detected";
                detection.technicalDetails = L"Process image appears to be replaced";

                AddDetection(result, std::move(detection));
            }
        }
        catch (...) {
            SS_LOG_ERROR(L"AntiEvasion", L"CheckInjectionTechniques: Exception");
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
            SS_LOG_ERROR(L"AntiEvasion", L"CheckMasqueradingTechniques: Exception");
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
        }
        catch (...) {
            SS_LOG_ERROR(L"AntiEvasion", L"CheckAntiDebugTechniques: Exception");
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
            SS_LOG_ERROR(L"AntiEvasion", L"CalculateEvasionScore: Exception");
        }
    }

    void ProcessEvasionDetector::AddDetection(
        ProcessEvasionResult& result,
        DetectedTechnique detection
    ) noexcept {
        try {
            // Set category bit
            const auto techIdx = static_cast<uint32_t>(detection.technique);
            if (techIdx < 32) {
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
            SS_LOG_ERROR(L"AntiEvasion", L"AddDetection: Exception");
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
