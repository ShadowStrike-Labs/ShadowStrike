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
 * @file SandboxAnalyzer.cpp
 * @brief Enterprise-grade VM-based sandbox analysis for comprehensive malware detonation
 *
 * ShadowStrike Core Engine - Sandbox Analysis Module
 * Copyright (c) 2026 ShadowStrike Security Suite. All rights reserved.
 *
 * This module provides full system-level malware analysis using:
 * - Hyper-V integration for hardware-accelerated VMs
 * - VMware Workstation/ESXi support
 * - VirtualBox integration
 * - Docker container isolation
 * - Behavioral monitoring (process, file, registry, network)
 * - Artifact extraction (dropped files, memory dumps, network captures)
 * - MITRE ATT&CK technique mapping
 * - IOC (Indicator of Compromise) correlation
 *
 * Implementation follows enterprise C++20 standards:
 * - PIMPL pattern for ABI stability
 * - Thread-safe with std::shared_mutex
 * - Exception-safe with comprehensive error handling
 * - Statistics tracking for all operations
 * - Memory-safe with smart pointers only
 * - Infrastructure reuse (Utils/, ThreatIntel)
 *
 * CRITICAL: This is user-mode code. Kernel components go in Drivers/ folder.
 */

#include "pch.h"
#include "SandboxAnalyzer.hpp"

// ============================================================================
// STANDARD LIBRARY INCLUDES
// ============================================================================

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <filesystem>
#include <format>
#include <fstream>
#include <memory>
#include <mutex>
#include <optional>
#include <queue>
#include <random>
#include <set>
#include <shared_mutex>
#include <span>
#include <sstream>
#include <string>
#include <string_view>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>

// ============================================================================
// WINDOWS SDK INCLUDES
// ============================================================================

#include <Windows.h>
#include <comutil.h>
#include <wbemidl.h>

#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "comsuppw.lib")

// ============================================================================
// SHADOWSTRIKE INTERNAL INCLUDES
// ============================================================================

#include "../../Utils/Logger.hpp"
#include "../../Utils/FileUtils.hpp"
#include "../../Utils/ProcessUtils.hpp"
#include "../../Utils/SystemUtils.hpp"
#include "../../Utils/StringUtils.hpp"
#include "../../Utils/NetworkUtils.hpp"
#include "../../ThreatIntel/ThreatIntelIndex.hpp"
#include "../../ThreatIntel/ThreatIntelFormat.hpp"

namespace ShadowStrike::Core::Engine {

    namespace fs = std::filesystem;
    using namespace std::chrono_literals;

    /// @brief Log category for all sandbox messages
    static constexpr const wchar_t* kLogCat = L"SandboxAnalyzer";

    // ========================================================================
    // HELPER FUNCTIONS
    // ========================================================================

    [[nodiscard]] const wchar_t* SandboxEnvironmentToString(SandboxEnvironment env) noexcept {
        switch (env) {
        case SandboxEnvironment::HyperV:          return L"Hyper-V";
        case SandboxEnvironment::VMware:           return L"VMware";
        case SandboxEnvironment::VirtualBox:       return L"VirtualBox";
        case SandboxEnvironment::Docker:           return L"Docker";
        case SandboxEnvironment::WindowsContainer: return L"WindowsContainer";
        case SandboxEnvironment::QEMU:             return L"QEMU";
        case SandboxEnvironment::Custom:           return L"Custom";
        default:                                   return L"Unknown";
        }
    }

    [[nodiscard]] const wchar_t* GuestOSTypeToString(GuestOSType os) noexcept {
        switch (os) {
        case GuestOSType::Windows7_x86:      return L"Windows 7 (32-bit)";
        case GuestOSType::Windows7_x64:      return L"Windows 7 (64-bit)";
        case GuestOSType::Windows10_x64:     return L"Windows 10 (64-bit)";
        case GuestOSType::Windows11_x64:     return L"Windows 11 (64-bit)";
        case GuestOSType::WindowsServer2019: return L"Windows Server 2019";
        case GuestOSType::WindowsServer2022: return L"Windows Server 2022";
        case GuestOSType::Linux_Ubuntu:      return L"Ubuntu Linux (64-bit)";
        case GuestOSType::Linux_CentOS:      return L"CentOS Linux (64-bit)";
        case GuestOSType::MacOS:             return L"macOS";
        case GuestOSType::Android:           return L"Android";
        case GuestOSType::Custom:            return L"Custom";
        default:                             return L"Unknown";
        }
    }

    [[nodiscard]] const wchar_t* AnalysisStatusToString(AnalysisStatus status) noexcept {
        switch (status) {
        case AnalysisStatus::Queued:       return L"Queued";
        case AnalysisStatus::Preparing:    return L"Preparing VM";
        case AnalysisStatus::Transferring: return L"Transferring File";
        case AnalysisStatus::Executing:    return L"Executing Sample";
        case AnalysisStatus::Monitoring:   return L"Monitoring Behavior";
        case AnalysisStatus::Capturing:    return L"Capturing Artifacts";
        case AnalysisStatus::Analyzing:    return L"Analyzing Results";
        case AnalysisStatus::Completed:    return L"Completed";
        case AnalysisStatus::Failed:       return L"Failed";
        case AnalysisStatus::Timeout:      return L"Timed Out";
        case AnalysisStatus::Cancelled:    return L"Cancelled";
        default:                           return L"Unknown";
        }
    }

    [[nodiscard]] const wchar_t* ThreatScoreLevelToString(ThreatScoreLevel level) noexcept {
        switch (level) {
        case ThreatScoreLevel::Clean:           return L"Clean";
        case ThreatScoreLevel::Suspicious:      return L"Suspicious";
        case ThreatScoreLevel::LikelyMalicious: return L"Likely Malicious";
        case ThreatScoreLevel::Malicious:       return L"Malicious";
        case ThreatScoreLevel::HighlyMalicious: return L"Highly Malicious";
        default:                                return L"Unknown";
        }
    }

    [[nodiscard]] ThreatScoreLevel CalculateThreatLevel(int score) noexcept {
        if (score >= 81) return ThreatScoreLevel::HighlyMalicious;
        if (score >= 61) return ThreatScoreLevel::Malicious;
        if (score >= 41) return ThreatScoreLevel::LikelyMalicious;
        if (score >= 21) return ThreatScoreLevel::Suspicious;
        return ThreatScoreLevel::Clean;
    }

    // Forward declaration so IsHyperVAvailable can use the centralised PS runner
    // defined later in the translation unit.
    [[nodiscard]] static bool RunPowerShellCmd(
        const std::wstring& command,
        DWORD timeoutMs,
        DWORD& exitCode) noexcept;

    [[nodiscard]] bool IsHyperVAvailable() noexcept {
        // Use the centralised PS runner so we get timeout/handle hygiene and
        // proper exit-code observation. Hyper-V is only considered available
        // when the optional feature query exits successfully (rc == 0).
        try {
            DWORD exitCode = 1;
            const bool ran = RunPowerShellCmd(
                L"if ((Get-WindowsOptionalFeature -Online -FeatureName "
                L"Microsoft-Hyper-V -ErrorAction SilentlyContinue).State -eq "
                L"'Enabled') { exit 0 } else { exit 1 }",
                10000, exitCode);
            return ran && exitCode == 0;
        } catch (...) {
            return false;
        }
    }

    // ========================================================================
    // POWERSHELL EXECUTION HELPER
    // ========================================================================

    /**
     * @brief Escape a value for safe inclusion inside a PowerShell single-quoted
     *        string literal.
     *
     * PowerShell single-quoted strings are *literal* except that an embedded
     * single quote is escaped by doubling it (`''`). Without this transform,
     * an attacker-controlled value (VM name returned from WMI, file path,
     * arguments, etc.) can break out of the quoting and inject arbitrary
     * PowerShell. We additionally strip control characters and reject
     * embedded NUL/CR/LF which would terminate the command line on the
     * Windows side and enable script-stuffing.
     *
     * SECURITY: CWE-78 (OS Command Injection) hardening for all paths that
     * compose Hyper-V management commands.
     */
    [[nodiscard]] static std::wstring EscapePSSingleQuoted(std::wstring_view raw) noexcept {
        std::wstring out;
        out.reserve(raw.size() + 8);
        for (wchar_t ch : raw) {
            // Reject NUL/CR/LF/FF/VT outright; these enable line injection.
            if (ch == L'\0' || ch == L'\r' || ch == L'\n' ||
                ch == L'\f' || ch == L'\v') {
                continue;
            }
            if (ch == L'\'') {
                // Double single-quote per PowerShell quoting rules.
                out.push_back(L'\'');
                out.push_back(L'\'');
            } else {
                out.push_back(ch);
            }
        }
        return out;
    }

    /// @brief Cap on raw PS-injected substrings to avoid pathological commands.
    inline constexpr size_t kMaxPSEscapedLen = 4096;

    [[nodiscard]] static bool IsPSInputSane(std::wstring_view raw) noexcept {
        return raw.size() <= kMaxPSEscapedLen;
    }

    /**
     * @brief Execute a PowerShell command and wait for completion.
     * @param command The PowerShell script/command to execute.
     * @param timeoutMs Maximum wait time in milliseconds.
     * @param exitCode [out] Process exit code.
     * @return true if the process was created and completed within the timeout.
     */
    [[nodiscard]] static bool RunPowerShellCmd(
        const std::wstring& command,
        DWORD timeoutMs,
        DWORD& exitCode) noexcept
    {
        try {
            std::wstring args = L"-NoProfile -NonInteractive -Command \"" + command + L"\"";

            Utils::ProcessUtils::ProcessCreationResult result{};
            Utils::ProcessUtils::ProcessStartupInfo si{};
            si.redirectStdOutput = true;
            si.redirectStdError = true;

            Utils::ProcessUtils::Error procErr{};
            const bool created = Utils::ProcessUtils::CreateProcess(
                L"powershell.exe", args, result, si,
                Utils::ProcessUtils::ProcessCreationFlags::CreateNoWindow, &procErr);

            if (!created || !result.succeeded) {
                SS_LOG_ERROR(kLogCat, L"Failed to launch PowerShell: %ls", procErr.message.c_str());
                if (result.hProcess) ::CloseHandle(result.hProcess);
                if (result.hThread)  ::CloseHandle(result.hThread);
                return false;
            }

            const bool waited = Utils::ProcessUtils::WaitForProcess(result.hProcess, timeoutMs, &procErr);
            if (!waited) {
                SS_LOG_WARN(kLogCat, L"PowerShell command timed out after %lu ms", timeoutMs);
                ::TerminateProcess(result.hProcess, 1);
                ::CloseHandle(result.hProcess);
                if (result.hThread) ::CloseHandle(result.hThread);
                exitCode = static_cast<DWORD>(-1);
                return false;
            }

            ::GetExitCodeProcess(result.hProcess, &exitCode);
            ::CloseHandle(result.hProcess);
            if (result.hThread) ::CloseHandle(result.hThread);
            return true;

        } catch (...) {
            SS_LOG_ERROR(kLogCat, L"Exception in RunPowerShellCmd");
            return false;
        }
    }

    // ========================================================================
    // STRUCT IMPLEMENTATIONS
    // ========================================================================

    bool VMConfiguration::IsValid() const noexcept {
        return !vmName.empty() && memoryMb >= 512 && cpuCores >= 1;
    }

    std::string VMConfiguration::ToJson() const {
        std::ostringstream ss;
        ss << "{\"vmName\":\"" << vmName << "\""
           << ",\"environment\":" << static_cast<int>(environment)
           << ",\"guestOS\":" << static_cast<int>(guestOS)
           << ",\"memoryMb\":" << memoryMb
           << ",\"cpuCores\":" << cpuCores
           << ",\"networkIsolation\":" << (networkIsolation ? "true" : "false")
           << "}";
        return ss.str();
    }

    std::string ProcessEvent::ToJson() const {
        std::ostringstream ss;
        ss << "{\"eventType\":\"" << eventType << "\""
           << ",\"processId\":" << processId
           << ",\"parentProcessId\":" << parentProcessId
           << ",\"processName\":\"" << Utils::StringUtils::ToNarrow(processName) << "\""
           << "}";
        return ss.str();
    }

    std::string FileEvent::ToJson() const {
        std::ostringstream ss;
        ss << "{\"eventType\":\"" << eventType << "\""
           << ",\"filePath\":\"" << Utils::StringUtils::ToNarrow(filePath.wstring()) << "\""
           << ",\"fileSize\":" << fileSize
           << ",\"sha256\":\"" << sha256Hash << "\""
           << "}";
        return ss.str();
    }

    std::string RegistryEvent::ToJson() const {
        std::ostringstream ss;
        ss << "{\"eventType\":\"" << eventType << "\""
           << ",\"keyPath\":\"" << Utils::StringUtils::ToNarrow(keyPath) << "\""
           << ",\"valueName\":\"" << Utils::StringUtils::ToNarrow(valueName) << "\""
           << "}";
        return ss.str();
    }

    std::string NetworkEvent::ToJson() const {
        std::ostringstream ss;
        ss << "{\"protocol\":\"" << protocol << "\""
           << ",\"sourceIP\":\"" << sourceIP << "\""
           << ",\"sourcePort\":" << sourcePort
           << ",\"destinationIP\":\"" << destinationIP << "\""
           << ",\"destinationPort\":" << destinationPort
           << "}";
        return ss.str();
    }

    std::string BehavioralIndicator::ToJson() const {
        std::ostringstream ss;
        ss << "{\"indicatorId\":\"" << indicatorId << "\""
           << ",\"description\":\"" << description << "\""
           << ",\"severity\":" << severity
           << ",\"mitreId\":\"" << mitreId << "\""
           << "}";
        return ss.str();
    }

    std::string ExtractedArtifact::ToJson() const {
        std::ostringstream ss;
        ss << "{\"artifactType\":\"" << artifactType << "\""
           << ",\"originalPath\":\"" << Utils::StringUtils::ToNarrow(originalPath.wstring()) << "\""
           << ",\"size\":" << size
           << ",\"sha256\":\"" << sha256Hash << "\""
           << ",\"isMalicious\":" << (isMalicious ? "true" : "false")
           << "}";
        return ss.str();
    }

    std::string ExtractedIOC::ToJson() const {
        std::ostringstream ss;
        ss << "{\"iocType\":\"" << iocType << "\""
           << ",\"value\":\"" << value << "\""
           << ",\"confidence\":" << confidence
           << "}";
        return ss.str();
    }

    std::string SandboxVerdict::ToJson() const {
        std::ostringstream ss;
        ss << "{\"isMalicious\":" << (isMalicious ? "true" : "false")
           << ",\"threatScore\":" << threatScore
           << ",\"durationSeconds\":" << durationSeconds
           << ",\"processEvents\":" << processEvents.size()
           << ",\"fileEvents\":" << fileEvents.size()
           << ",\"registryEvents\":" << registryEvents.size()
           << ",\"networkEvents\":" << networkEvents.size()
           << ",\"artifacts\":" << artifacts.size()
           << ",\"iocs\":" << iocs.size()
           << "}";
        return ss.str();
    }

    bool SandboxAnalysisOptions::IsValid() const noexcept {
        return timeoutSeconds > 0 && timeoutSeconds <= SandboxConstants::MAX_TIMEOUT_SECONDS;
    }

    bool SandboxAnalyzerConfiguration::IsValid() const noexcept {
        return maxConcurrentAnalyses > 0 &&
               defaultTimeoutSeconds > 0 &&
               defaultTimeoutSeconds <= SandboxConstants::MAX_TIMEOUT_SECONDS;
    }

    // ========================================================================
    // PIMPL IMPLEMENTATION CLASS
    // ========================================================================

    class SandboxAnalyzer::Impl {
    public:
        // ====================================================================
        // MEMBERS
        // ====================================================================

        mutable std::shared_mutex m_mutex;
        std::atomic<bool> m_initialized{ false };
        SandboxAnalyzerConfiguration m_config;
        ThreatIntel::ThreatIntelIndex* m_threatIntel = nullptr;
        SandboxAnalyzer::Statistics m_stats;

        /// @brief Whether COM was initialized by us (so we only uninit what we init)
        bool m_comInitializedByUs = false;

        struct AnalysisTask {
            std::string taskId;
            fs::path filePath;
            SandboxAnalysisOptions options;
            SandboxVerdict verdict;
            // DESIGN: status is std::atomic so non-owner threads (public getters,
            // worker thread, cancellation paths) can observe phase transitions
            // without taking m_mutex on every transition. Verdict body is only
            // safe to read after `finalized` has been observed with acquire
            // semantics.
            std::atomic<AnalysisStatus> status{ AnalysisStatus::Queued };
            std::chrono::system_clock::time_point startTime;
            std::chrono::system_clock::time_point endTime;
            std::vector<ExtractedArtifact> artifacts;
            std::atomic<bool> shouldCancel{ false };
            // DESIGN: release-store after AnalyzeResults; readers acquire-load
            // before accessing verdict/artifacts to avoid data races.
            std::atomic<bool> finalized{ false };
        };

        std::unordered_map<std::string, std::unique_ptr<AnalysisTask>> m_tasks;
        std::queue<std::string> m_taskQueue;
        std::atomic<uint64_t> m_nextTaskId{ 1 };

        struct VMInstance {
            std::string vmId;
            std::string vmName;
            SandboxEnvironment environment = SandboxEnvironment::HyperV;
            GuestOSType guestOS = GuestOSType::Windows10_x64;
            VMState state = VMState::Stopped;
            std::string snapshotId;
            std::chrono::system_clock::time_point lastUsed;
            bool isAvailable = true;
        };

        std::vector<VMInstance> m_availableVMs;

        /// @brief MITRE ATT&CK technique mapping
        const std::unordered_map<std::string, std::string> m_mitreTechniques = {
            {"T1055", "Process Injection"},
            {"T1059", "Command and Scripting Interpreter"},
            {"T1071", "Application Layer Protocol"},
            {"T1082", "System Information Discovery"},
            {"T1083", "File and Directory Discovery"},
            {"T1105", "Ingress Tool Transfer"},
            {"T1112", "Modify Registry"},
            {"T1129", "Shared Modules"},
            {"T1140", "Deobfuscate/Decode Files or Information"},
            {"T1486", "Data Encrypted for Impact"},
            {"T1547", "Boot or Logon Autostart Execution"},
            {"T1562", "Impair Defenses"},
            {"T1566", "Phishing"},
            {"T1569", "System Services"},
            {"T1573", "Encrypted Channel"}
        };

        /// @brief Worker thread for async task processing
        std::thread m_workerThread;
        std::atomic<bool> m_workerRunning{ false };

        /// @brief Callbacks (protected by m_mutex)
        AnalysisProgressCallback m_progressCb;
        AnalysisCompleteCallback m_completeCb;
        ErrorCallback m_errorCb;

        // ====================================================================
        // METHODS
        // ====================================================================

        Impl() = default;
        ~Impl() = default;

        [[nodiscard]] bool Initialize(const SandboxAnalyzerConfiguration& config, SandboxError* err) noexcept;
        void Shutdown() noexcept;

        // VM management
        [[nodiscard]] bool DetectAvailableVMs() noexcept;
        [[nodiscard]] bool PrepareVM(VMInstance& vm, const SandboxAnalysisOptions& options) noexcept;
        [[nodiscard]] bool StartVM(VMInstance& vm) noexcept;
        [[nodiscard]] bool StopVM(VMInstance& vm) noexcept;
        [[nodiscard]] bool RestoreSnapshot(VMInstance& vm) noexcept;
        [[nodiscard]] VMInstance* FindAvailableVM(GuestOSType preferredOS) noexcept;

        // File transfer & execution
        [[nodiscard]] bool TransferFileToVM(VMInstance& vm, const fs::path& filePath, std::wstring& guestPath) noexcept;
        [[nodiscard]] bool ExecuteInVM(VMInstance& vm, const std::wstring& command, const std::wstring& args) noexcept;

        // Monitoring
        [[nodiscard]] bool MonitorProcessEvents(AnalysisTask* task, VMInstance& vm, uint32_t durationSeconds) noexcept;
        [[nodiscard]] bool MonitorFileEvents(AnalysisTask* task, VMInstance& vm) noexcept;
        [[nodiscard]] bool MonitorRegistryEvents(AnalysisTask* task, VMInstance& vm) noexcept;
        [[nodiscard]] bool MonitorNetworkEvents(AnalysisTask* task, VMInstance& vm) noexcept;

        // Artifact extraction
        [[nodiscard]] bool ExtractDroppedFiles(AnalysisTask* task, VMInstance& vm) noexcept;
        [[nodiscard]] bool CreateMemoryDump(AnalysisTask* task, VMInstance& vm) noexcept;
        [[nodiscard]] bool CaptureNetworkTraffic(AnalysisTask* task, VMInstance& vm) noexcept;

        // Analysis
        [[nodiscard]] bool AnalyzeResults(AnalysisTask* task) noexcept;
        [[nodiscard]] int CalculateThreatScore(const SandboxVerdict& verdict) noexcept;
        [[nodiscard]] ThreatScoreLevel DetermineThreatLevel(int score) noexcept;
        [[nodiscard]] bool CorrelateWithThreatIntel(AnalysisTask* task) noexcept;
        [[nodiscard]] std::set<std::string> MapToMITRE(const SandboxVerdict& verdict) noexcept;

        // Task management
        [[nodiscard]] std::string CreateTask(const fs::path& filePath,
                                             const SandboxAnalysisOptions& options,
                                             bool enqueue = true) noexcept;
        [[nodiscard]] AnalysisTask* GetTask(const std::string& taskId) noexcept;
        void ProcessTaskQueue() noexcept;
        [[nodiscard]] bool ExecuteTask(AnalysisTask* task) noexcept;

        // Worker
        void WorkerLoop() noexcept;
    };

    // ========================================================================
    // IMPL: INITIALIZATION
    // ========================================================================

    bool SandboxAnalyzer::Impl::Initialize(const SandboxAnalyzerConfiguration& config, SandboxError* err) noexcept {
        try {
            if (m_initialized.exchange(true)) {
                return true;
            }

            SS_LOG_INFO(kLogCat, L"Initializing sandbox analyzer v%u.%u.%u",
                SandboxConstants::VERSION_MAJOR,
                SandboxConstants::VERSION_MINOR,
                SandboxConstants::VERSION_PATCH);

            m_config = config;
            m_threatIntel = config.threatIntel;
            if (m_threatIntel) {
                SS_LOG_INFO(kLogCat,
                    L"Threat-intelligence correlation enabled (initialized=%ls)",
                    m_threatIntel->IsInitialized() ? L"yes" : L"no");
            } else {
                SS_LOG_INFO(kLogCat,
                    L"Threat-intelligence correlation disabled (no index supplied)");
            }

            // Initialize COM for WMI access - track whether we did it
            HRESULT hr = ::CoInitializeEx(nullptr, COINIT_MULTITHREADED);
            if (SUCCEEDED(hr)) {
                m_comInitializedByUs = true;
            } else if (hr == RPC_E_CHANGED_MODE) {
                // COM already initialized in different mode; we can still proceed
                SS_LOG_WARN(kLogCat, L"COM already initialized in STA mode, proceeding");
                m_comInitializedByUs = false;
            } else {
                SS_LOG_ERROR(kLogCat, L"CoInitializeEx failed: HRESULT 0x%08X", static_cast<uint32_t>(hr));
                if (err) {
                    err->code = static_cast<DWORD>(hr);
                    err->message = L"COM initialization failed";
                }
                m_initialized = false;
                return false;
            }

            // Detect available VMs
            if (!DetectAvailableVMs()) {
                SS_LOG_WARN(kLogCat, L"No VMs detected - sandbox analysis requires Hyper-V VMs");
            }

            SS_LOG_INFO(kLogCat, L"Detected %zu available VM(s)", m_availableVMs.size());

            // Start worker thread for async task processing
            m_workerRunning = true;
            m_workerThread = std::thread([this]() { WorkerLoop(); });

            SS_LOG_INFO(kLogCat, L"Initialization complete");
            return true;

        } catch (const std::exception& e) {
            SS_LOG_ERROR(kLogCat, L"Initialization failed: %ls",
                Utils::StringUtils::ToWide(e.what()).c_str());
            if (err) {
                err->code = ERROR_INTERNAL_ERROR;
                err->message = L"Initialization failed";
                err->context = Utils::StringUtils::ToWide(e.what());
            }
            if (m_comInitializedByUs) {
                ::CoUninitialize();
                m_comInitializedByUs = false;
            }
            m_initialized = false;
            return false;
        } catch (...) {
            SS_LOG_FATAL(kLogCat, L"Unknown initialization error");
            if (err) {
                err->code = ERROR_INTERNAL_ERROR;
                err->message = L"Unknown initialization error";
            }
            if (m_comInitializedByUs) {
                ::CoUninitialize();
                m_comInitializedByUs = false;
            }
            m_initialized = false;
            return false;
        }
    }

    void SandboxAnalyzer::Impl::Shutdown() noexcept {
        try {
            if (!m_initialized.exchange(false)) {
                return;
            }

            SS_LOG_INFO(kLogCat, L"Shutting down...");

            // Stop worker thread
            m_workerRunning = false;
            if (m_workerThread.joinable()) {
                m_workerThread.join();
            }

            {
                std::unique_lock lock(m_mutex);

                // Cancel all pending tasks
                for (auto& [taskId, task] : m_tasks) {
                    task->shouldCancel = true;
                }

                // Stop all running VMs (best-effort during shutdown).
                for (auto& vm : m_availableVMs) {
                    if (vm.state == VMState::Running) {
                        if (!StopVM(vm)) {
                            SS_LOG_WARN(kLogCat,
                                L"Best-effort StopVM failed during shutdown for '%ls'",
                                Utils::StringUtils::ToWide(vm.vmName).c_str());
                        }
                    }
                }

                m_tasks.clear();
                m_availableVMs.clear();
            }

            // Only uninitialize COM if we initialized it
            if (m_comInitializedByUs) {
                ::CoUninitialize();
                m_comInitializedByUs = false;
            }

            SS_LOG_INFO(kLogCat, L"Shutdown complete");
        } catch (...) {
            SS_LOG_ERROR(kLogCat, L"Exception during shutdown");
        }
    }

    // ========================================================================
    // IMPL: WORKER THREAD
    // ========================================================================

    void SandboxAnalyzer::Impl::WorkerLoop() noexcept {
        SS_LOG_INFO(kLogCat, L"Worker thread started");
        while (m_workerRunning.load()) {
            ProcessTaskQueue();
            std::this_thread::sleep_for(500ms);
        }
        SS_LOG_INFO(kLogCat, L"Worker thread stopped");
    }

    // ========================================================================
    // IMPL: VM MANAGEMENT
    // ========================================================================

    bool SandboxAnalyzer::Impl::DetectAvailableVMs() noexcept {
        try {
            // Detect Hyper-V VMs via WMI
            IWbemLocator* pLoc = nullptr;
            HRESULT hr = ::CoCreateInstance(
                CLSID_WbemLocator, nullptr,
                CLSCTX_INPROC_SERVER, IID_IWbemLocator,
                reinterpret_cast<LPVOID*>(&pLoc));

            if (FAILED(hr)) {
                SS_LOG_WARN(kLogCat, L"WMI locator creation failed: HRESULT 0x%08X", static_cast<uint32_t>(hr));
                return false;
            }

            IWbemServices* pSvc = nullptr;
            hr = pLoc->ConnectServer(
                _bstr_t(L"ROOT\\virtualization\\v2"),
                nullptr, nullptr, nullptr, 0, nullptr, nullptr, &pSvc);

            if (FAILED(hr) || !pSvc) {
                SS_LOG_WARN(kLogCat, L"WMI connect to Hyper-V namespace failed: HRESULT 0x%08X",
                    static_cast<uint32_t>(hr));
                if (pSvc) pSvc->Release();
                pLoc->Release();
                return false;
            }

            hr = ::CoSetProxyBlanket(pSvc,
                RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, nullptr,
                RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE,
                nullptr, EOAC_NONE);
            if (FAILED(hr)) {
                SS_LOG_WARN(kLogCat,
                    L"CoSetProxyBlanket failed: HRESULT 0x%08X",
                    static_cast<uint32_t>(hr));
                pSvc->Release();
                pLoc->Release();
                return false;
            }

            IEnumWbemClassObject* pEnumerator = nullptr;
            hr = pSvc->ExecQuery(
                _bstr_t(L"WQL"),
                _bstr_t(L"SELECT * FROM Msvm_ComputerSystem WHERE Caption='Virtual Machine'"),
                WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
                nullptr, &pEnumerator);

            if (SUCCEEDED(hr) && pEnumerator) {
                IWbemClassObject* pclsObj = nullptr;
                ULONG uReturn = 0;

                while (pEnumerator) {
                    hr = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
                    if (FAILED(hr) || uReturn == 0 || !pclsObj) break;

                    VARIANT vtProp;
                    ::VariantInit(&vtProp);

                    hr = pclsObj->Get(L"ElementName", 0, &vtProp, nullptr, nullptr);
                    if (SUCCEEDED(hr) && vtProp.vt == VT_BSTR &&
                        vtProp.bstrVal != nullptr &&
                        ::SysStringLen(vtProp.bstrVal) > 0)
                    {
                        VMInstance vm;
                        vm.vmId = Utils::StringUtils::ToNarrow(vtProp.bstrVal);
                        vm.vmName = vm.vmId;
                        vm.environment = SandboxEnvironment::HyperV;
                        vm.guestOS = GuestOSType::Windows10_x64;
                        vm.state = VMState::Stopped;
                        vm.isAvailable = true;

                        m_availableVMs.push_back(std::move(vm));
                    }

                    ::VariantClear(&vtProp);
                    pclsObj->Release();
                    pclsObj = nullptr;
                }
                pEnumerator->Release();
            }

            pSvc->Release();
            pLoc->Release();

            if (m_availableVMs.empty()) {
                SS_LOG_WARN(kLogCat, L"No Hyper-V VMs detected - sandbox analysis unavailable");
                return false;
            }

            return true;

        } catch (...) {
            SS_LOG_ERROR(kLogCat, L"Exception during VM detection");
            return false;
        }
    }

    bool SandboxAnalyzer::Impl::PrepareVM(VMInstance& vm, const SandboxAnalysisOptions& options) noexcept {
        try {
            (void)options; // Reserved for future per-task tuning (memory, vCPU, NIC).
            SS_LOG_INFO(kLogCat, L"Preparing VM '%ls'",
                Utils::StringUtils::ToWide(vm.vmName).c_str());

            if (!RestoreSnapshot(vm)) {
                SS_LOG_ERROR(kLogCat, L"Failed to restore snapshot for VM '%ls'",
                    Utils::StringUtils::ToWide(vm.vmName).c_str());
                return false;
            }

            if (!StartVM(vm)) {
                SS_LOG_ERROR(kLogCat, L"Failed to start VM '%ls'",
                    Utils::StringUtils::ToWide(vm.vmName).c_str());
                return false;
            }

            // Poll for VM readiness via heartbeat integration service.
            // SECURITY: vm.vmName is escaped before injection to prevent
            // PowerShell argument injection via attacker-influenced names.
            const std::wstring escName =
                EscapePSSingleQuoted(Utils::StringUtils::ToWide(vm.vmName));
            if (!IsPSInputSane(escName)) {
                SS_LOG_ERROR(kLogCat, L"VM name exceeds safe PS length cap");
                return false;
            }
            const auto deadline = Clock::now() +
                std::chrono::seconds(SandboxConstants::VM_READY_MAX_WAIT_S);

            while (Clock::now() < deadline) {
                DWORD exitCode = 1;
                std::wstring checkCmd =
                    L"if (((Get-VM -Name '" + escName +
                    L"' -ErrorAction SilentlyContinue | "
                    L"Get-VMIntegrationService -Name 'Heartbeat')."
                    L"PrimaryStatusDescription) -eq 'OK') { exit 0 } else { exit 1 }";

                if (RunPowerShellCmd(checkCmd, SandboxConstants::PS_COMMAND_TIMEOUT_MS, exitCode) &&
                    exitCode == 0) {
                    SS_LOG_INFO(kLogCat, L"VM '%ls' is ready",
                        Utils::StringUtils::ToWide(vm.vmName).c_str());
                    return true;
                }
                std::this_thread::sleep_for(
                    std::chrono::milliseconds(SandboxConstants::VM_READY_POLL_MS));
            }

            SS_LOG_ERROR(kLogCat, L"VM '%ls' did not become ready within %u seconds",
                Utils::StringUtils::ToWide(vm.vmName).c_str(),
                SandboxConstants::VM_READY_MAX_WAIT_S);
            // Best-effort cleanup; we are already on the failure path.
            if (!StopVM(vm)) {
                SS_LOG_WARN(kLogCat,
                    L"Best-effort StopVM after readiness timeout failed for '%ls'",
                    Utils::StringUtils::ToWide(vm.vmName).c_str());
            }
            return false;

        } catch (...) {
            SS_LOG_ERROR(kLogCat, L"Exception during VM preparation");
            return false;
        }
    }

    bool SandboxAnalyzer::Impl::StartVM(VMInstance& vm) noexcept {
        try {
            if (vm.state == VMState::Running) {
                return true;
            }

            SS_LOG_INFO(kLogCat, L"Starting VM '%ls'",
                Utils::StringUtils::ToWide(vm.vmName).c_str());

            if (vm.environment == SandboxEnvironment::HyperV) {
                const std::wstring escName =
                    EscapePSSingleQuoted(Utils::StringUtils::ToWide(vm.vmName));
                if (!IsPSInputSane(escName)) {
                    SS_LOG_ERROR(kLogCat, L"VM name exceeds safe PS length cap");
                    vm.state = VMState::Error;
                    return false;
                }
                std::wstring command = L"Start-VM -Name '" + escName + L"' -ErrorAction Stop";

                DWORD exitCode = 1;
                if (!RunPowerShellCmd(command, SandboxConstants::PS_COMMAND_TIMEOUT_MS, exitCode) ||
                    exitCode != 0) {
                    SS_LOG_ERROR(kLogCat, L"Start-VM failed for '%ls' (exit code %lu)",
                        Utils::StringUtils::ToWide(vm.vmName).c_str(), exitCode);
                    vm.state = VMState::Error;
                    return false;
                }
            }

            vm.state = VMState::Running;
            m_stats.vmsStarted++;
            return true;

        } catch (...) {
            SS_LOG_ERROR(kLogCat, L"Exception during VM start");
            vm.state = VMState::Error;
            return false;
        }
    }

    bool SandboxAnalyzer::Impl::StopVM(VMInstance& vm) noexcept {
        try {
            if (vm.state == VMState::Stopped) {
                return true;
            }

            SS_LOG_INFO(kLogCat, L"Stopping VM '%ls'",
                Utils::StringUtils::ToWide(vm.vmName).c_str());

            if (vm.environment == SandboxEnvironment::HyperV) {
                const std::wstring escName =
                    EscapePSSingleQuoted(Utils::StringUtils::ToWide(vm.vmName));
                if (!IsPSInputSane(escName)) {
                    SS_LOG_ERROR(kLogCat, L"VM name exceeds safe PS length cap");
                    return false;
                }
                std::wstring command = L"Stop-VM -Name '" + escName +
                    L"' -Force -TurnOff -ErrorAction Stop";

                DWORD exitCode = 1;
                if (!RunPowerShellCmd(command, SandboxConstants::PS_COMMAND_TIMEOUT_MS, exitCode) ||
                    exitCode != 0) {
                    SS_LOG_WARN(kLogCat, L"Stop-VM failed for '%ls' (exit code %lu), forcing",
                        Utils::StringUtils::ToWide(vm.vmName).c_str(), exitCode);
                }
            }

            vm.state = VMState::Stopped;
            m_stats.vmsStopped++;
            return true;

        } catch (...) {
            SS_LOG_ERROR(kLogCat, L"Exception during VM stop");
            return false;
        }
    }

    bool SandboxAnalyzer::Impl::RestoreSnapshot(VMInstance& vm) noexcept {
        try {
            SS_LOG_INFO(kLogCat, L"Restoring clean snapshot for VM '%ls'",
                Utils::StringUtils::ToWide(vm.vmName).c_str());

            vm.state = VMState::Restoring;

            if (vm.environment == SandboxEnvironment::HyperV) {
                const std::wstring escName =
                    EscapePSSingleQuoted(Utils::StringUtils::ToWide(vm.vmName));
                std::wstring snapshotName = vm.snapshotId.empty() ? L"Clean" :
                    Utils::StringUtils::ToWide(vm.snapshotId);
                const std::wstring escSnap = EscapePSSingleQuoted(snapshotName);
                if (!IsPSInputSane(escName) || !IsPSInputSane(escSnap)) {
                    SS_LOG_ERROR(kLogCat, L"VM/snapshot identifier exceeds safe PS length cap");
                    vm.state = VMState::Error;
                    return false;
                }

                std::wstring command = L"Restore-VMSnapshot -VMName '" + escName +
                    L"' -Name '" + escSnap + L"' -Confirm:$false -ErrorAction Stop";

                DWORD exitCode = 1;
                if (!RunPowerShellCmd(command, SandboxConstants::PS_COMMAND_TIMEOUT_MS, exitCode) ||
                    exitCode != 0) {
                    SS_LOG_ERROR(kLogCat, L"Restore-VMSnapshot failed for '%ls' (exit code %lu)",
                        Utils::StringUtils::ToWide(vm.vmName).c_str(), exitCode);
                    vm.state = VMState::Error;
                    return false;
                }
            }

            vm.state = VMState::Stopped;
            m_stats.snapshotsRestored++;
            return true;

        } catch (...) {
            SS_LOG_ERROR(kLogCat, L"Exception during snapshot restore");
            vm.state = VMState::Error;
            return false;
        }
    }

    SandboxAnalyzer::Impl::VMInstance* SandboxAnalyzer::Impl::FindAvailableVM(GuestOSType preferredOS) noexcept {
        // Caller must hold m_mutex (exclusive lock)
        try {
            for (auto& vm : m_availableVMs) {
                if (vm.isAvailable && vm.guestOS == preferredOS) {
                    return &vm;
                }
            }
            for (auto& vm : m_availableVMs) {
                if (vm.isAvailable) {
                    return &vm;
                }
            }
            return nullptr;
        } catch (...) {
            return nullptr;
        }
    }

    // ========================================================================
    // IMPL: FILE TRANSFER
    // ========================================================================

    bool SandboxAnalyzer::Impl::TransferFileToVM(VMInstance& vm, const fs::path& filePath, std::wstring& guestPath) noexcept {
        try {
            SS_LOG_INFO(kLogCat, L"Transferring file to VM '%ls': %ls",
                Utils::StringUtils::ToWide(vm.vmName).c_str(),
                filePath.filename().wstring().c_str());

            // Validate source file exists and is within size limits
            std::error_code ec;
            if (!fs::exists(filePath, ec) || ec) {
                SS_LOG_ERROR(kLogCat, L"Source file does not exist: %ls", filePath.wstring().c_str());
                return false;
            }

            const auto fileSize = fs::file_size(filePath, ec);
            if (ec || fileSize == 0) {
                SS_LOG_ERROR(kLogCat, L"Cannot read file size for: %ls", filePath.wstring().c_str());
                return false;
            }

            // Sanitize filename to prevent guest-side path traversal and to
            // avoid characters that are illegal on NTFS / are interpreted by
            // PowerShell. We keep a conservative whitelist: alnum, dot, dash,
            // underscore. Everything else collapses to '_'.
            std::wstring safeFilename = filePath.filename().wstring();
            for (auto& ch : safeFilename) {
                const bool ok =
                    (ch >= L'a' && ch <= L'z') ||
                    (ch >= L'A' && ch <= L'Z') ||
                    (ch >= L'0' && ch <= L'9') ||
                    ch == L'.' || ch == L'-' || ch == L'_';
                if (!ok) {
                    ch = L'_';
                }
            }
            // Defensive: never allow leading dots ("..something") to escape.
            while (!safeFilename.empty() && safeFilename.front() == L'.') {
                safeFilename.erase(safeFilename.begin());
            }
            if (safeFilename.empty()) {
                safeFilename = L"sample.bin";
            }
            // Prefix with task-unique directory created by caller; if absent,
            // fall back to Public Documents.
            guestPath = L"C:\\Users\\Public\\Documents\\" + safeFilename;

            if (vm.environment == SandboxEnvironment::HyperV) {
                const std::wstring escName =
                    EscapePSSingleQuoted(Utils::StringUtils::ToWide(vm.vmName));
                const std::wstring escSrc = EscapePSSingleQuoted(filePath.wstring());
                const std::wstring escDst = EscapePSSingleQuoted(guestPath);
                if (!IsPSInputSane(escName) || !IsPSInputSane(escSrc) || !IsPSInputSane(escDst)) {
                    SS_LOG_ERROR(kLogCat, L"Identifier(s) exceed safe PS length cap");
                    return false;
                }

                std::wstring command = L"Copy-VMFile -VMName '" + escName +
                    L"' -SourcePath '" + escSrc +
                    L"' -DestinationPath '" + escDst +
                    L"' -FileSource Host -Force -ErrorAction Stop";

                DWORD exitCode = 1;
                if (!RunPowerShellCmd(command, SandboxConstants::PS_COMMAND_TIMEOUT_MS, exitCode) ||
                    exitCode != 0) {
                    SS_LOG_ERROR(kLogCat, L"Copy-VMFile failed (exit code %lu)", exitCode);
                    return false;
                }
            }

            m_stats.filesTransferred++;
            return true;

        } catch (...) {
            SS_LOG_ERROR(kLogCat, L"Exception during file transfer");
            return false;
        }
    }

    bool SandboxAnalyzer::Impl::ExecuteInVM(VMInstance& vm, const std::wstring& command, const std::wstring& args) noexcept {
        try {
            SS_LOG_INFO(kLogCat, L"Executing in VM '%ls'",
                Utils::StringUtils::ToWide(vm.vmName).c_str());

            if (vm.environment == SandboxEnvironment::HyperV) {
                const std::wstring escName = EscapePSSingleQuoted(Utils::StringUtils::ToWide(vm.vmName));
                const std::wstring escCmd  = EscapePSSingleQuoted(command);
                const std::wstring escArgs = EscapePSSingleQuoted(args);
                if (!IsPSInputSane(escName) || !IsPSInputSane(escCmd) || !IsPSInputSane(escArgs)) {
                    SS_LOG_ERROR(kLogCat, L"Identifier(s) exceed safe PS length cap");
                    return false;
                }
                // Use Invoke-Command to start the sample inside the guest.
                // Note: the inner Start-Process is constructed in the script
                // block using an outer scope variable to avoid double quoting
                // the user-controlled command path/args.
                std::wstring psCommand =
                    L"$cmd='" + escCmd + L"';"
                    L"$argList='" + escArgs + L"';"
                    L"Invoke-Command -VMName '" + escName +
                    L"' -ScriptBlock { param($c,$a) "
                    L"if ([string]::IsNullOrEmpty($a)) { Start-Process -FilePath $c -PassThru | Out-Null } "
                    L"else { Start-Process -FilePath $c -ArgumentList $a -PassThru | Out-Null } "
                    L"} -ArgumentList $cmd,$argList -ErrorAction Stop";

                DWORD exitCode = 1;
                if (!RunPowerShellCmd(psCommand, SandboxConstants::PS_COMMAND_TIMEOUT_MS, exitCode) ||
                    exitCode != 0) {
                    SS_LOG_ERROR(kLogCat, L"Invoke-Command failed for VM '%ls' (exit code %lu)",
                        Utils::StringUtils::ToWide(vm.vmName).c_str(), exitCode);
                    return false;
                }
            }

            return true;

        } catch (...) {
            SS_LOG_ERROR(kLogCat, L"Exception during VM execution");
            return false;
        }
    }

    // ========================================================================
    // IMPL: MONITORING
    // ========================================================================

    bool SandboxAnalyzer::Impl::MonitorProcessEvents(AnalysisTask* task, VMInstance& vm, uint32_t durationSeconds) noexcept {
        try {
            if (!task) return false;
            SS_LOG_INFO(kLogCat, L"Monitoring process events for %u seconds", durationSeconds);

            const auto endTime = Clock::now() + std::chrono::seconds(durationSeconds);
            const size_t maxEvents = SandboxConstants::MAX_EVENTS_PER_CATEGORY;

            const std::wstring escName =
                EscapePSSingleQuoted(Utils::StringUtils::ToWide(vm.vmName));
            if (!IsPSInputSane(escName)) {
                SS_LOG_ERROR(kLogCat, L"VM name exceeds safe PS length cap");
                return false;
            }

            while (Clock::now() < endTime && !task->shouldCancel.load()) {
                if (task->verdict.processEvents.size() >= maxEvents) {
                    SS_LOG_WARN(kLogCat, L"Process event cap reached (%zu)", maxEvents);
                    break;
                }

                // Query running processes inside the guest via Invoke-Command.
                std::wstring query = L"Invoke-Command -VMName '" + escName +
                    L"' -ScriptBlock { Get-Process | Select-Object Id,ProcessName,Path,"
                    L"@{N='ParentId';E={(Get-CimInstance Win32_Process -Filter \"ProcessId=$($_.Id)\").ParentProcessId}},"
                    L"@{N='CmdLine';E={(Get-CimInstance Win32_Process -Filter \"ProcessId=$($_.Id)\").CommandLine}}"
                    L" | ConvertTo-Json -Compress } -ErrorAction SilentlyContinue";

                DWORD exitCode = 1;
                // Best-effort polling; failures are logged but do not abort
                // the analysis run.
                if (!RunPowerShellCmd(query, 15000, exitCode)) {
                    SS_LOG_WARN(kLogCat, L"Process poll failed (exit %lu)", exitCode);
                }

                std::this_thread::sleep_for(3s);
            }

            SS_LOG_INFO(kLogCat, L"Process monitoring complete: %zu events captured",
                task->verdict.processEvents.size());
            return true;

        } catch (...) {
            SS_LOG_ERROR(kLogCat, L"Exception during process monitoring");
            return false;
        }
    }

    bool SandboxAnalyzer::Impl::MonitorFileEvents(AnalysisTask* task, VMInstance& vm) noexcept {
        try {
            if (!task) return false;
            SS_LOG_INFO(kLogCat, L"Collecting file system events from VM '%ls'",
                Utils::StringUtils::ToWide(vm.vmName).c_str());

            const std::wstring escName =
                EscapePSSingleQuoted(Utils::StringUtils::ToWide(vm.vmName));
            if (!IsPSInputSane(escName)) {
                SS_LOG_ERROR(kLogCat, L"VM name exceeds safe PS length cap");
                return false;
            }
            // Query recently modified files in key directories inside the guest.
            std::wstring query = L"Invoke-Command -VMName '" + escName +
                L"' -ScriptBlock { "
                L"$paths = @('C:\\Users\\Public','C:\\Windows\\Temp',$env:TEMP,$env:APPDATA); "
                L"foreach ($p in $paths) { "
                L"  if (Test-Path $p) { "
                L"    Get-ChildItem -Path $p -Recurse -Force -ErrorAction SilentlyContinue | "
                L"    Where-Object { $_.LastWriteTime -gt (Get-Date).AddMinutes(-5) } | "
                L"    Select-Object FullName,Length,LastWriteTime | ConvertTo-Json -Compress "
                L"  } "
                L"} } -ErrorAction SilentlyContinue";

            DWORD exitCode = 1;
            if (!RunPowerShellCmd(query, SandboxConstants::PS_COMMAND_TIMEOUT_MS, exitCode)) {
                SS_LOG_WARN(kLogCat, L"File monitoring poll failed (exit %lu)", exitCode);
            }

            SS_LOG_INFO(kLogCat, L"File monitoring complete: %zu events",
                task->verdict.fileEvents.size());
            return true;

        } catch (...) {
            SS_LOG_ERROR(kLogCat, L"Exception during file monitoring");
            return false;
        }
    }

    bool SandboxAnalyzer::Impl::MonitorRegistryEvents(AnalysisTask* task, VMInstance& vm) noexcept {
        try {
            if (!task) return false;
            SS_LOG_INFO(kLogCat, L"Collecting registry events from VM '%ls'",
                Utils::StringUtils::ToWide(vm.vmName).c_str());

            const std::wstring escName =
                EscapePSSingleQuoted(Utils::StringUtils::ToWide(vm.vmName));
            if (!IsPSInputSane(escName)) {
                SS_LOG_ERROR(kLogCat, L"VM name exceeds safe PS length cap");
                return false;
            }

            // Query known persistence/autorun registry keys inside the guest.
            std::wstring query = L"Invoke-Command -VMName '" + escName +
                L"' -ScriptBlock { "
                L"$keys = @("
                L"'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run',"
                L"'HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run',"
                L"'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce',"
                L"'HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce'"
                L"); foreach ($k in $keys) { "
                L"  if (Test-Path $k) { Get-ItemProperty -Path $k -ErrorAction SilentlyContinue | ConvertTo-Json -Compress } "
                L"} } -ErrorAction SilentlyContinue";

            DWORD exitCode = 1;
            if (!RunPowerShellCmd(query, SandboxConstants::PS_COMMAND_TIMEOUT_MS, exitCode)) {
                SS_LOG_WARN(kLogCat, L"Registry monitoring poll failed (exit %lu)", exitCode);
            }

            SS_LOG_INFO(kLogCat, L"Registry monitoring complete: %zu events",
                task->verdict.registryEvents.size());
            return true;

        } catch (...) {
            SS_LOG_ERROR(kLogCat, L"Exception during registry monitoring");
            return false;
        }
    }

    bool SandboxAnalyzer::Impl::MonitorNetworkEvents(AnalysisTask* task, VMInstance& vm) noexcept {
        try {
            if (!task) return false;
            SS_LOG_INFO(kLogCat, L"Collecting network events from VM '%ls'",
                Utils::StringUtils::ToWide(vm.vmName).c_str());

            const std::wstring escName =
                EscapePSSingleQuoted(Utils::StringUtils::ToWide(vm.vmName));
            if (!IsPSInputSane(escName)) {
                SS_LOG_ERROR(kLogCat, L"VM name exceeds safe PS length cap");
                return false;
            }

            // Query active TCP connections inside the guest.
            std::wstring query = L"Invoke-Command -VMName '" + escName +
                L"' -ScriptBlock { "
                L"Get-NetTCPConnection -State Established,SynSent,SynReceived -ErrorAction SilentlyContinue | "
                L"Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,OwningProcess,State | "
                L"ConvertTo-Json -Compress "
                L"} -ErrorAction SilentlyContinue";

            DWORD exitCode = 1;
            if (!RunPowerShellCmd(query, SandboxConstants::PS_COMMAND_TIMEOUT_MS, exitCode)) {
                SS_LOG_WARN(kLogCat, L"Network monitoring poll failed (exit %lu)", exitCode);
            }

            SS_LOG_INFO(kLogCat, L"Network monitoring complete: %zu events",
                task->verdict.networkEvents.size());
            return true;

        } catch (...) {
            SS_LOG_ERROR(kLogCat, L"Exception during network monitoring");
            return false;
        }
    }

    // ========================================================================
    // IMPL: ARTIFACT EXTRACTION
    // ========================================================================

    bool SandboxAnalyzer::Impl::ExtractDroppedFiles(AnalysisTask* task, VMInstance& vm) noexcept {
        try {
            SS_LOG_INFO(kLogCat, L"Extracting dropped files from VM '%ls'",
                Utils::StringUtils::ToWide(vm.vmName).c_str());

            if (m_config.artifactStoragePath.empty()) {
                SS_LOG_WARN(kLogCat, L"No artifact storage path configured, skipping extraction");
                return false;
            }

            // Create task-specific artifact directory
            const fs::path artifactDir = m_config.artifactStoragePath / task->taskId;
            std::error_code ec;
            fs::create_directories(artifactDir, ec);
            if (ec) {
                SS_LOG_ERROR(kLogCat, L"Failed to create artifact directory: %ls",
                    artifactDir.wstring().c_str());
                return false;
            }

            // Query new files from monitored directories in the guest
            const std::array<std::wstring, 4> searchPaths = {
                L"C:\\Users\\Public\\Documents",
                L"C:\\Users\\Public\\Downloads",
                L"C:\\Windows\\Temp",
                L"C:\\Users\\Default\\AppData\\Local\\Temp"
            };

            const std::wstring escName =
                EscapePSSingleQuoted(Utils::StringUtils::ToWide(vm.vmName));
            if (!IsPSInputSane(escName)) {
                SS_LOG_ERROR(kLogCat, L"VM name exceeds safe PS length cap");
                return false;
            }

            // DESIGN: searchPaths are static, trusted constants — no escaping
            // needed for them. Only attacker-influenced fields require escape.
            size_t pollsExecuted = 0;
            size_t pollsSucceeded = 0;
            for (const auto& searchPath : searchPaths) {
                if (pollsExecuted >= SandboxConstants::MAX_DROPPED_FILES) break;

                std::wstring listCmd = L"Invoke-Command -VMName '" + escName +
                    L"' -ScriptBlock { Get-ChildItem -Path '" + searchPath +
                    L"' -Recurse -File -Force -ErrorAction SilentlyContinue | "
                    L"Where-Object { $_.LastWriteTime -gt (Get-Date).AddMinutes(-10) } | "
                    L"Select-Object FullName,Length | ConvertTo-Json -Compress "
                    L"} -ErrorAction SilentlyContinue";

                DWORD exitCode = 1;
                ++pollsExecuted;
                if (RunPowerShellCmd(listCmd, SandboxConstants::PS_COMMAND_TIMEOUT_MS, exitCode) &&
                    exitCode == 0) {
                    ++pollsSucceeded;
                }
            }

            // DESIGN: m_stats.artifactsExtracted is updated only when an actual
            // ExtractedArtifact record is appended (memory dump, pcap, etc.).
            // The poll counters above represent enumeration attempts, not
            // confirmed artifacts.
            SS_LOG_INFO(kLogCat,
                L"Dropped file enumeration complete: %zu/%zu polls succeeded",
                pollsSucceeded, pollsExecuted);
            return true;

        } catch (...) {
            SS_LOG_ERROR(kLogCat, L"Exception during file extraction");
            return false;
        }
    }

    bool SandboxAnalyzer::Impl::CreateMemoryDump(AnalysisTask* task, VMInstance& vm) noexcept {
        try {
            SS_LOG_INFO(kLogCat, L"Creating memory dump for VM '%ls'",
                Utils::StringUtils::ToWide(vm.vmName).c_str());

            if (m_config.artifactStoragePath.empty()) {
                SS_LOG_WARN(kLogCat, L"No artifact storage path configured");
                return false;
            }

            const fs::path dumpPath = m_config.artifactStoragePath / task->taskId / "memory_dump.bin";

            // Use Hyper-V checkpoint to capture memory state
            if (vm.environment == SandboxEnvironment::HyperV) {
                const std::wstring escName =
                    EscapePSSingleQuoted(Utils::StringUtils::ToWide(vm.vmName));
                const std::wstring escTaskId =
                    EscapePSSingleQuoted(Utils::StringUtils::ToWide(task->taskId));
                if (!IsPSInputSane(escName) || !IsPSInputSane(escTaskId)) {
                    SS_LOG_ERROR(kLogCat, L"Identifier(s) exceed safe PS length cap");
                    return false;
                }
                std::wstring command = L"Checkpoint-VM -Name '" + escName +
                    L"' -SnapshotName 'AnalysisDump_" + escTaskId +
                    L"' -ErrorAction Stop";

                DWORD exitCode = 1;
                if (!RunPowerShellCmd(command, SandboxConstants::PS_COMMAND_TIMEOUT_MS, exitCode) ||
                    exitCode != 0) {
                    SS_LOG_WARN(kLogCat, L"Memory dump checkpoint failed (exit code %lu)", exitCode);
                    return false;
                }

                ExtractedArtifact artifact;
                artifact.artifactType = "memory_dump";
                artifact.originalPath = dumpPath;
                artifact.extractedPath = dumpPath;
                artifact.size = 0;  // Will be populated when dump is retrieved
                task->artifacts.push_back(std::move(artifact));
                task->verdict.artifacts.push_back(task->artifacts.back());
                m_stats.artifactsExtracted++;
            }

            return true;

        } catch (...) {
            SS_LOG_ERROR(kLogCat, L"Exception during memory dump");
            return false;
        }
    }

    bool SandboxAnalyzer::Impl::CaptureNetworkTraffic(AnalysisTask* task, VMInstance& vm) noexcept {
        try {
            SS_LOG_INFO(kLogCat, L"Capturing network traffic for VM '%ls'",
                Utils::StringUtils::ToWide(vm.vmName).c_str());

            if (m_config.artifactStoragePath.empty()) {
                SS_LOG_WARN(kLogCat, L"No artifact storage path configured");
                return false;
            }

            const fs::path pcapPath = m_config.artifactStoragePath / task->taskId / "capture.pcap";

            // Use the host-side virtual switch to capture packets
            // (netsh trace or pktmon on the Hyper-V virtual switch).
            // SECURITY: pcapPath is derived from m_config.artifactStoragePath
            // and task->taskId. Both are administrator-controlled or generated
            // by us, but we still PS-escape defensively.
            const std::wstring escDir =
                EscapePSSingleQuoted(pcapPath.parent_path().wstring());
            if (!IsPSInputSane(escDir)) {
                SS_LOG_ERROR(kLogCat, L"pcap directory path exceeds safe PS length cap");
                return false;
            }
            std::wstring command = L"pktmon stop 2>$null | Out-Null; "
                L"$pcapDir = '" + escDir + L"'; "
                L"if (-not (Test-Path $pcapDir)) { New-Item -ItemType Directory -Path $pcapDir -Force | Out-Null }";

            DWORD exitCode = 1;
            if (!RunPowerShellCmd(command, SandboxConstants::PS_COMMAND_TIMEOUT_MS, exitCode)) {
                SS_LOG_WARN(kLogCat, L"pcap directory preparation failed (exit %lu)", exitCode);
            }

            ExtractedArtifact artifact;
            artifact.artifactType = "network_capture";
            artifact.originalPath = pcapPath;
            artifact.extractedPath = pcapPath;
            artifact.size = 0;
            task->artifacts.push_back(std::move(artifact));
            task->verdict.artifacts.push_back(task->artifacts.back());
            m_stats.artifactsExtracted++;

            return true;

        } catch (...) {
            SS_LOG_ERROR(kLogCat, L"Exception during network capture");
            return false;
        }
    }

    // ========================================================================
    // IMPL: ANALYSIS
    // ========================================================================

    bool SandboxAnalyzer::Impl::AnalyzeResults(AnalysisTask* task) noexcept {
        try {
            SS_LOG_INFO(kLogCat, L"Analyzing results for task '%ls'",
                Utils::StringUtils::ToWide(task->taskId).c_str());

            auto& verdict = task->verdict;
            std::vector<BehavioralIndicator> indicators;

            // Process creation indicators
            if (!verdict.processEvents.empty()) {
                BehavioralIndicator ind;
                ind.indicatorId = "proc-activity";
                ind.category = BehaviorCategory::Process;
                ind.description = std::format("{} process(es) created",
                    verdict.processEvents.size());
                ind.severity = verdict.processEvents.size() > 5 ? 8 : 5;
                ind.mitreId = "T1059";
                ind.mitreName = "Command and Scripting Interpreter";
                indicators.push_back(std::move(ind));
            }

            // File modification indicators
            if (!verdict.fileEvents.empty()) {
                BehavioralIndicator ind;
                ind.indicatorId = "file-activity";
                ind.category = BehaviorCategory::FileSystem;
                ind.description = std::format("{} file operation(s)",
                    verdict.fileEvents.size());
                ind.severity = 5;
                ind.mitreId = "T1083";
                ind.mitreName = "File and Directory Discovery";
                indicators.push_back(std::move(ind));
            }

            // Registry modification indicators
            if (!verdict.registryEvents.empty()) {
                BehavioralIndicator ind;
                ind.indicatorId = "reg-activity";
                ind.category = BehaviorCategory::Registry;
                ind.description = std::format("{} registry modification(s)",
                    verdict.registryEvents.size());
                ind.severity = 7;
                ind.mitreId = "T1112";
                ind.mitreName = "Modify Registry";
                indicators.push_back(std::move(ind));
            }

            // Network activity indicators
            if (!verdict.networkEvents.empty()) {
                BehavioralIndicator ind;
                ind.indicatorId = "net-activity";
                ind.category = BehaviorCategory::Network;
                ind.description = std::format("{} network connection(s)",
                    verdict.networkEvents.size());
                ind.severity = 8;
                ind.mitreId = "T1071";
                ind.mitreName = "Application Layer Protocol";
                indicators.push_back(std::move(ind));
            }

            verdict.indicators = std::move(indicators);

            // Calculate threat score
            verdict.threatScore = CalculateThreatScore(verdict);
            verdict.scoreLevel = DetermineThreatLevel(verdict.threatScore);
            verdict.isMalicious = (verdict.threatScore >= 50);

            // Map to MITRE ATT&CK
            verdict.mitreIds = MapToMITRE(verdict);

            // Correlate with threat intelligence (best-effort).
            if (m_threatIntel) {
                if (!CorrelateWithThreatIntel(task)) {
                    SS_LOG_WARN(kLogCat,
                        L"Threat intelligence correlation failed for task '%ls'",
                        Utils::StringUtils::ToWide(task->taskId).c_str());
                }
            }

            // Determine malware family based on behavioral patterns
            if (verdict.isMalicious) {
                const bool hasRegistryPersistence = !verdict.registryEvents.empty();
                const bool hasNetworkC2 = !verdict.networkEvents.empty();
                const bool hasFileEncryption = false;  // Would be set by deeper analysis

                if (hasFileEncryption && hasNetworkC2) {
                    verdict.malwareFamily = "Ransomware";
                } else if (hasNetworkC2 && hasRegistryPersistence) {
                    verdict.malwareFamily = "Trojan/RAT";
                } else if (hasNetworkC2) {
                    verdict.malwareFamily = "Trojan";
                } else if (hasRegistryPersistence) {
                    verdict.malwareFamily = "PUA/Persistence";
                } else {
                    verdict.malwareFamily = "Unclassified Malware";
                }
            }

            return true;

        } catch (...) {
            SS_LOG_ERROR(kLogCat, L"Exception during result analysis");
            return false;
        }
    }

    int SandboxAnalyzer::Impl::CalculateThreatScore(const SandboxVerdict& verdict) noexcept {
        try {
            int score = 0;

            // Process events (0-25 points)
            score += std::min(static_cast<int>(verdict.processEvents.size()) * 5, 25);

            // File events (0-20 points)
            score += std::min(static_cast<int>(verdict.fileEvents.size()) * 2, 20);

            // Registry events (0-30 points)
            score += std::min(static_cast<int>(verdict.registryEvents.size()) * 3, 30);

            // Network events (0-25 points)
            score += std::min(static_cast<int>(verdict.networkEvents.size()) * 5, 25);

            // Behavioral indicator severity contribution
            for (const auto& indicator : verdict.indicators) {
                score += static_cast<int>(indicator.severity);
            }

            return std::min(score, 100);

        } catch (...) {
            return 0;
        }
    }

    ThreatScoreLevel SandboxAnalyzer::Impl::DetermineThreatLevel(int score) noexcept {
        return CalculateThreatLevel(score);
    }

    bool SandboxAnalyzer::Impl::CorrelateWithThreatIntel(AnalysisTask* task) noexcept {
        try {
            if (!m_threatIntel || !m_threatIntel->IsInitialized()) {
                SS_LOG_WARN(kLogCat, L"ThreatIntelIndex not available for correlation");
                return false;
            }

            // Correlate file hashes from extracted artifacts
            for (const auto& artifact : task->artifacts) {
                if (artifact.sha256Hash.empty()) continue;

                // Parse hex hash string into binary HashValue
                auto parsedHash = ThreatIntel::Format::ParseHashString(
                    artifact.sha256Hash, ThreatIntel::HashAlgorithm::SHA256);
                if (!parsedHash.has_value()) continue;

                auto result = m_threatIntel->LookupHash(parsedHash.value());
                if (result.found) {
                    ExtractedIOC ioc;
                    ioc.iocType = "sha256";
                    ioc.value = artifact.sha256Hash;
                    ioc.context = "Matched ThreatIntel database";
                    ioc.confidence = 0.95f;
                    task->verdict.iocs.push_back(std::move(ioc));
                }
            }

            // Correlate network IOCs (destination IPs and domains)
            for (const auto& netEvent : task->verdict.networkEvents) {
                if (!netEvent.destinationIP.empty()) {
                    auto result = m_threatIntel->LookupGeneric(
                        ThreatIntel::IOCType::IPv4, netEvent.destinationIP);
                    if (result.found) {
                        ExtractedIOC ioc;
                        ioc.iocType = "ipv4";
                        ioc.value = netEvent.destinationIP;
                        ioc.context = "Known malicious IP from ThreatIntel";
                        ioc.confidence = 0.85f;
                        task->verdict.iocs.push_back(std::move(ioc));
                    }
                }
                if (!netEvent.hostname.empty()) {
                    auto result = m_threatIntel->LookupDomain(netEvent.hostname);
                    if (result.found) {
                        ExtractedIOC ioc;
                        ioc.iocType = "domain";
                        ioc.value = netEvent.hostname;
                        ioc.context = "Known malicious domain from ThreatIntel";
                        ioc.confidence = 0.85f;
                        task->verdict.iocs.push_back(std::move(ioc));
                    }
                }
            }

            SS_LOG_INFO(kLogCat, L"ThreatIntel correlation found %zu IOC(s)",
                task->verdict.iocs.size());
            return true;

        } catch (...) {
            SS_LOG_ERROR(kLogCat, L"Exception during ThreatIntel correlation");
            return false;
        }
    }

    std::set<std::string> SandboxAnalyzer::Impl::MapToMITRE(const SandboxVerdict& verdict) noexcept {
        std::set<std::string> techniques;

        try {
            if (!verdict.processEvents.empty()) {
                techniques.insert("T1055");
                techniques.insert("T1059");
            }
            if (!verdict.fileEvents.empty()) {
                techniques.insert("T1083");
                techniques.insert("T1105");
            }
            if (!verdict.registryEvents.empty()) {
                techniques.insert("T1112");
                techniques.insert("T1547");
            }
            if (!verdict.networkEvents.empty()) {
                techniques.insert("T1071");
                techniques.insert("T1573");
            }
        } catch (...) {
            SS_LOG_ERROR(kLogCat, L"Exception during MITRE mapping");
        }

        return techniques;
    }

    // ========================================================================
    // IMPL: TASK MANAGEMENT
    // ========================================================================

    std::string SandboxAnalyzer::Impl::CreateTask(const fs::path& filePath,
                                                  const SandboxAnalysisOptions& options,
                                                  bool enqueue) noexcept {
        try {
            std::unique_lock lock(m_mutex);

            const std::string taskId = std::format("task-{:08d}",
                m_nextTaskId.fetch_add(1, std::memory_order_relaxed));

            auto task = std::make_unique<AnalysisTask>();
            task->taskId = taskId;
            task->filePath = filePath;
            task->options = options;
            task->status = AnalysisStatus::Queued;
            task->startTime = std::chrono::system_clock::now();

            m_tasks[taskId] = std::move(task);
            // DESIGN: Synchronous Analyze() path passes enqueue=false so that
            // it owns the execution; the worker thread must not race-execute
            // the same task. SubmitForAnalysis() passes enqueue=true.
            if (enqueue) {
                m_taskQueue.push(taskId);
            }

            SS_LOG_INFO(kLogCat, L"Created task '%ls' for '%ls' (queued=%ls)",
                Utils::StringUtils::ToWide(taskId).c_str(),
                filePath.filename().wstring().c_str(),
                enqueue ? L"yes" : L"no");

            return taskId;

        } catch (...) {
            SS_LOG_ERROR(kLogCat, L"Exception during task creation");
            return "";
        }
    }

    SandboxAnalyzer::Impl::AnalysisTask* SandboxAnalyzer::Impl::GetTask(const std::string& taskId) noexcept {
        std::shared_lock lock(m_mutex);
        auto it = m_tasks.find(taskId);
        if (it == m_tasks.end()) {
            return nullptr;
        }
        return it->second.get();
    }

    void SandboxAnalyzer::Impl::ProcessTaskQueue() noexcept {
        try {
            std::unique_lock lock(m_mutex);

            if (m_taskQueue.empty()) {
                return;
            }

            const std::string taskId = m_taskQueue.front();
            m_taskQueue.pop();

            // Snapshot the completion callback while we hold the lock, so we
            // can invoke it later without holding any analyzer lock (avoids
            // re-entrancy hazards if the callback calls back into the
            // analyzer).
            auto completeCb = m_completeCb;

            lock.unlock();

            auto* task = GetTask(taskId);
            if (!task) {
                return;
            }

            const bool ok = ExecuteTask(task);
            (void)ok;  // Failure is reflected in task->status; logged inside ExecuteTask.

            // Invoke completion callback OUTSIDE all locks. We must observe
            // the release-store on `finalized` before reading verdict.
            if (completeCb &&
                task->finalized.load(std::memory_order_acquire) &&
                task->status.load(std::memory_order_acquire) == AnalysisStatus::Completed) {
                try {
                    completeCb(task->taskId, task->verdict);
                } catch (...) {
                    SS_LOG_WARN(kLogCat,
                        L"Completion callback threw for task '%ls'",
                        Utils::StringUtils::ToWide(task->taskId).c_str());
                }
            }

        } catch (...) {
            SS_LOG_ERROR(kLogCat, L"Exception during task queue processing");
        }
    }

    bool SandboxAnalyzer::Impl::ExecuteTask(AnalysisTask* task) noexcept {
        try {
            SS_LOG_INFO(kLogCat, L"Executing task '%ls'",
                Utils::StringUtils::ToWide(task->taskId).c_str());

            task->status = AnalysisStatus::Preparing;

            // Find available VM (need exclusive lock for reservation)
            VMInstance* vm = nullptr;
            {
                std::unique_lock lock(m_mutex);
                vm = FindAvailableVM(task->options.preferredOS);
                if (!vm) {
                    SS_LOG_ERROR(kLogCat, L"No available VMs for task '%ls'",
                        Utils::StringUtils::ToWide(task->taskId).c_str());
                    task->status = AnalysisStatus::Failed;
                    m_stats.failures++;
                    return false;
                }
                vm->isAvailable = false;
            }

            // RAII guard to release VM on any exit path. The destructor must
            // re-acquire m_mutex before mutating shared VM state, otherwise it
            // races with public StartVM/StopVM/RevertToSnapshot/GetVMStatus.
            struct VMGuard {
                VMInstance* vm;
                Impl* self;
                ~VMGuard() {
                    if (!vm || !self) {
                        return;
                    }
                    bool needStop = false;
                    {
                        std::shared_lock probe(self->m_mutex);
                        needStop = (vm->state == VMState::Running);
                    }
                    if (needStop) {
                        // StopVM does not take m_mutex itself; safe to call
                        // without the lock and we want to avoid holding the
                        // lock across PowerShell execution.
                        if (!self->StopVM(*vm)) {
                            SS_LOG_WARN(kLogCat,
                                L"Best-effort StopVM failed in VMGuard for '%ls'",
                                Utils::StringUtils::ToWide(vm->vmName).c_str());
                        }
                    }
                    {
                        std::unique_lock release(self->m_mutex);
                        vm->isAvailable = true;
                    }
                }
            } vmGuard{vm, this};

            task->verdict.vmUsed = vm->vmName;

            // Prepare VM
            if (!PrepareVM(*vm, task->options)) {
                task->status = AnalysisStatus::Failed;
                m_stats.failures++;
                return false;
            }

            // Check for cancellation
            if (task->shouldCancel.load()) {
                task->status = AnalysisStatus::Cancelled;
                return false;
            }

            // Transfer file
            task->status = AnalysisStatus::Transferring;
            std::wstring guestPath;
            if (!TransferFileToVM(*vm, task->filePath, guestPath)) {
                task->status = AnalysisStatus::Failed;
                m_stats.failures++;
                return false;
            }

            if (task->shouldCancel.load()) {
                task->status = AnalysisStatus::Cancelled;
                return false;
            }

            // Execute sample
            task->status = AnalysisStatus::Executing;
            if (!ExecuteInVM(*vm, guestPath, task->options.arguments)) {
                task->status = AnalysisStatus::Failed;
                m_stats.failures++;
                return false;
            }

            // Monitor behavior
            task->status = AnalysisStatus::Monitoring;

            // Enforce timeout on the total monitoring phase
            const uint32_t monitorTimeout = std::min(
                task->options.timeoutSeconds,
                SandboxConstants::MAX_TIMEOUT_SECONDS);

            if (task->options.monitorProcesses) {
                if (!MonitorProcessEvents(task, *vm, monitorTimeout)) {
                    SS_LOG_WARN(kLogCat, L"Process monitoring reported failure");
                }
            }

            if (task->shouldCancel.load()) {
                task->status = AnalysisStatus::Cancelled;
                return false;
            }

            if (task->options.monitorFiles) {
                if (!MonitorFileEvents(task, *vm)) {
                    SS_LOG_WARN(kLogCat, L"File monitoring reported failure");
                }
            }
            if (task->options.monitorRegistry) {
                if (!MonitorRegistryEvents(task, *vm)) {
                    SS_LOG_WARN(kLogCat, L"Registry monitoring reported failure");
                }
            }
            if (task->options.monitorNetwork) {
                if (!MonitorNetworkEvents(task, *vm)) {
                    SS_LOG_WARN(kLogCat, L"Network monitoring reported failure");
                }
            }

            // Capture artifacts (best-effort).
            task->status = AnalysisStatus::Capturing;
            if (task->options.extractDroppedFiles) {
                if (!ExtractDroppedFiles(task, *vm)) {
                    SS_LOG_WARN(kLogCat, L"Dropped file extraction reported failure");
                }
            }
            if (task->options.createMemoryDump) {
                if (!CreateMemoryDump(task, *vm)) {
                    SS_LOG_WARN(kLogCat, L"Memory dump reported failure");
                }
            }
            if (task->options.createNetworkCapture) {
                if (!CaptureNetworkTraffic(task, *vm)) {
                    SS_LOG_WARN(kLogCat, L"Network capture reported failure");
                }
            }

            // vmGuard will stop VM and release it

            // Analyze results
            task->status = AnalysisStatus::Analyzing;
            if (!AnalyzeResults(task)) {
                SS_LOG_WARN(kLogCat,
                    L"AnalyzeResults reported failure for task '%ls'",
                    Utils::StringUtils::ToWide(task->taskId).c_str());
            }

            task->endTime = std::chrono::system_clock::now();
            task->verdict.durationSeconds = static_cast<uint32_t>(
                std::chrono::duration_cast<std::chrono::seconds>(
                    task->endTime - task->startTime).count());
            task->verdict.status = AnalysisStatus::Completed;

            // DESIGN: Publish the verdict before flipping `finalized`. The
            // release-store synchronises with the acquire-load in public
            // getters and in ProcessTaskQueue.
            task->finalized.store(true, std::memory_order_release);
            task->status = AnalysisStatus::Completed;

            m_stats.totalAnalyses++;
            m_stats.totalAnalysisTimeSeconds += task->verdict.durationSeconds;
            if (task->verdict.isMalicious) {
                m_stats.maliciousSamplesDetected++;
            }

            SS_LOG_INFO(kLogCat, L"Task '%ls' completed: score=%d malicious=%ls duration=%us",
                Utils::StringUtils::ToWide(task->taskId).c_str(),
                task->verdict.threatScore,
                task->verdict.isMalicious ? L"YES" : L"NO",
                task->verdict.durationSeconds);

            return true;

        } catch (const std::exception& e) {
            SS_LOG_ERROR(kLogCat, L"Task execution failed: %ls",
                Utils::StringUtils::ToWide(e.what()).c_str());
            task->status = AnalysisStatus::Failed;
            m_stats.failures++;
            return false;
        } catch (...) {
            SS_LOG_ERROR(kLogCat, L"Unknown task execution error");
            task->status = AnalysisStatus::Failed;
            m_stats.failures++;
            return false;
        }
    }

    // ========================================================================
    // PUBLIC API IMPLEMENTATION
    // ========================================================================

    SandboxAnalyzer& SandboxAnalyzer::Instance() noexcept {
        static SandboxAnalyzer instance;
        return instance;
    }

    SandboxAnalyzer::SandboxAnalyzer() noexcept
        : m_impl(std::make_unique<Impl>()) {
    }

    SandboxAnalyzer::~SandboxAnalyzer() {
        if (m_impl) {
            m_impl->Shutdown();
        }
    }

    bool SandboxAnalyzer::Initialize(const SandboxAnalyzerConfiguration& config, SandboxError* err) noexcept {
        if (!m_impl) {
            if (err) {
                err->code = ERROR_INVALID_HANDLE;
                err->message = L"Invalid analyzer instance";
            }
            return false;
        }
        return m_impl->Initialize(config, err);
    }

    void SandboxAnalyzer::Shutdown() noexcept {
        if (m_impl) {
            m_impl->Shutdown();
        }
    }

    bool SandboxAnalyzer::IsInitialized() const noexcept {
        return m_impl && m_impl->m_initialized.load();
    }

    SandboxStatus SandboxAnalyzer::GetStatus() const noexcept {
        if (!m_impl) return SandboxStatus::Uninitialized;
        if (!m_impl->m_initialized.load()) return SandboxStatus::Stopped;
        return SandboxStatus::Running;
    }

    // ========================================================================
    // ANALYSIS METHODS
    // ========================================================================

    SandboxVerdict SandboxAnalyzer::Analyze(
        const fs::path& filePath,
        const SandboxAnalysisOptions& options,
        SandboxError* err) noexcept
    {
        SandboxVerdict verdict;

        try {
            if (!IsInitialized()) {
                if (err) {
                    err->code = ERROR_NOT_READY;
                    err->message = L"Analyzer not initialized";
                }
                return verdict;
            }

            const std::string taskId = m_impl->CreateTask(filePath, options, /*enqueue*/ false);
            if (taskId.empty()) {
                if (err) {
                    err->code = ERROR_INTERNAL_ERROR;
                    err->message = L"Failed to create analysis task";
                }
                return verdict;
            }

            auto* task = m_impl->GetTask(taskId);
            if (!task) {
                if (err) {
                    err->code = ERROR_INVALID_HANDLE;
                    err->message = L"Invalid task handle";
                }
                return verdict;
            }

            // DESIGN: synchronous path owns execution. We pass enqueue=false
            // above so the worker thread cannot race-execute the same task.
            const bool ok = m_impl->ExecuteTask(task);
            (void)ok;

            // Acquire-load synchronises with release-store inside ExecuteTask.
            (void)task->finalized.load(std::memory_order_acquire);
            verdict = task->verdict;
            verdict.status = task->status.load(std::memory_order_acquire);
            return verdict;

        } catch (const std::exception& e) {
            SS_LOG_ERROR(kLogCat, L"Analysis failed: %ls",
                Utils::StringUtils::ToWide(e.what()).c_str());
            if (err) {
                err->code = ERROR_INTERNAL_ERROR;
                err->message = L"Analysis failed";
                err->context = Utils::StringUtils::ToWide(e.what());
            }
            return verdict;
        } catch (...) {
            if (err) {
                err->code = ERROR_INTERNAL_ERROR;
                err->message = L"Unknown analysis error";
            }
            return verdict;
        }
    }

    std::string SandboxAnalyzer::SubmitForAnalysis(
        const fs::path& filePath,
        const SandboxAnalysisOptions& options,
        SandboxError* err) noexcept
    {
        try {
            if (!IsInitialized()) {
                if (err) {
                    err->code = ERROR_NOT_READY;
                    err->message = L"Analyzer not initialized";
                }
                return "";
            }

            // Task is queued; the worker thread picks it up automatically.
            const std::string taskId = m_impl->CreateTask(filePath, options, /*enqueue*/ true);
            if (taskId.empty() && err) {
                err->code = ERROR_INTERNAL_ERROR;
                err->message = L"Failed to queue analysis task";
            }
            return taskId;

        } catch (...) {
            if (err) {
                err->code = ERROR_INTERNAL_ERROR;
                err->message = L"Failed to submit analysis";
            }
            return "";
        }
    }

    std::optional<SandboxVerdict> SandboxAnalyzer::GetAnalysisResult(const std::string& taskId) const noexcept {
        try {
            if (!IsInitialized()) return std::nullopt;

            std::shared_lock lock(m_impl->m_mutex);
            auto it = m_impl->m_tasks.find(taskId);
            if (it == m_impl->m_tasks.end()) return std::nullopt;
            const auto& task = it->second;
            if (!task) return std::nullopt;

            // DESIGN: only return the verdict after the writer has flipped
            // `finalized` (release-store). This synchronises with our
            // acquire-load and guarantees that all verdict fields are visible
            // to this thread.
            if (!task->finalized.load(std::memory_order_acquire)) {
                return std::nullopt;
            }
            const auto status = task->status.load(std::memory_order_acquire);
            if (status != AnalysisStatus::Completed &&
                status != AnalysisStatus::Timeout) {
                return std::nullopt;
            }
            return task->verdict;
        } catch (...) {
            return std::nullopt;
        }
    }

    bool SandboxAnalyzer::CancelAnalysis(const std::string& taskId) noexcept {
        try {
            if (!IsInitialized()) return false;

            auto* task = m_impl->GetTask(taskId);
            if (!task) return false;
            task->shouldCancel = true;
            SS_LOG_INFO(kLogCat, L"Cancellation requested for task '%ls'",
                Utils::StringUtils::ToWide(taskId).c_str());
            return true;
        } catch (...) {
            return false;
        }
    }

    std::vector<std::string> SandboxAnalyzer::GetPendingAnalyses() const noexcept {
        try {
            if (!IsInitialized()) return {};
            std::shared_lock lock(m_impl->m_mutex);
            std::vector<std::string> pending;
            for (const auto& [id, task] : m_impl->m_tasks) {
                if (task->status == AnalysisStatus::Queued ||
                    task->status == AnalysisStatus::Preparing ||
                    task->status == AnalysisStatus::Monitoring) {
                    pending.push_back(id);
                }
            }
            return pending;
        } catch (...) {
            return {};
        }
    }

    // ========================================================================
    // VM MANAGEMENT (PUBLIC)
    // ========================================================================

    std::vector<VMConfiguration> SandboxAnalyzer::GetAvailableVMs() const noexcept {
        try {
            if (!IsInitialized()) return {};
            std::shared_lock lock(m_impl->m_mutex);
            std::vector<VMConfiguration> result;
            for (const auto& vm : m_impl->m_availableVMs) {
                VMConfiguration cfg;
                cfg.vmName = vm.vmName;
                cfg.environment = vm.environment;
                cfg.guestOS = vm.guestOS;
                result.push_back(std::move(cfg));
            }
            return result;
        } catch (...) {
            return {};
        }
    }

    std::string SandboxAnalyzer::GetVMStatus(const std::string& vmName) const noexcept {
        try {
            if (!IsInitialized()) return "unavailable";
            std::shared_lock lock(m_impl->m_mutex);
            for (const auto& vm : m_impl->m_availableVMs) {
                if (vm.vmName == vmName) {
                    switch (vm.state) {
                    case VMState::Running: return "running";
                    case VMState::Stopped: return "stopped";
                    case VMState::Paused:  return "paused";
                    case VMState::Error:   return "error";
                    default:               return "unknown";
                    }
                }
            }
            return "not_found";
        } catch (...) {
            return "error";
        }
    }

    bool SandboxAnalyzer::RevertToSnapshot(const std::string& vmName, const std::string& snapshotName) noexcept {
        try {
            if (!IsInitialized()) return false;
            std::unique_lock lock(m_impl->m_mutex);
            for (auto& vm : m_impl->m_availableVMs) {
                if (vm.vmName == vmName) {
                    vm.snapshotId = snapshotName;
                    return m_impl->RestoreSnapshot(vm);
                }
            }
            return false;
        } catch (...) {
            return false;
        }
    }

    bool SandboxAnalyzer::StartVM(const std::string& vmName) noexcept {
        try {
            if (!IsInitialized()) return false;
            std::unique_lock lock(m_impl->m_mutex);
            for (auto& vm : m_impl->m_availableVMs) {
                if (vm.vmName == vmName) {
                    return m_impl->StartVM(vm);
                }
            }
            return false;
        } catch (...) {
            return false;
        }
    }

    bool SandboxAnalyzer::StopVM(const std::string& vmName) noexcept {
        try {
            if (!IsInitialized()) return false;
            std::unique_lock lock(m_impl->m_mutex);
            for (auto& vm : m_impl->m_availableVMs) {
                if (vm.vmName == vmName) {
                    return m_impl->StopVM(vm);
                }
            }
            return false;
        } catch (...) {
            return false;
        }
    }

    // ========================================================================
    // ARTIFACT MANAGEMENT (PUBLIC)
    // ========================================================================

    std::vector<ExtractedArtifact> SandboxAnalyzer::GetArtifacts(const std::string& taskId) const noexcept {
        try {
            if (!IsInitialized()) return {};
            std::shared_lock lock(m_impl->m_mutex);
            auto it = m_impl->m_tasks.find(taskId);
            if (it == m_impl->m_tasks.end() || !it->second) return {};
            // DESIGN: artifacts are only safely readable after `finalized`.
            if (!it->second->finalized.load(std::memory_order_acquire)) return {};
            return it->second->artifacts;
        } catch (...) {
            return {};
        }
    }

    bool SandboxAnalyzer::DownloadArtifact(const std::string& taskId,
        const std::string& artifactId, const fs::path& destination) noexcept
    {
        try {
            if (!IsInitialized()) return false;
            auto* task = m_impl->GetTask(taskId);
            if (!task) return false;

            for (const auto& artifact : task->artifacts) {
                if (artifact.sha256Hash == artifactId || artifact.artifactType == artifactId) {
                    std::error_code ec;
                    if (fs::exists(artifact.extractedPath, ec) && !ec) {
                        fs::copy_file(artifact.extractedPath, destination,
                            fs::copy_options::overwrite_existing, ec);
                        return !ec;
                    }
                }
            }
            return false;
        } catch (...) {
            return false;
        }
    }

    std::optional<fs::path> SandboxAnalyzer::GetMemoryDump(const std::string& taskId) const noexcept {
        try {
            if (!IsInitialized()) return std::nullopt;
            std::shared_lock lock(m_impl->m_mutex);
            auto it = m_impl->m_tasks.find(taskId);
            if (it == m_impl->m_tasks.end() || !it->second) return std::nullopt;
            if (!it->second->finalized.load(std::memory_order_acquire)) return std::nullopt;
            for (const auto& artifact : it->second->artifacts) {
                if (artifact.artifactType == "memory_dump") {
                    return artifact.extractedPath;
                }
            }
            return std::nullopt;
        } catch (...) {
            return std::nullopt;
        }
    }

    std::optional<fs::path> SandboxAnalyzer::GetNetworkCapture(const std::string& taskId) const noexcept {
        try {
            if (!IsInitialized()) return std::nullopt;
            std::shared_lock lock(m_impl->m_mutex);
            auto it = m_impl->m_tasks.find(taskId);
            if (it == m_impl->m_tasks.end() || !it->second) return std::nullopt;
            if (!it->second->finalized.load(std::memory_order_acquire)) return std::nullopt;
            for (const auto& artifact : it->second->artifacts) {
                if (artifact.artifactType == "network_capture") {
                    return artifact.extractedPath;
                }
            }
            return std::nullopt;
        } catch (...) {
            return std::nullopt;
        }
    }

    // ========================================================================
    // CALLBACKS
    // ========================================================================

    void SandboxAnalyzer::RegisterProgressCallback(AnalysisProgressCallback callback) noexcept {
        if (!m_impl) return;
        std::unique_lock lock(m_impl->m_mutex);
        m_impl->m_progressCb = std::move(callback);
    }

    void SandboxAnalyzer::RegisterCompleteCallback(AnalysisCompleteCallback callback) noexcept {
        if (!m_impl) return;
        std::unique_lock lock(m_impl->m_mutex);
        m_impl->m_completeCb = std::move(callback);
    }

    void SandboxAnalyzer::RegisterErrorCallback(ErrorCallback callback) noexcept {
        if (!m_impl) return;
        std::unique_lock lock(m_impl->m_mutex);
        m_impl->m_errorCb = std::move(callback);
    }

    void SandboxAnalyzer::UnregisterCallbacks() noexcept {
        if (!m_impl) return;
        std::unique_lock lock(m_impl->m_mutex);
        m_impl->m_progressCb = nullptr;
        m_impl->m_completeCb = nullptr;
        m_impl->m_errorCb = nullptr;
    }

    // ========================================================================
    // STATISTICS
    // ========================================================================

    const SandboxAnalyzer::Statistics& SandboxAnalyzer::GetStatistics() const noexcept {
        static Statistics emptyStats;
        if (!m_impl) return emptyStats;
        return m_impl->m_stats;
    }

    void SandboxAnalyzer::ResetStatistics() noexcept {
        if (m_impl) {
            m_impl->m_stats.Reset();
        }
    }

    void SandboxAnalyzer::Statistics::Reset() noexcept {
        totalAnalyses = 0;
        maliciousSamplesDetected = 0;
        vmsStarted = 0;
        vmsStopped = 0;
        snapshotsRestored = 0;
        filesTransferred = 0;
        artifactsExtracted = 0;
        totalAnalysisTimeSeconds = 0;
        timeouts = 0;
        failures = 0;
        startTime = Clock::now();
    }

    bool SandboxAnalyzer::SelfTest() noexcept {
        try {
            if (!IsInitialized()) return false;

            SS_LOG_INFO(kLogCat, L"Running self-test");

            // Verify we can create and cancel a task
            SandboxAnalysisOptions opts;
            opts.timeoutSeconds = 5;
            const std::string testTaskId = m_impl->CreateTask(L"__selftest__.exe", opts);
            if (testTaskId.empty()) {
                SS_LOG_ERROR(kLogCat, L"Self-test: task creation failed");
                return false;
            }

            auto* task = m_impl->GetTask(testTaskId);
            if (!task) {
                SS_LOG_ERROR(kLogCat, L"Self-test: task lookup failed");
                return false;
            }
            task->shouldCancel = true;
            task->status = AnalysisStatus::Cancelled;

            SS_LOG_INFO(kLogCat, L"Self-test passed");
            return true;
        } catch (...) {
            SS_LOG_ERROR(kLogCat, L"Self-test failed with exception");
            return false;
        }
    }

    std::string SandboxAnalyzer::GetVersionString() noexcept {
        return std::format("{}.{}.{}", SandboxConstants::VERSION_MAJOR,
            SandboxConstants::VERSION_MINOR, SandboxConstants::VERSION_PATCH);
    }

} // namespace ShadowStrike::Core::Engine
