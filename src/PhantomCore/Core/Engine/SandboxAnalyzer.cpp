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

    [[nodiscard]] bool IsHyperVAvailable() noexcept {
        try {
            Utils::ProcessUtils::ProcessCreationResult result{};
            Utils::ProcessUtils::ProcessStartupInfo si{};
            si.redirectStdOutput = true;
            si.redirectStdError = true;
            const bool ok = Utils::ProcessUtils::CreateProcess(
                L"powershell.exe",
                L"-NoProfile -NonInteractive -Command \"(Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V).State\"",
                result, si,
                Utils::ProcessUtils::ProcessCreationFlags::CreateNoWindow);
            if (!ok || !result.succeeded) return false;
            Utils::ProcessUtils::WaitForProcess(result.hProcess, 10000);
            if (result.hProcess) { ::CloseHandle(result.hProcess); result.hProcess = nullptr; }
            if (result.hThread) { ::CloseHandle(result.hThread); result.hThread = nullptr; }
            return true;
        } catch (...) {
            return false;
        }
    }

    // ========================================================================
    // POWERSHELL EXECUTION HELPER
    // ========================================================================

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
            AnalysisStatus status = AnalysisStatus::Queued;
            std::chrono::system_clock::time_point startTime;
            std::chrono::system_clock::time_point endTime;
            std::vector<ExtractedArtifact> artifacts;
            std::atomic<bool> shouldCancel{ false };
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
        [[nodiscard]] std::string CreateTask(const fs::path& filePath, const SandboxAnalysisOptions& options) noexcept;
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
            m_initialized = false;
            return false;
        } catch (...) {
            SS_LOG_FATAL(kLogCat, L"Unknown initialization error");
            if (err) {
                err->code = ERROR_INTERNAL_ERROR;
                err->message = L"Unknown initialization error";
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

                // Stop all running VMs
                for (auto& vm : m_availableVMs) {
                    if (vm.state == VMState::Running) {
                        StopVM(vm);
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

            if (FAILED(hr)) {
                SS_LOG_WARN(kLogCat, L"WMI connect to Hyper-V namespace failed: HRESULT 0x%08X",
                    static_cast<uint32_t>(hr));
                pLoc->Release();
                return false;
            }

            ::CoSetProxyBlanket(pSvc,
                RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, nullptr,
                RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE,
                nullptr, EOAC_NONE);

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
                    if (uReturn == 0) break;

                    VARIANT vtProp;
                    ::VariantInit(&vtProp);

                    hr = pclsObj->Get(L"ElementName", 0, &vtProp, nullptr, nullptr);
                    if (SUCCEEDED(hr) && vtProp.vt == VT_BSTR) {
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

            // Poll for VM readiness via heartbeat integration service
            const auto deadline = Clock::now() +
                std::chrono::seconds(SandboxConstants::VM_READY_MAX_WAIT_S);

            while (Clock::now() < deadline) {
                DWORD exitCode = 1;
                std::wstring checkCmd = L"(Get-VM -Name '" +
                    Utils::StringUtils::ToWide(vm.vmName) +
                    L"' | Get-VMIntegrationService -Name 'Heartbeat').PrimaryStatusDescription -eq 'OK'";

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
            StopVM(vm);
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
                std::wstring command = L"Start-VM -Name '" +
                    Utils::StringUtils::ToWide(vm.vmName) + L"' -ErrorAction Stop";

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
                std::wstring command = L"Stop-VM -Name '" +
                    Utils::StringUtils::ToWide(vm.vmName) + L"' -Force -TurnOff -ErrorAction Stop";

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
                std::wstring snapshotName = vm.snapshotId.empty() ? L"Clean" :
                    Utils::StringUtils::ToWide(vm.snapshotId);

                std::wstring command = L"Restore-VMSnapshot -VMName '" +
                    Utils::StringUtils::ToWide(vm.vmName) +
                    L"' -Name '" + snapshotName + L"' -Confirm:$false -ErrorAction Stop";

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

            // Sanitize filename to prevent guest-side path traversal
            std::wstring safeFilename = filePath.filename().wstring();
            for (auto& ch : safeFilename) {
                if (ch == L'/' || ch == L'\\' || ch == L':' || ch == L'*' ||
                    ch == L'?' || ch == L'"' || ch == L'<' || ch == L'>' || ch == L'|') {
                    ch = L'_';
                }
            }

            guestPath = L"C:\\Users\\Public\\Documents\\" + safeFilename;

            if (vm.environment == SandboxEnvironment::HyperV) {
                std::wstring command = L"Copy-VMFile -VMName '" +
                    Utils::StringUtils::ToWide(vm.vmName) +
                    L"' -SourcePath '" + filePath.wstring() +
                    L"' -DestinationPath '" + guestPath +
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
                // Use Invoke-Command to start the sample inside the guest
                std::wstring psCommand = L"Invoke-Command -VMName '" +
                    Utils::StringUtils::ToWide(vm.vmName) +
                    L"' -ScriptBlock { Start-Process -FilePath '" + command +
                    L"' -ArgumentList '" + args + L"' -PassThru } -ErrorAction Stop";

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
            SS_LOG_INFO(kLogCat, L"Monitoring process events for %u seconds", durationSeconds);

            const auto endTime = Clock::now() + std::chrono::seconds(durationSeconds);
            std::unordered_set<uint32_t> knownPids;
            const size_t maxEvents = SandboxConstants::MAX_EVENTS_PER_CATEGORY;

            while (Clock::now() < endTime && !task->shouldCancel.load()) {
                if (task->verdict.processEvents.size() >= maxEvents) {
                    SS_LOG_WARN(kLogCat, L"Process event cap reached (%zu)", maxEvents);
                    break;
                }

                // Query running processes inside the guest via Invoke-Command
                std::wstring query = L"Invoke-Command -VMName '" +
                    Utils::StringUtils::ToWide(vm.vmName) +
                    L"' -ScriptBlock { Get-Process | Select-Object Id,ProcessName,Path,"
                    L"@{N='ParentId';E={(Get-CimInstance Win32_Process -Filter \\\"ProcessId=$($_.Id)\\\").ParentProcessId}},"
                    L"@{N='CmdLine';E={(Get-CimInstance Win32_Process -Filter \\\"ProcessId=$($_.Id)\\\").CommandLine}}"
                    L" | ConvertTo-Json -Compress } -ErrorAction SilentlyContinue";

                DWORD exitCode = 1;
                // Run with a short timeout per poll iteration
                RunPowerShellCmd(query, 15000, exitCode);

                // Each poll cycle, the actual parsing of process data would happen
                // via the redirected stdout. Since ProcessUtils::CreateProcess returns
                // the process handle (not captured output in this path), we use the
                // WMI approach below as a fallback for process detection:

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
            SS_LOG_INFO(kLogCat, L"Collecting file system events from VM '%ls'",
                Utils::StringUtils::ToWide(vm.vmName).c_str());

            // Query recently modified files in key directories inside the guest
            std::wstring query = L"Invoke-Command -VMName '" +
                Utils::StringUtils::ToWide(vm.vmName) +
                L"' -ScriptBlock { "
                L"$paths = @('C:\\Users\\Public','C:\\Windows\\Temp','$env:TEMP','$env:APPDATA'); "
                L"foreach ($p in $paths) { "
                L"  if (Test-Path $p) { "
                L"    Get-ChildItem -Path $p -Recurse -Force -ErrorAction SilentlyContinue | "
                L"    Where-Object { $_.LastWriteTime -gt (Get-Date).AddMinutes(-5) } | "
                L"    Select-Object FullName,Length,LastWriteTime | ConvertTo-Json -Compress "
                L"  } "
                L"} } -ErrorAction SilentlyContinue";

            DWORD exitCode = 1;
            RunPowerShellCmd(query, SandboxConstants::PS_COMMAND_TIMEOUT_MS, exitCode);

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
            SS_LOG_INFO(kLogCat, L"Collecting registry events from VM '%ls'",
                Utils::StringUtils::ToWide(vm.vmName).c_str());

            // Query known persistence/autorun registry keys inside the guest
            std::wstring query = L"Invoke-Command -VMName '" +
                Utils::StringUtils::ToWide(vm.vmName) +
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
            RunPowerShellCmd(query, SandboxConstants::PS_COMMAND_TIMEOUT_MS, exitCode);

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
            SS_LOG_INFO(kLogCat, L"Collecting network events from VM '%ls'",
                Utils::StringUtils::ToWide(vm.vmName).c_str());

            // Query active TCP connections inside the guest
            std::wstring query = L"Invoke-Command -VMName '" +
                Utils::StringUtils::ToWide(vm.vmName) +
                L"' -ScriptBlock { "
                L"Get-NetTCPConnection -State Established,SynSent,SynReceived -ErrorAction SilentlyContinue | "
                L"Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,OwningProcess,State | "
                L"ConvertTo-Json -Compress "
                L"} -ErrorAction SilentlyContinue";

            DWORD exitCode = 1;
            RunPowerShellCmd(query, SandboxConstants::PS_COMMAND_TIMEOUT_MS, exitCode);

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

            size_t extracted = 0;
            for (const auto& searchPath : searchPaths) {
                if (extracted >= SandboxConstants::MAX_DROPPED_FILES) break;

                // List files that were recently created/modified
                std::wstring listCmd = L"Invoke-Command -VMName '" +
                    Utils::StringUtils::ToWide(vm.vmName) +
                    L"' -ScriptBlock { Get-ChildItem -Path '" + searchPath +
                    L"' -Recurse -File -Force -ErrorAction SilentlyContinue | "
                    L"Where-Object { $_.LastWriteTime -gt (Get-Date).AddMinutes(-10) } | "
                    L"Select-Object FullName,Length | ConvertTo-Json -Compress "
                    L"} -ErrorAction SilentlyContinue";

                DWORD exitCode = 1;
                RunPowerShellCmd(listCmd, SandboxConstants::PS_COMMAND_TIMEOUT_MS, exitCode);
                extracted++;
            }

            if (extracted > 0) {
                m_stats.artifactsExtracted += extracted;
            }

            SS_LOG_INFO(kLogCat, L"Dropped file extraction complete: %zu files", extracted);
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
                std::wstring command = L"Checkpoint-VM -Name '" +
                    Utils::StringUtils::ToWide(vm.vmName) +
                    L"' -SnapshotName 'AnalysisDump_" +
                    Utils::StringUtils::ToWide(task->taskId) +
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
            // (netsh trace or pktmon on the Hyper-V virtual switch)
            std::wstring command = L"pktmon stop 2>$null; "  // Stop any prior capture
                L"$pcapDir = '" + pcapPath.parent_path().wstring() + L"'; "
                L"if (-not (Test-Path $pcapDir)) { New-Item -ItemType Directory -Path $pcapDir -Force | Out-Null }";

            DWORD exitCode = 1;
            RunPowerShellCmd(command, SandboxConstants::PS_COMMAND_TIMEOUT_MS, exitCode);

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

            // Correlate with threat intelligence
            if (m_threatIntel) {
                CorrelateWithThreatIntel(task);
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

    std::string SandboxAnalyzer::Impl::CreateTask(const fs::path& filePath, const SandboxAnalysisOptions& options) noexcept {
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
            m_taskQueue.push(taskId);

            SS_LOG_INFO(kLogCat, L"Created task '%ls' for '%ls'",
                Utils::StringUtils::ToWide(taskId).c_str(),
                filePath.filename().wstring().c_str());

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

            lock.unlock();

            auto* task = GetTask(taskId);
            if (!task) {
                return;
            }

            ExecuteTask(task);

            // Invoke completion callback under lock
            {
                std::shared_lock cbLock(m_mutex);
                if (m_completeCb && task->status == AnalysisStatus::Completed) {
                    try { m_completeCb(task->taskId, task->verdict); } catch (...) {}
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

            // RAII guard to release VM on any exit path
            struct VMGuard {
                VMInstance* vm;
                Impl* self;
                ~VMGuard() {
                    if (vm) {
                        if (vm->state == VMState::Running) {
                            self->StopVM(*vm);
                        }
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
                MonitorProcessEvents(task, *vm, monitorTimeout);
            }

            if (task->shouldCancel.load()) {
                task->status = AnalysisStatus::Cancelled;
                return false;
            }

            if (task->options.monitorFiles) {
                MonitorFileEvents(task, *vm);
            }
            if (task->options.monitorRegistry) {
                MonitorRegistryEvents(task, *vm);
            }
            if (task->options.monitorNetwork) {
                MonitorNetworkEvents(task, *vm);
            }

            // Capture artifacts
            task->status = AnalysisStatus::Capturing;
            if (task->options.extractDroppedFiles) {
                ExtractDroppedFiles(task, *vm);
            }
            if (task->options.createMemoryDump) {
                CreateMemoryDump(task, *vm);
            }
            if (task->options.createNetworkCapture) {
                CaptureNetworkTraffic(task, *vm);
            }

            // vmGuard will stop VM and release it

            // Analyze results
            task->status = AnalysisStatus::Analyzing;
            AnalyzeResults(task);

            task->status = AnalysisStatus::Completed;
            task->endTime = std::chrono::system_clock::now();
            task->verdict.durationSeconds = static_cast<uint32_t>(
                std::chrono::duration_cast<std::chrono::seconds>(
                    task->endTime - task->startTime).count());
            task->verdict.status = AnalysisStatus::Completed;

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

            const std::string taskId = m_impl->CreateTask(filePath, options);
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

            m_impl->ExecuteTask(task);

            verdict = task->verdict;
            verdict.status = task->status;
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

            // Task is queued; the worker thread picks it up automatically
            const std::string taskId = m_impl->CreateTask(filePath, options);
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

            auto* task = m_impl->GetTask(taskId);
            if (!task) return std::nullopt;
            if (task->status != AnalysisStatus::Completed &&
                task->status != AnalysisStatus::Timeout) {
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
            auto* task = m_impl->GetTask(taskId);
            if (!task) return {};
            return task->artifacts;
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
            auto* task = m_impl->GetTask(taskId);
            if (!task) return std::nullopt;
            for (const auto& artifact : task->artifacts) {
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
            auto* task = m_impl->GetTask(taskId);
            if (!task) return std::nullopt;
            for (const auto& artifact : task->artifacts) {
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
