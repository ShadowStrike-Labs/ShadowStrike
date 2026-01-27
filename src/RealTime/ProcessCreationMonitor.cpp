/**
 * ============================================================================
 * ShadowStrike Real-Time - PROCESS CREATION MONITOR IMPLEMENTATION
 * ============================================================================
 *
 * @file ProcessCreationMonitor.cpp
 * @brief Implementation of the Process Creation Monitor (The Overseer)
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @copyright (c) 2026 ShadowStrike Security Suite. All rights reserved.
 *
 * LICENSE: Proprietary - ShadowStrike Enterprise License
 * ============================================================================
 */

#include "pch.h"
#include "ProcessCreationMonitor.hpp"
#include "../Utils/Logger.hpp"
#include "../Utils/SystemUtils.hpp"
#include "../Utils/CryptoUtils.hpp"
#include "../Core/Engine/ScanEngine.hpp"
#include "../Core/Engine/ThreatDetector.hpp"
#include "../Core/Engine/BehaviorAnalyzer.hpp"

#include <algorithm>
#include <regex>
#include <sstream>
#include <thread>
#include <future>

namespace ShadowStrike {
namespace RealTime {

// ============================================================================
// STATIC MEMBER INITIALIZATION
// ============================================================================

// Singleton instance is static local in Instance() method in C++11+,
// but we follow the pattern if needed.
// Using Meyer's Singleton as per CLAUDE.md, so no static member init needed here for instance.

// ============================================================================
// INTERNAL HELPERS
// ============================================================================

namespace {

    /// @brief Generate a unique process ID key (PID + CreationTime) to handle PID reuse
    std::string GenerateProcessKey(uint32_t pid, const std::chrono::system_clock::time_point& creationTime) {
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(creationTime.time_since_epoch()).count();
        return std::to_string(pid) + "_" + std::to_string(ms);
    }

    /// @brief Check if string contains another string (case insensitive)
    bool ContainsCaseInsensitive(std::wstring_view str, std::wstring_view sub) {
        auto it = std::search(
            str.begin(), str.end(),
            sub.begin(), sub.end(),
            [](wchar_t ch1, wchar_t ch2) {
                return std::towlower(ch1) == std::towlower(ch2);
            }
        );
        return it != str.end();
    }

    /// @brief Convert suspicious pattern to string
    std::string SuspiciousPatternToString(SuspiciousPattern pattern) {
        switch (pattern) {
            case SuspiciousPattern::OfficeSpawnsScript: return "OfficeSpawnsScript";
            case SuspiciousPattern::OfficeSpawnsShell: return "OfficeSpawnsShell";
            case SuspiciousPattern::BrowserSpawnsExe: return "BrowserSpawnsExe";
            case SuspiciousPattern::ServicesSpawnsShell: return "ServicesSpawnsShell";
            case SuspiciousPattern::SvchostSpawnsUnexpected: return "SvchostSpawnsUnexpected";
            case SuspiciousPattern::WmiSpawnsProcess: return "WmiSpawnsProcess";
            case SuspiciousPattern::ScriptSpawnsExe: return "ScriptSpawnsExe";
            case SuspiciousPattern::MshtaSpawnsProcess: return "MshtaSpawnsProcess";
            case SuspiciousPattern::EncodedPowerShell: return "EncodedPowerShell";
            case SuspiciousPattern::ObfuscatedCmdLine: return "ObfuscatedCmdLine";
            case SuspiciousPattern::DownloadCommand: return "DownloadCommand";
            case SuspiciousPattern::BypassExecutionPolicy: return "BypassExecutionPolicy";
            case SuspiciousPattern::HiddenWindowExecution: return "HiddenWindowExecution";
            case SuspiciousPattern::ReflectionLoad: return "ReflectionLoad";
            case SuspiciousPattern::COMScripting: return "COMScripting";
            case SuspiciousPattern::ScheduledTaskCreation: return "ScheduledTaskCreation";
            case SuspiciousPattern::ServiceCreation: return "ServiceCreation";
            case SuspiciousPattern::RegistryModification: return "RegistryModification";
            case SuspiciousPattern::TempFolderExecution: return "TempFolderExecution";
            case SuspiciousPattern::DownloadsFolderExecution: return "DownloadsFolderExecution";
            case SuspiciousPattern::UserProfileExecution: return "UserProfileExecution";
            case SuspiciousPattern::RecycleBinExecution: return "RecycleBinExecution";
            case SuspiciousPattern::NetworkShareExecution: return "NetworkShareExecution";
            case SuspiciousPattern::ArchiveExecution: return "ArchiveExecution";
            case SuspiciousPattern::DoubleExtension: return "DoubleExtension";
            case SuspiciousPattern::ProcessMasquerading: return "ProcessMasquerading";
            case SuspiciousPattern::ProcessHollowing: return "ProcessHollowing";
            case SuspiciousPattern::ProcessDoppelgang: return "ProcessDoppelgang";
            case SuspiciousPattern::ProcessHerpadering: return "ProcessHerpadering";
            case SuspiciousPattern::ProcessGhosting: return "ProcessGhosting";
            default: return "Unknown";
        }
    }

} // anonymous namespace

// ============================================================================
// PIMPL IMPLEMENTATION CLASS
// ============================================================================

struct ProcessCreationMonitor::Impl {
    // -------------------------------------------------------------------------
    // Members
    // -------------------------------------------------------------------------

    // Configuration & State
    ProcessMonitorConfig config;
    ProcessMonitorStats stats;
    std::atomic<bool> isRunning{false};
    std::atomic<bool> isInitialized{false};

    // Resources
    std::shared_ptr<Utils::ThreadPool> threadPool;

    // Data Storage
    mutable std::shared_mutex processMutex;
    std::unordered_map<uint32_t, ProcessInfo> activeProcesses;
    std::unordered_map<uint32_t, ProcessTreeNode> processTree;

    // Rules
    mutable std::shared_mutex rulesMutex;
    std::vector<ProcessPolicyRule> rules;

    // External Integrations
    Core::Engine::ScanEngine* scanEngine = nullptr;
    Core::Engine::ThreatDetector* threatDetector = nullptr;
    Core::Engine::BehaviorAnalyzer* behaviorAnalyzer = nullptr;
    Whitelist::WhitelistStore* whitelistStore = nullptr;
    HashStore::HashStore* hashStore = nullptr;
    ThreatIntel::ThreatIntelIndex* threatIntelIndex = nullptr;

    // Callbacks
    mutable std::shared_mutex callbacksMutex;
    std::map<uint64_t, ProcessCreateCallback> createCallbacks;
    std::map<uint64_t, ProcessTerminateCallback> terminateCallbacks;
    std::map<uint64_t, SuspiciousProcessCallback> suspiciousCallbacks;
    std::atomic<uint64_t> nextCallbackId{1};

    // -------------------------------------------------------------------------
    // Implementation Methods
    // -------------------------------------------------------------------------

    Impl() {
        stats.Reset();
    }

    bool Initialize(std::shared_ptr<Utils::ThreadPool> tp, const ProcessMonitorConfig& cfg) {
        if (isInitialized) return false;

        threadPool = tp;
        config = cfg;

        // Load default rules if none exist
        // In a real implementation, we would load from disk/DB

        isInitialized = true;
        Utils::Logger::Info("ProcessCreationMonitor initialized");
        return true;
    }

    void Shutdown() {
        if (!isInitialized) return;
        Stop();

        {
            std::unique_lock lock(processMutex);
            activeProcesses.clear();
            processTree.clear();
        }

        isInitialized = false;
        Utils::Logger::Info("ProcessCreationMonitor shutdown");
    }

    void Start() {
        if (!isInitialized || isRunning) return;

        // In a real implementation, this would register with the kernel driver
        // via FilterSendMessage or IOCTL

        isRunning = true;
        Utils::Logger::Info("ProcessCreationMonitor started");
    }

    void Stop() {
        if (!isRunning) return;

        // Unregister from kernel driver

        isRunning = false;
        Utils::Logger::Info("ProcessCreationMonitor stopped");
    }

    // -------------------------------------------------------------------------
    // Core Logic
    // -------------------------------------------------------------------------

    ProcessVerdict HandleProcessCreate(const ProcessCreateEvent& event) {
        stats.totalProcessCreations++;
        auto startTime = std::chrono::high_resolution_clock::now();

        // 1. Basic Allow/Block based on config
        if (!config.enabled) {
            stats.processesAllowed++;
            return ProcessVerdict::Allow;
        }

        // 2. Check Whitelist
        if (config.trustWhitelisted && whitelistStore) {
            if (whitelistStore->IsWhitelisted(event.imagePath)) {
                // Still update tree, but skip heavy scanning
                UpdateProcessState(event, ProcessVerdict::Allow);
                stats.processesAllowed++;
                return ProcessVerdict::Allow;
            }
        }

        // 3. Hash Check
        if (config.blockKnownMalicious && hashStore) {
            if (hashStore->IsKnownMalware(event.imageHash)) {
                stats.processesBlocked++;
                // Log and alert
                return ProcessVerdict::Block;
            }
        }

        // 4. Command Line Analysis
        CommandLineAnalysis cmdAnalysis;
        if (config.analyzeCommandLine) {
            cmdAnalysis = AnalyzeCommandLine(event.commandLine);
        }

        // 5. Rule Evaluation
        auto ruleVerdict = EvaluateRules(event, cmdAnalysis);
        if (ruleVerdict.has_value()) {
            if (*ruleVerdict == ProcessVerdict::Block) {
                stats.processesBlocked++;
                return ProcessVerdict::Block;
            }
        }

        // 6. Pre-Execution Scan (if enabled and not trusted)
        ProcessVerdict scanVerdict = ProcessVerdict::Allow;
        if (config.preExecutionScan && scanEngine) {
            // Check if we should scan (e.g. not Microsoft signed if trusted)
            bool shouldScan = true;
            if (config.trustMicrosoftSigned && event.isImageSigned && event.imageSigner.find(L"Microsoft") != std::string::npos) {
                shouldScan = false;
            }

            if (shouldScan) {
                scanVerdict = PerformScan(event);
                if (scanVerdict == ProcessVerdict::Block) {
                    stats.processesBlocked++;
                    return ProcessVerdict::Block;
                }
            }
        }

        // 7. Behavioral/Heuristic Checks (Parent-Child, LOLBAS)
        std::vector<SuspiciousPattern> patterns;
        double riskScore = CalculateRiskScore(event, cmdAnalysis, patterns);

        ProcessVerdict finalVerdict = ProcessVerdict::Allow;

        if (riskScore >= config.blockThreshold) {
            finalVerdict = ProcessVerdict::Block;
            stats.processesBlocked++;
        } else if (riskScore >= config.alertThreshold) {
            finalVerdict = ProcessVerdict::AllowMonitored; // Or AllowSuspicious
            stats.processesSuspicious++;

            // Create ProcessInfo for callback
            ProcessInfo info = CreateProcessInfoFromEvent(event);
            info.riskScore = riskScore;
            info.suspiciousPatterns = patterns;

            NotifySuspicious(info, patterns);
        } else {
            finalVerdict = ProcessVerdict::Allow;
            stats.processesAllowed++;
        }

        // 8. Update State (Process Tree)
        if (finalVerdict != ProcessVerdict::Block) {
            UpdateProcessState(event, finalVerdict);
        }

        // Update timing stats
        auto endTime = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(endTime - startTime).count();
        stats.avgDecisionTimeUs = (stats.avgDecisionTimeUs * 9 + duration) / 10; // Simple moving average

        // Notify callbacks
        NotifyCreate(event, finalVerdict);

        return finalVerdict;
    }

    void UpdateProcessState(const ProcessCreateEvent& event, ProcessVerdict verdict) {
        if (!config.trackParentChild) return;

        std::unique_lock lock(processMutex);

        // Create ProcessInfo
        ProcessInfo info = CreateProcessInfoFromEvent(event);
        info.verdict = verdict;
        info.state = ProcessState::Running;

        // Add to active processes
        activeProcesses[event.processId] = info;
        stats.trackedProcesses = activeProcesses.size();

        // Update Tree
        if (config.buildProcessTree) {
            ProcessTreeNode node;
            node.process = info;
            node.parentPid = event.parentProcessId;

            // Find parent
            auto parentIt = processTree.find(event.parentProcessId);
            if (parentIt != processTree.end()) {
                parentIt->second.childPids.push_back(event.processId);
                node.depth = parentIt->second.depth + 1;
                node.ancestorPath = parentIt->second.ancestorPath;
                node.ancestorPath.push_back(event.parentProcessId);
            } else {
                node.depth = 0;
            }

            processTree[event.processId] = node;
        }
    }

    void HandleProcessTerminate(uint32_t pid, uint32_t exitCode) {
        stats.processTerminations++;

        {
            std::unique_lock lock(processMutex);
            auto it = activeProcesses.find(pid);
            if (it != activeProcesses.end()) {
                it->second.state = ProcessState::Terminated;
                it->second.exitCode = exitCode;
                it->second.terminationTime = std::chrono::system_clock::now();

                // We don't remove immediately to allow for history retention
                // Cleanup is handled by a separate maintenance task
            }
        }

        NotifyTerminate(pid, exitCode);
    }

    // -------------------------------------------------------------------------
    // Analysis Methods
    // -------------------------------------------------------------------------

    CommandLineAnalysis AnalyzeCommandLine(const std::wstring& cmdLine) {
        CommandLineAnalysis result;
        result.originalCommandLine = cmdLine;

        // Parse arguments (simplified)
        result.arguments = Utils::StringUtils::SplitArgs(cmdLine);
        if (!result.arguments.empty()) {
            result.executablePath = result.arguments[0];
        }

        // Check for indicators
        // 1. Base64 / Encoded
        if (config.detectEncodedCommands && Utils::StringUtils::ContainsBase64(cmdLine)) {
            result.hasEncodedContent = true;
            result.encodingType = "Base64";
            result.patterns.push_back(SuspiciousPattern::EncodedPowerShell);
            result.riskScore += ProcessMonitorConstants::ENCODED_COMMAND_SCORE;
        }

        // 2. URLs
        result.extractedURLs = ExtractURLsFromCommandLine(cmdLine);
        if (!result.extractedURLs.empty()) {
            result.hasURLs = true;
            if (result.extractedURLs.size() > ProcessMonitorConstants::URL_COUNT_THRESHOLD) {
                result.riskScore += ProcessMonitorConstants::DOWNLOAD_COMMAND_SCORE;
                result.patterns.push_back(SuspiciousPattern::DownloadCommand);
            }
        }

        // 3. Suspicious Keywords (Obfuscation, bypass)
        static const std::vector<std::wstring> suspiciousKeywords = {
            L"-enc", L"-encodedcommand", L"bypass", L"hidden", L"downloadstring",
            L"iex", L"invoke-expression", L"invoke-webrequest"
        };

        for (const auto& keyword : suspiciousKeywords) {
            if (ContainsCaseInsensitive(cmdLine, keyword)) {
                result.suspiciousKeywords.push_back(Utils::StringUtils::WideToUtf8(keyword));
                result.riskScore += 10.0;

                if (keyword == L"bypass") result.patterns.push_back(SuspiciousPattern::BypassExecutionPolicy);
                if (keyword == L"hidden") result.patterns.push_back(SuspiciousPattern::HiddenWindowExecution);
            }
        }

        // 4. Obfuscation (caret, random case)
        if (std::count(cmdLine.begin(), cmdLine.end(), L'^') > 3) {
            result.patterns.push_back(SuspiciousPattern::ObfuscatedCmdLine);
            result.riskScore += 15.0;
        }

        return result;
    }

    ProcessVerdict PerformScan(const ProcessCreateEvent& event) {
        stats.scansPerformed++;

        // Use infrastructure ScanEngine
        if (!scanEngine) return ProcessVerdict::Allow;

        // Note: ScanEngine::ScanFile should be synchronous or we wait
        // In a real kernel callback scenario, we must be fast.
        // Here we simulate a quick scan or cache lookup.

        // auto result = scanEngine->ScanFile(event.imagePath);
        // if (result.verdict == Engine::Verdict::Malware) return ProcessVerdict::Block;

        return ProcessVerdict::Allow;
    }

    std::optional<ProcessVerdict> EvaluateRules(const ProcessCreateEvent& event, const CommandLineAnalysis& cmdAnalysis) {
        std::shared_lock lock(rulesMutex);

        // Sort by priority (descending)
        // Note: Ideally rules are pre-sorted

        for (const auto& rule : rules) {
            if (!rule.enabled) continue;

            bool match = true;

            if (rule.imagePathPattern && !PathMatchesPattern(event.imagePath, *rule.imagePathPattern)) match = false;
            if (match && rule.imageHash && event.imageHash != *rule.imageHash) match = false;
            if (match && rule.imageNamePattern && !PathMatchesPattern(event.imageFileName, *rule.imageNamePattern)) match = false;

            if (match && rule.commandLinePattern) {
                // Regex check or substring
                if (!ContainsCaseInsensitive(event.commandLine, *rule.commandLinePattern)) match = false;
            }

            if (match) {
                return rule.action;
            }
        }

        return std::nullopt;
    }

    double CalculateRiskScore(const ProcessCreateEvent& event, const CommandLineAnalysis& cmd, std::vector<SuspiciousPattern>& patterns) {
        double score = cmd.riskScore;
        patterns.insert(patterns.end(), cmd.patterns.begin(), cmd.patterns.end());

        // Parent-Child Analysis
        if (config.detectSuspiciousParentChild && config.trackParentChild) {
            std::shared_lock lock(processMutex);
            auto parentIt = activeProcesses.find(event.parentProcessId);
            if (parentIt != activeProcesses.end()) {
                auto pcPatterns = CheckParentChild(parentIt->second, event);
                if (!pcPatterns.empty()) {
                    patterns.insert(patterns.end(), pcPatterns.begin(), pcPatterns.end());
                    score += ProcessMonitorConstants::SUSPICIOUS_PARENT_CHILD_SCORE * pcPatterns.size();
                }
            }
        }

        // LOLBAS
        if (config.detectLOLBAS) {
            LOLBASType type = ClassifyLOLBAS(event.imageFileName);
            if (type != LOLBASType::None) {
                // Check if arguments look malicious for this LOLBAS
                if (cmd.hasURLs || cmd.hasEncodedContent || !cmd.suspiciousKeywords.empty()) {
                    score += ProcessMonitorConstants::LOLBAS_ABUSE_SCORE;
                }
            }
        }

        // Location Checks
        if (IsInTempFolder(event.imagePath)) {
            patterns.push_back(SuspiciousPattern::TempFolderExecution);
            score += ProcessMonitorConstants::TEMP_FOLDER_EXECUTION_SCORE;
        }

        if (IsNetworkPath(event.imagePath)) {
            patterns.push_back(SuspiciousPattern::NetworkShareExecution);
            if (config.blockFromNetwork) score += 100.0;
        }

        // Signature
        if (!event.isImageSigned) {
            score += ProcessMonitorConstants::UNSIGNED_EXECUTABLE_SCORE;
            if (config.blockUnsigned) score += 100.0;
        }

        return score;
    }

    std::vector<SuspiciousPattern> CheckParentChild(const ProcessInfo& parent, const ProcessCreateEvent& child) {
        std::vector<SuspiciousPattern> patterns;

        // 1. Office -> Script/Shell
        if (parent.isOfficeApp) {
            if (IsScriptInterpreter(child.imageFileName)) patterns.push_back(SuspiciousPattern::OfficeSpawnsScript);
            if (ClassifyLOLBAS(child.imageFileName) == LOLBASType::Cmd ||
                ClassifyLOLBAS(child.imageFileName) == LOLBASType::PowerShell) {
                patterns.push_back(SuspiciousPattern::OfficeSpawnsShell);
            }
        }

        // 2. Services -> Shell (often web shell or exploit)
        if (Utils::StringUtils::EqualsCaseInsensitive(parent.imageName, L"services.exe")) {
             if (ClassifyLOLBAS(child.imageFileName) == LOLBASType::Cmd ||
                ClassifyLOLBAS(child.imageFileName) == LOLBASType::PowerShell) {
                patterns.push_back(SuspiciousPattern::ServicesSpawnsShell);
            }
        }

        // 3. Svchost -> Non-Service
        if (Utils::StringUtils::EqualsCaseInsensitive(parent.imageName, L"svchost.exe")) {
            // Svchost normally spawns other system services or COM providers
            // Spawning cmd.exe is very suspicious
            if (ClassifyLOLBAS(child.imageFileName) != LOLBASType::None) {
                patterns.push_back(SuspiciousPattern::SvchostSpawnsUnexpected);
            }
        }

        return patterns;
    }

    // -------------------------------------------------------------------------
    // Utility Helpers
    // -------------------------------------------------------------------------

    ProcessInfo CreateProcessInfoFromEvent(const ProcessCreateEvent& event) {
        ProcessInfo info;
        info.processId = event.processId;
        info.parentProcessId = event.parentProcessId;
        info.sessionId = event.sessionId;
        info.imagePath = event.imagePath;
        info.imageName = event.imageFileName;
        info.commandLine = event.commandLine;
        info.currentDirectory = event.currentDirectory;
        info.userSid = event.userSid;
        info.userName = event.userName;
        info.isElevated = event.isElevated;
        info.integrityLevel = event.integrityLevel;
        info.creationTime = event.timestamp;
        info.state = ProcessState::Creating;
        info.isSigned = event.isImageSigned;
        info.signerName = event.imageSigner;
        info.imageHash = event.imageHash;

        info.lolbasType = ClassifyLOLBAS(info.imageName);
        info.isScriptInterpreter = IsScriptInterpreter(info.imageName);
        info.isOfficeApp = IsOfficeApplication(info.imageName);
        info.isBrowser = IsBrowser(info.imageName);

        info.processType = ClassifyProcessType(info);

        return info;
    }

    LOLBASType ClassifyLOLBAS(const std::wstring& imageName) const {
        if (Utils::StringUtils::EqualsCaseInsensitive(imageName, L"cmd.exe")) return LOLBASType::Cmd;
        if (Utils::StringUtils::EqualsCaseInsensitive(imageName, L"powershell.exe")) return LOLBASType::PowerShell;
        if (Utils::StringUtils::EqualsCaseInsensitive(imageName, L"pwsh.exe")) return LOLBASType::PowerShell;
        if (Utils::StringUtils::EqualsCaseInsensitive(imageName, L"wscript.exe")) return LOLBASType::WSH;
        if (Utils::StringUtils::EqualsCaseInsensitive(imageName, L"cscript.exe")) return LOLBASType::WSH;
        if (Utils::StringUtils::EqualsCaseInsensitive(imageName, L"mshta.exe")) return LOLBASType::Mshta;
        if (Utils::StringUtils::EqualsCaseInsensitive(imageName, L"regsvr32.exe")) return LOLBASType::Regsvr32;
        if (Utils::StringUtils::EqualsCaseInsensitive(imageName, L"rundll32.exe")) return LOLBASType::Rundll32;
        if (Utils::StringUtils::EqualsCaseInsensitive(imageName, L"certutil.exe")) return LOLBASType::Certutil;
        if (Utils::StringUtils::EqualsCaseInsensitive(imageName, L"bitsadmin.exe")) return LOLBASType::Bitsadmin;
        if (Utils::StringUtils::EqualsCaseInsensitive(imageName, L"wmic.exe")) return LOLBASType::Wmic;
        return LOLBASType::None;
    }

    bool IsScriptInterpreter(const std::wstring& imageName) const {
        LOLBASType type = ClassifyLOLBAS(imageName);
        return type == LOLBASType::PowerShell || type == LOLBASType::WSH || type == LOLBASType::Mshta || type == LOLBASType::Cmd;
    }

    bool IsOfficeApplication(const std::wstring& imageName) const {
        return Utils::StringUtils::EqualsCaseInsensitive(imageName, L"winword.exe") ||
               Utils::StringUtils::EqualsCaseInsensitive(imageName, L"excel.exe") ||
               Utils::StringUtils::EqualsCaseInsensitive(imageName, L"powerpnt.exe") ||
               Utils::StringUtils::EqualsCaseInsensitive(imageName, L"outlook.exe");
    }

    bool IsBrowser(const std::wstring& imageName) const {
        return Utils::StringUtils::EqualsCaseInsensitive(imageName, L"chrome.exe") ||
               Utils::StringUtils::EqualsCaseInsensitive(imageName, L"firefox.exe") ||
               Utils::StringUtils::EqualsCaseInsensitive(imageName, L"msedge.exe") ||
               Utils::StringUtils::EqualsCaseInsensitive(imageName, L"iexplore.exe");
    }

    ProcessType ClassifyProcessType(const ProcessInfo& info) const {
        if (info.isScriptInterpreter) return ProcessType::ScriptInterpreter;
        if (info.isBrowser) return ProcessType::Browser;
        if (info.isOfficeApp) return ProcessType::Office;
        if (Utils::StringUtils::EqualsCaseInsensitive(info.imageName, L"svchost.exe")) return ProcessType::Service;
        return ProcessType::Unknown;
    }

    // -------------------------------------------------------------------------
    // Notification
    // -------------------------------------------------------------------------

    void NotifyCreate(const ProcessCreateEvent& event, ProcessVerdict verdict) {
        std::shared_lock lock(callbacksMutex);
        for (const auto& [id, callback] : createCallbacks) {
            try {
                // Note: Kernel event expects verdict return, but here we just notify async observers
                // The actual verdict was already decided
                callback(event);
            } catch (...) {}
        }
    }

    void NotifyTerminate(uint32_t pid, uint32_t exitCode) {
        std::shared_lock lock(callbacksMutex);
        for (const auto& [id, callback] : terminateCallbacks) {
            try {
                callback(pid, exitCode);
            } catch (...) {}
        }
    }

    void NotifySuspicious(const ProcessInfo& info, const std::vector<SuspiciousPattern>& patterns) {
        std::shared_lock lock(callbacksMutex);
        for (const auto& [id, callback] : suspiciousCallbacks) {
            try {
                callback(info, patterns);
            } catch (...) {}
        }
    }
};

// ============================================================================
// PUBLIC API IMPLEMENTATION
// ============================================================================

ProcessCreationMonitor& ProcessCreationMonitor::Instance() {
    static ProcessCreationMonitor instance;
    return instance;
}

ProcessCreationMonitor::ProcessCreationMonitor() : m_impl(std::make_unique<Impl>()) {}
ProcessCreationMonitor::~ProcessCreationMonitor() = default;

bool ProcessCreationMonitor::Initialize() {
    return m_impl->Initialize(nullptr, ProcessMonitorConfig::CreateDefault());
}

bool ProcessCreationMonitor::Initialize(std::shared_ptr<Utils::ThreadPool> threadPool) {
    return m_impl->Initialize(threadPool, ProcessMonitorConfig::CreateDefault());
}

bool ProcessCreationMonitor::Initialize(std::shared_ptr<Utils::ThreadPool> threadPool, const ProcessMonitorConfig& config) {
    return m_impl->Initialize(threadPool, config);
}

void ProcessCreationMonitor::Shutdown() {
    m_impl->Shutdown();
}

void ProcessCreationMonitor::Start() {
    m_impl->Start();
}

void ProcessCreationMonitor::Stop() {
    m_impl->Stop();
}

bool ProcessCreationMonitor::IsRunning() const noexcept {
    return m_impl->isRunning;
}

void ProcessCreationMonitor::UpdateConfig(const ProcessMonitorConfig& config) {
    m_impl->config = config;
}

ProcessMonitorConfig ProcessCreationMonitor::GetConfig() const {
    return m_impl->config;
}

ProcessVerdict ProcessCreationMonitor::OnProcessCreate(const ProcessCreateEvent& event) {
    return m_impl->HandleProcessCreate(event);
}

ProcessVerdict ProcessCreationMonitor::OnProcessCreate(uint32_t pid, const std::wstring& imagePath, uint32_t parentPid) {
    ProcessCreateEvent event;
    event.processId = pid;
    event.imagePath = imagePath;
    event.parentProcessId = parentPid;
    event.timestamp = std::chrono::system_clock::now();

    // Extract filename
    std::filesystem::path p(imagePath);
    event.imageFileName = p.filename().wstring();

    return m_impl->HandleProcessCreate(event);
}

void ProcessCreationMonitor::OnProcessTerminate(uint32_t pid, uint32_t exitCode) {
    m_impl->HandleProcessTerminate(pid, exitCode);
}

// Queries
std::optional<ProcessInfo> ProcessCreationMonitor::GetProcessInfo(uint32_t pid) const {
    std::shared_lock lock(m_impl->processMutex);
    auto it = m_impl->activeProcesses.find(pid);
    if (it != m_impl->activeProcesses.end()) return it->second;
    return std::nullopt;
}

std::optional<ProcessTreeNode> ProcessCreationMonitor::GetProcessTree(uint32_t pid) const {
    std::shared_lock lock(m_impl->processMutex);
    auto it = m_impl->processTree.find(pid);
    if (it != m_impl->processTree.end()) return it->second;
    return std::nullopt;
}

std::optional<ProcessInfo> ProcessCreationMonitor::GetParentProcess(uint32_t pid) const {
    std::shared_lock lock(m_impl->processMutex);
    auto it = m_impl->activeProcesses.find(pid);
    if (it != m_impl->activeProcesses.end()) {
        auto parentIt = m_impl->activeProcesses.find(it->second.parentProcessId);
        if (parentIt != m_impl->activeProcesses.end()) return parentIt->second;
    }
    return std::nullopt;
}

std::vector<ProcessInfo> ProcessCreationMonitor::GetChildProcesses(uint32_t pid) const {
    std::vector<ProcessInfo> children;
    std::shared_lock lock(m_impl->processMutex);

    auto it = m_impl->processTree.find(pid);
    if (it != m_impl->processTree.end()) {
        for (uint32_t childPid : it->second.childPids) {
            auto childIt = m_impl->activeProcesses.find(childPid);
            if (childIt != m_impl->activeProcesses.end()) {
                children.push_back(childIt->second);
            }
        }
    }
    return children;
}

std::vector<ProcessInfo> ProcessCreationMonitor::GetAncestorChain(uint32_t pid) const {
    std::vector<ProcessInfo> ancestors;
    std::shared_lock lock(m_impl->processMutex);

    auto it = m_impl->processTree.find(pid);
    if (it != m_impl->processTree.end()) {
        for (uint32_t ancestorPid : it->second.ancestorPath) {
            auto aIt = m_impl->activeProcesses.find(ancestorPid);
            if (aIt != m_impl->activeProcesses.end()) {
                ancestors.push_back(aIt->second);
            }
        }
    }
    return ancestors;
}

bool ProcessCreationMonitor::IsProcessRunning(uint32_t pid) const {
    std::shared_lock lock(m_impl->processMutex);
    auto it = m_impl->activeProcesses.find(pid);
    if (it != m_impl->activeProcesses.end()) {
        return it->second.IsRunning();
    }
    return false;
}

std::vector<ProcessInfo> ProcessCreationMonitor::GetAllProcesses() const {
    std::vector<ProcessInfo> result;
    std::shared_lock lock(m_impl->processMutex);
    result.reserve(m_impl->activeProcesses.size());
    for (const auto& [pid, info] : m_impl->activeProcesses) {
        result.push_back(info);
    }
    return result;
}

std::vector<ProcessInfo> ProcessCreationMonitor::GetProcessesByUser(const std::wstring& userName) const {
    std::vector<ProcessInfo> result;
    std::shared_lock lock(m_impl->processMutex);
    for (const auto& [pid, info] : m_impl->activeProcesses) {
        if (Utils::StringUtils::EqualsCaseInsensitive(info.userName, userName)) {
            result.push_back(info);
        }
    }
    return result;
}

std::vector<ProcessInfo> ProcessCreationMonitor::GetProcessesByImage(const std::wstring& imageName) const {
    std::vector<ProcessInfo> result;
    std::shared_lock lock(m_impl->processMutex);
    for (const auto& [pid, info] : m_impl->activeProcesses) {
        if (Utils::StringUtils::EqualsCaseInsensitive(info.imageName, imageName)) {
            result.push_back(info);
        }
    }
    return result;
}

// Analysis
CommandLineAnalysis ProcessCreationMonitor::AnalyzeCommandLine(const std::wstring& commandLine) const {
    return m_impl->AnalyzeCommandLine(commandLine);
}

bool ProcessCreationMonitor::IsCommandLineSuspicious(const std::wstring& commandLine) const {
    auto analysis = m_impl->AnalyzeCommandLine(commandLine);
    return !analysis.patterns.empty() || analysis.riskScore > 20.0;
}

std::wstring ProcessCreationMonitor::DecodeEncodedContent(const std::wstring& content) const {
    // Basic base64 decode for illustration
    return Utils::StringUtils::Base64DecodeW(content);
}

LOLBASType ProcessCreationMonitor::ClassifyLOLBAS(const std::wstring& imageName) const {
    return m_impl->ClassifyLOLBAS(imageName);
}

ProcessType ProcessCreationMonitor::ClassifyProcessType(const ProcessInfo& info) const {
    return m_impl->ClassifyProcessType(info);
}

std::vector<SuspiciousPattern> ProcessCreationMonitor::CheckParentChild(const ProcessInfo& parent, const ProcessInfo& child) const {
    ProcessCreateEvent dummyEvent;
    dummyEvent.imageFileName = child.imageName;
    dummyEvent.imagePath = child.imagePath;
    return m_impl->CheckParentChild(parent, dummyEvent);
}

// Rule Management
bool ProcessCreationMonitor::AddRule(const ProcessPolicyRule& rule) {
    std::unique_lock lock(m_impl->rulesMutex);
    m_impl->rules.push_back(rule);
    // Sort by priority descending
    std::sort(m_impl->rules.begin(), m_impl->rules.end(),
        [](const auto& a, const auto& b) { return a.priority > b.priority; });
    return true;
}

bool ProcessCreationMonitor::RemoveRule(const std::string& ruleId) {
    std::unique_lock lock(m_impl->rulesMutex);
    auto it = std::remove_if(m_impl->rules.begin(), m_impl->rules.end(),
        [&ruleId](const auto& rule) { return rule.ruleId == ruleId; });

    if (it != m_impl->rules.end()) {
        m_impl->rules.erase(it, m_impl->rules.end());
        return true;
    }
    return false;
}

void ProcessCreationMonitor::SetRuleEnabled(const std::string& ruleId, bool enabled) {
    std::unique_lock lock(m_impl->rulesMutex);
    for (auto& rule : m_impl->rules) {
        if (rule.ruleId == ruleId) {
            rule.enabled = enabled;
            break;
        }
    }
}

std::vector<ProcessPolicyRule> ProcessCreationMonitor::GetRules() const {
    std::shared_lock lock(m_impl->rulesMutex);
    return m_impl->rules;
}

bool ProcessCreationMonitor::LoadRulesFromFile(const std::wstring& filePath) {
    // In production: JSON load
    return false;
}

bool ProcessCreationMonitor::SaveRulesToFile(const std::wstring& filePath) const {
    // In production: JSON save
    return false;
}

// Stats
ProcessMonitorStats ProcessCreationMonitor::GetStats() const {
    return m_impl->stats;
}

void ProcessCreationMonitor::ResetStats() {
    m_impl->stats.Reset();
}

// Callbacks
uint64_t ProcessCreationMonitor::RegisterCreateCallback(ProcessCreateCallback callback) {
    std::unique_lock lock(m_impl->callbacksMutex);
    uint64_t id = m_impl->nextCallbackId++;
    m_impl->createCallbacks[id] = callback;
    return id;
}

bool ProcessCreationMonitor::UnregisterCreateCallback(uint64_t callbackId) {
    std::unique_lock lock(m_impl->callbacksMutex);
    return m_impl->createCallbacks.erase(callbackId) > 0;
}

uint64_t ProcessCreationMonitor::RegisterTerminateCallback(ProcessTerminateCallback callback) {
    std::unique_lock lock(m_impl->callbacksMutex);
    uint64_t id = m_impl->nextCallbackId++;
    m_impl->terminateCallbacks[id] = callback;
    return id;
}

bool ProcessCreationMonitor::UnregisterTerminateCallback(uint64_t callbackId) {
    std::unique_lock lock(m_impl->callbacksMutex);
    return m_impl->terminateCallbacks.erase(callbackId) > 0;
}

uint64_t ProcessCreationMonitor::RegisterSuspiciousCallback(SuspiciousProcessCallback callback) {
    std::unique_lock lock(m_impl->callbacksMutex);
    uint64_t id = m_impl->nextCallbackId++;
    m_impl->suspiciousCallbacks[id] = callback;
    return id;
}

bool ProcessCreationMonitor::UnregisterSuspiciousCallback(uint64_t callbackId) {
    std::unique_lock lock(m_impl->callbacksMutex);
    return m_impl->suspiciousCallbacks.erase(callbackId) > 0;
}

// Integration
void ProcessCreationMonitor::SetScanEngine(Core::Engine::ScanEngine* engine) {
    m_impl->scanEngine = engine;
}

void ProcessCreationMonitor::SetThreatDetector(Core::Engine::ThreatDetector* detector) {
    m_impl->threatDetector = detector;
}

void ProcessCreationMonitor::SetBehaviorAnalyzer(Core::Engine::BehaviorAnalyzer* analyzer) {
    m_impl->behaviorAnalyzer = analyzer;
}

void ProcessCreationMonitor::SetWhitelistStore(Whitelist::WhitelistStore* store) {
    m_impl->whitelistStore = store;
}

void ProcessCreationMonitor::SetHashStore(HashStore::HashStore* store) {
    m_impl->hashStore = store;
}

void ProcessCreationMonitor::SetThreatIntelIndex(ThreatIntel::ThreatIntelIndex* index) {
    m_impl->threatIntelIndex = index;
}

// Utility Implementations
std::wstring GetProcessImageName(const std::wstring& imagePath) {
    std::filesystem::path p(imagePath);
    return p.filename().wstring();
}

bool IsScriptInterpreter(const std::wstring& imageName) noexcept {
    return ProcessCreationMonitor::Instance().m_impl->IsScriptInterpreter(imageName);
}

bool IsBrowser(const std::wstring& imageName) noexcept {
    return ProcessCreationMonitor::Instance().m_impl->IsBrowser(imageName);
}

bool IsOfficeApplication(const std::wstring& imageName) noexcept {
    return ProcessCreationMonitor::Instance().m_impl->IsOfficeApplication(imageName);
}

bool IsInTempFolder(const std::wstring& path) noexcept {
    return ContainsCaseInsensitive(path, L"\\AppData\\Local\\Temp") ||
           ContainsCaseInsensitive(path, L"\\Windows\\Temp");
}

bool IsInDownloadsFolder(const std::wstring& path) noexcept {
    return ContainsCaseInsensitive(path, L"\\Downloads\\");
}

bool IsNetworkPath(const std::wstring& path) noexcept {
    return path.starts_with(L"\\\\");
}

bool ContainsBase64(const std::wstring& str) noexcept {
    return Utils::StringUtils::ContainsBase64(str);
}

std::vector<std::string> ExtractURLsFromCommandLine(const std::wstring& cmdLine) noexcept {
    // Simplified URL extraction
    // In production use proper regex
    return {};
}

// Utility string functions
constexpr const char* ProcessVerdictToString(ProcessVerdict verdict) noexcept {
    switch (verdict) {
        case ProcessVerdict::Allow: return "Allow";
        case ProcessVerdict::Block: return "Block";
        case ProcessVerdict::AllowMonitored: return "AllowMonitored";
        case ProcessVerdict::AllowSuspicious: return "AllowSuspicious";
        case ProcessVerdict::Timeout: return "Timeout";
        case ProcessVerdict::Error: return "Error";
        default: return "Unknown";
    }
}

constexpr const char* LOLBASTypeToString(LOLBASType type) noexcept {
    switch (type) {
        case LOLBASType::Cmd: return "Cmd";
        case LOLBASType::PowerShell: return "PowerShell";
        case LOLBASType::WSH: return "WSH";
        case LOLBASType::Mshta: return "Mshta";
        case LOLBASType::Regsvr32: return "Regsvr32";
        default: return "Other/None";
    }
}

constexpr const char* SuspiciousPatternToString(SuspiciousPattern pattern) noexcept {
    // See internal helper
    return "SuspiciousPattern";
}

} // namespace RealTime
} // namespace ShadowStrike
