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
#include "../SelfProtection/DigitalSignatureValidator.hpp"
#include "../AI/PhantomCortex.hpp"

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <regex>
#include <sstream>
#include <thread>
#include <future>
#include <nlohmann/json.hpp>

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

#if defined(SHADOWSTRIKE_RTP_FOCUSED_BUILD)
    constexpr bool kFocusedUserModeBuild = true;
#else
    constexpr bool kFocusedUserModeBuild = false;
#endif

    // -------------------------------------------------------------------------
    // INTERNAL ATOMIC STATS (bridges atomic writes → public copyable snapshot)
    // -------------------------------------------------------------------------
    struct ProcessMonitorStatsInternal {
        std::atomic<uint64_t> totalProcessCreations{0};
        std::atomic<uint64_t> processesAllowed{0};
        std::atomic<uint64_t> processesBlocked{0};
        std::atomic<uint64_t> processesSuspicious{0};
        std::atomic<uint64_t> scansPerformed{0};
        std::atomic<uint64_t> scanTimeouts{0};
        std::atomic<uint64_t> lolbasDetections{0};
        std::atomic<uint64_t> parentChildDetections{0};
        std::atomic<uint64_t> encodedCommandDetections{0};
        std::atomic<uint64_t> masqueradingDetections{0};
        std::atomic<size_t>   trackedProcesses{0};
        std::atomic<uint64_t> processTerminations{0};
        std::atomic<uint64_t> avgDecisionTimeUs{0};

        void Reset() noexcept {
            totalProcessCreations.store(0,    std::memory_order_relaxed);
            processesAllowed.store(0,         std::memory_order_relaxed);
            processesBlocked.store(0,         std::memory_order_relaxed);
            processesSuspicious.store(0,      std::memory_order_relaxed);
            scansPerformed.store(0,           std::memory_order_relaxed);
            scanTimeouts.store(0,             std::memory_order_relaxed);
            lolbasDetections.store(0,         std::memory_order_relaxed);
            parentChildDetections.store(0,    std::memory_order_relaxed);
            encodedCommandDetections.store(0, std::memory_order_relaxed);
            masqueradingDetections.store(0,   std::memory_order_relaxed);
            trackedProcesses.store(0,         std::memory_order_relaxed);
            processTerminations.store(0,      std::memory_order_relaxed);
            avgDecisionTimeUs.store(0,        std::memory_order_relaxed);
        }

        [[nodiscard]] ProcessMonitorStats Snapshot() const noexcept {
            ProcessMonitorStats s;
            s.totalProcessCreations    = totalProcessCreations.load(std::memory_order_relaxed);
            s.processesAllowed         = processesAllowed.load(std::memory_order_relaxed);
            s.processesBlocked         = processesBlocked.load(std::memory_order_relaxed);
            s.processesSuspicious      = processesSuspicious.load(std::memory_order_relaxed);
            s.scansPerformed           = scansPerformed.load(std::memory_order_relaxed);
            s.scanTimeouts             = scanTimeouts.load(std::memory_order_relaxed);
            s.lolbasDetections         = lolbasDetections.load(std::memory_order_relaxed);
            s.parentChildDetections    = parentChildDetections.load(std::memory_order_relaxed);
            s.encodedCommandDetections = encodedCommandDetections.load(std::memory_order_relaxed);
            s.masqueradingDetections   = masqueradingDetections.load(std::memory_order_relaxed);
            s.trackedProcesses         = trackedProcesses.load(std::memory_order_relaxed);
            s.processTerminations      = processTerminations.load(std::memory_order_relaxed);
            s.avgDecisionTimeUs        = avgDecisionTimeUs.load(std::memory_order_relaxed);
            return s;
        }
    };

    // -------------------------------------------------------------------------

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
                return ::towlower(static_cast<wint_t>(ch1)) ==
                       ::towlower(static_cast<wint_t>(ch2));
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

    /// @brief Detect a run of Base64-valid characters long enough to be encoded content
    bool ContainsBase64Blob(std::wstring_view str) noexcept {
        constexpr size_t kMinRun = ProcessMonitorConstants::ENCODED_CMDLINE_THRESHOLD;
        size_t runLen = 0;
        for (wchar_t ch : str) {
            if ((ch >= L'A' && ch <= L'Z') || (ch >= L'a' && ch <= L'z') ||
                (ch >= L'0' && ch <= L'9') || ch == L'+' || ch == L'/' || ch == L'=') {
                if (++runLen >= kMinRun) return true;
            } else {
                runLen = 0;
            }
        }
        return false;
    }

    /// @brief Case-insensitive wildcard path match (supports * glob token)
    bool PathMatchesPattern(const std::wstring& path, const std::wstring& pattern) noexcept {
        if (pattern.empty() || pattern == L"*") return true;

        // Build lower-case copies via ::towlower to avoid string allocation in hot path
        std::wstring lPath(path.size(), L'\0');
        std::wstring lPat(pattern.size(), L'\0');
        std::transform(path.begin(),    path.end(),    lPath.begin(),
                       [](wchar_t c){ return static_cast<wchar_t>(::towlower(static_cast<wint_t>(c))); });
        std::transform(pattern.begin(), pattern.end(), lPat.begin(),
                       [](wchar_t c){ return static_cast<wchar_t>(::towlower(static_cast<wint_t>(c))); });

        if (lPat.find(L'*') == std::wstring::npos)
            return lPath == lPat;

        // Segment-by-segment wildcard matching
        size_t patPos = 0;
        size_t strPos = 0;
        bool   first  = true;

        while (patPos <= lPat.size()) {
            size_t starPos = lPat.find(L'*', patPos);
            std::wstring seg = (starPos == std::wstring::npos)
                               ? lPat.substr(patPos)
                               : lPat.substr(patPos, starPos - patPos);
            patPos = (starPos == std::wstring::npos) ? lPat.size() + 1 : starPos + 1;

            if (seg.empty()) { first = false; continue; }

            size_t found = lPath.find(seg, strPos);
            if (found == std::wstring::npos) return false;
            if (first && found != 0)         return false;
            first  = false;
            strPos = found + seg.size();
        }

        return (lPat.back() == L'*') || (strPos == lPath.size());
    }

    /// @brief Extract http/https/ftp URLs from a command line string
    std::vector<std::string> ExtractURLsFromCmdLine(const std::wstring& cmdLine) noexcept {
        std::vector<std::string> urls;
        try {
            static const std::wregex urlRegex(
                LR"((https?|ftp)://[^\s\x00-\x1F"'<>\\]{4,2048})",
                std::regex_constants::icase | std::regex_constants::optimize);

            auto begin = std::wsregex_iterator(cmdLine.begin(), cmdLine.end(), urlRegex);
            const std::wsregex_iterator end{};

            urls.reserve(4);
            for (auto it = begin; it != end && urls.size() < 16; ++it) {
                std::wstring m = (*it)[0].str();
                urls.push_back(Utils::StringUtils::ToNarrow(m));
            }
        } catch (...) {}
        return urls;
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
    mutable std::shared_mutex configMutex;
    ProcessMonitorStatsInternal stats;
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

    // External Integrations (guarded by integrationMutex)
    mutable std::shared_mutex integrationMutex;
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
        if (isInitialized.load(std::memory_order_acquire)) {
            Utils::Logger::Warn("ProcessCreationMonitor already initialized");
            return true;
        }

        threadPool = tp;
        {
            std::unique_lock cfgLock(configMutex);
            config = cfg;
        }

        stats.Reset();
        isInitialized.store(true, std::memory_order_release);
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
        stats.totalProcessCreations.fetch_add(1, std::memory_order_relaxed);
        auto startTime = std::chrono::high_resolution_clock::now();

        // Snapshot config once under shared lock to avoid racing with UpdateConfig
        ProcessMonitorConfig cfg;
        {
            std::shared_lock cfgLock(configMutex);
            cfg = config;
        }

        // Snapshot integration pointers under shared lock — Set* methods take unique_lock
        Core::Engine::ScanEngine* localScanEngine = nullptr;
        Core::Engine::ThreatDetector* localThreatDetector = nullptr;
        Core::Engine::BehaviorAnalyzer* localBehaviorAnalyzer = nullptr;
        Whitelist::WhitelistStore* localWhitelistStore = nullptr;
        HashStore::HashStore* localHashStore = nullptr;
        ThreatIntel::ThreatIntelIndex* localThreatIntelIndex = nullptr;
        {
            std::shared_lock intLock(integrationMutex);
            localScanEngine       = scanEngine;
            localThreatDetector   = threatDetector;
            localBehaviorAnalyzer = behaviorAnalyzer;
            localWhitelistStore   = whitelistStore;
            localHashStore        = hashStore;
            localThreatIntelIndex = threatIntelIndex;
        }

        // 1. Basic Allow/Block based on config
        if (!cfg.enabled) {
            stats.processesAllowed.fetch_add(1, std::memory_order_relaxed);
            return ProcessVerdict::Allow;
        }

        // 2. Check Whitelist
#if !defined(SHADOWSTRIKE_RTP_FOCUSED_BUILD)
        if (cfg.trustWhitelisted && localWhitelistStore) {
            auto wlResult = localWhitelistStore->IsWhitelisted(event.imagePath);
            if (wlResult.found) {
                UpdateProcessState(event, ProcessVerdict::Allow, cfg);
                stats.processesAllowed.fetch_add(1, std::memory_order_relaxed);
                return ProcessVerdict::Allow;
            }
        }
#endif

        // 3. Hash Check
#if !defined(SHADOWSTRIKE_RTP_FOCUSED_BUILD)
        if (cfg.blockKnownMalicious && localHashStore && !event.imageHash.empty()) {
            auto detection = localHashStore->LookupHashString(
                event.imageHash, HashStore::HashType::SHA256);
            if (detection.has_value()) {
                stats.processesBlocked.fetch_add(1, std::memory_order_relaxed);
                SS_LOG_WARN(L"ProcessCreationMonitor",
                    L"BLOCKED known malware hash: PID=%u Path=%ls Signature=%hs ThreatLevel=%u",
                    event.processId, event.imagePath.c_str(),
                    detection->signatureName.c_str(),
                    static_cast<uint32_t>(detection->threatLevel));
                return ProcessVerdict::Block;
            }
        }
#endif

        // 4. Command Line Analysis
        CommandLineAnalysis cmdAnalysis;
        if (cfg.analyzeCommandLine) {
            cmdAnalysis = AnalyzeCommandLine(event.commandLine);
        }

        // 5. Rule Evaluation
        auto ruleVerdict = EvaluateRules(event, cmdAnalysis);
        if (ruleVerdict.has_value()) {
            if (*ruleVerdict == ProcessVerdict::Block) {
                stats.processesBlocked.fetch_add(1, std::memory_order_relaxed);
                return ProcessVerdict::Block;
            }
            if (*ruleVerdict == ProcessVerdict::Allow) {
                // Explicit Allow rule — trusted process, skip further expensive checks
                UpdateProcessState(event, ProcessVerdict::Allow, cfg);
                stats.processesAllowed.fetch_add(1, std::memory_order_relaxed);
                return ProcessVerdict::Allow;
            }
        }

        // 6. Pre-Execution Scan (if enabled and not trusted)
        ProcessVerdict scanVerdict = ProcessVerdict::Allow;
#if !defined(SHADOWSTRIKE_RTP_FOCUSED_BUILD)
        if (cfg.preExecutionScan && localScanEngine) {
            // Check if we should scan (e.g. not Microsoft signed if trusted)
            bool shouldScan = true;
            if (cfg.trustMicrosoftSigned && event.isImageSigned &&
                event.imageSigner.find(L"Microsoft") != std::wstring::npos) {
                shouldScan = false;
            }

            if (shouldScan) {
                scanVerdict = PerformScan(event, localScanEngine);
                if (scanVerdict == ProcessVerdict::Block) {
                    stats.processesBlocked.fetch_add(1, std::memory_order_relaxed);
                    return ProcessVerdict::Block;
                }
            }
        }
#endif

        // 7. Behavioral/Heuristic Checks (Parent-Child, LOLBAS, Masquerading)
        std::vector<SuspiciousPattern> patterns;
        double riskScore = CalculateRiskScore(event, cmdAnalysis, patterns);

        ProcessVerdict finalVerdict = ProcessVerdict::Allow;

        if (riskScore >= cfg.blockThreshold) {
            finalVerdict = ProcessVerdict::Block;
            stats.processesBlocked.fetch_add(1, std::memory_order_relaxed);
        } else if (riskScore >= cfg.alertThreshold) {
            finalVerdict = ProcessVerdict::AllowMonitored;
            stats.processesSuspicious.fetch_add(1, std::memory_order_relaxed);

            // Create ProcessInfo for callback
            ProcessInfo info = CreateProcessInfoFromEvent(event);
            info.riskScore = riskScore;
            info.suspiciousPatterns = patterns;

            NotifySuspicious(info, patterns);
        } else {
            finalVerdict = ProcessVerdict::Allow;
            stats.processesAllowed.fetch_add(1, std::memory_order_relaxed);
        }

        // 8. Forward to BehaviorAnalyzer for cross-process correlation and APT hunting
#if !defined(SHADOWSTRIKE_RTP_FOCUSED_BUILD)
        if (localBehaviorAnalyzer && localBehaviorAnalyzer->IsInitialized()) {
            try {
                auto baEvent = Core::Engine::CreateProcessEvent(
                    Core::Engine::BehaviorEventType::ProcessCreate,
                    event.processId,
                    event.parentProcessId);
                baEvent.processName  = event.imagePath;
                baEvent.processPath  = event.imagePath;
                baEvent.commandLine  = event.commandLine;
                baEvent.success      = true;

                auto baVerdict = localBehaviorAnalyzer->ProcessEvent(baEvent);
                if (baVerdict.has_value() &&
                    baVerdict->RequiresImmediateAction() &&
                    finalVerdict != ProcessVerdict::Block) {
                    finalVerdict = ProcessVerdict::Block;
                    stats.processesBlocked.fetch_add(1, std::memory_order_relaxed);
                    SS_LOG_WARN(L"ProcessCreationMonitor",
                        L"BehaviorAnalyzer escalated PID=%u to BLOCK (score=%.1f pattern=%hs)",
                        event.processId,
                        baVerdict->maliceScore,
                        Core::Engine::BehaviorPatternTypeToString(baVerdict->primaryPattern));
                }
            } catch (const std::exception& ex) {
                SS_LOG_ERROR(L"ProcessCreationMonitor",
                    L"BA forwarding failed for PID=%u: %hs",
                    event.processId, ex.what());
            }
        }
#endif

        // 9. Update State (Process Tree)
        if (finalVerdict != ProcessVerdict::Block) {
            UpdateProcessState(event, finalVerdict, cfg);
        }

        // Update timing stats with atomic EMA (CAS loop prevents torn update)
        auto endTime  = std::chrono::high_resolution_clock::now();
        auto duration = static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::microseconds>(endTime - startTime).count());
        {
            uint64_t prev = stats.avgDecisionTimeUs.load(std::memory_order_relaxed);
            uint64_t next;
            do {
                next = (prev == 0) ? duration : (prev * 9 + duration) / 10;
            } while (!stats.avgDecisionTimeUs.compare_exchange_weak(
                prev, next, std::memory_order_relaxed, std::memory_order_relaxed));
        }

        // Notify callbacks
        NotifyCreate(event, finalVerdict);

        return finalVerdict;
    }

    void UpdateProcessState(const ProcessCreateEvent& event, ProcessVerdict verdict,
                            const ProcessMonitorConfig& cfg) {
        if (!cfg.trackParentChild || event.processId == 0) return;

        std::unique_lock lock(processMutex);

        // Create ProcessInfo
        ProcessInfo info = CreateProcessInfoFromEvent(event);
        info.verdict = verdict;
        info.state = ProcessState::Running;

        // Add to active processes
        activeProcesses[event.processId] = info;
        stats.trackedProcesses.store(activeProcesses.size(), std::memory_order_relaxed);

        // Update Tree
        if (cfg.buildProcessTree) {
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
        stats.processTerminations.fetch_add(1, std::memory_order_relaxed);

        // Forward termination to BehaviorAnalyzer for state cleanup (PID reuse protection)
#if !defined(SHADOWSTRIKE_RTP_FOCUSED_BUILD)
        {
            Core::Engine::BehaviorAnalyzer* localBA = nullptr;
            {
                std::shared_lock intLock(integrationMutex);
                localBA = behaviorAnalyzer;
            }
            if (localBA && localBA->IsInitialized()) {
                try {
                    auto baEvent = Core::Engine::CreateProcessEvent(
                        Core::Engine::BehaviorEventType::ProcessTerminate,
                        pid, 0);
                    baEvent.success = true;
                    (void)localBA->ProcessEvent(baEvent);
                } catch (...) {
                    // Termination forwarding must not block cleanup
                }
            }
        }
#endif

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

        // Local config snapshot to avoid races with UpdateConfig
        ProcessMonitorConfig cfg;
        {
            std::shared_lock cfgLock(configMutex);
            cfg = config;
        }

        // Parse arguments
        result.arguments = Utils::StringUtils::Split(cmdLine, L" ");
        if (!result.arguments.empty()) {
            result.executablePath = result.arguments[0];
        }

        // Check for indicators
        // 1. Base64 / Encoded
        if (cfg.detectEncodedCommands && ContainsBase64Blob(cmdLine)) {
            result.hasEncodedContent = true;
            result.encodingType = "Base64";
            result.patterns.push_back(SuspiciousPattern::EncodedPowerShell);
            result.riskScore += ProcessMonitorConstants::ENCODED_COMMAND_SCORE;
            stats.encodedCommandDetections.fetch_add(1, std::memory_order_relaxed);
        }

        // 2. URLs
        result.extractedURLs = ExtractURLsFromCmdLine(cmdLine);
        if (!result.extractedURLs.empty()) {
            result.hasURLs = true;
            if (result.extractedURLs.size() >= ProcessMonitorConstants::URL_COUNT_THRESHOLD) {
                result.riskScore += ProcessMonitorConstants::DOWNLOAD_COMMAND_SCORE;
                result.patterns.push_back(SuspiciousPattern::DownloadCommand);
            }
        }

        // 3. Suspicious Keywords (Obfuscation, bypass, download)
        static const std::vector<std::wstring> suspiciousKeywords = {
            L"-enc", L"-encodedcommand", L"bypass", L"hidden", L"downloadstring",
            L"iex", L"invoke-expression", L"invoke-webrequest", L"webclient",
            L"urldownloadtofile", L"bitsadmin", L"certutil", L"regsvr32",
            L"mshta", L"wscript", L"cscript", L"rundll32"
        };

        for (const auto& keyword : suspiciousKeywords) {
            if (ContainsCaseInsensitive(cmdLine, keyword)) {
                result.suspiciousKeywords.push_back(Utils::StringUtils::ToNarrow(keyword));
                result.riskScore += 10.0;

                if (keyword == L"-enc" || keyword == L"-encodedcommand") {
                    if (!result.hasEncodedContent) {
                        result.hasEncodedContent = true;
                        result.encodingType = "Base64";
                        result.patterns.push_back(SuspiciousPattern::EncodedPowerShell);
                        result.riskScore += ProcessMonitorConstants::ENCODED_COMMAND_SCORE;
                        stats.encodedCommandDetections.fetch_add(1, std::memory_order_relaxed);
                    }
                }
                if (keyword == L"bypass") result.patterns.push_back(SuspiciousPattern::BypassExecutionPolicy);
                if (keyword == L"hidden") result.patterns.push_back(SuspiciousPattern::HiddenWindowExecution);
                if (keyword == L"downloadstring" || keyword == L"urldownloadtofile" ||
                    keyword == L"invoke-webrequest") result.patterns.push_back(SuspiciousPattern::DownloadCommand);
                if (keyword == L"iex" || keyword == L"invoke-expression") result.patterns.push_back(SuspiciousPattern::ReflectionLoad);
            }
        }

        // 4. Obfuscation (caret, random case)
        if (std::count(cmdLine.begin(), cmdLine.end(), L'^') > 3) {
            result.patterns.push_back(SuspiciousPattern::ObfuscatedCmdLine);
            result.riskScore += 15.0;
        }

        return result;
    }

    ProcessVerdict PerformScan(const ProcessCreateEvent& event,
                              Core::Engine::ScanEngine* localScanEngine) {
#if defined(SHADOWSTRIKE_RTP_FOCUSED_BUILD)
        (void)event;
        (void)localScanEngine;
        return ProcessVerdict::Allow;
#else
        stats.scansPerformed.fetch_add(1, std::memory_order_relaxed);

        // ================================================================
        // DIGITAL SIGNATURE VALIDATION (Pre-Execution Gate)
        // ================================================================
        // Validate the process image signature before allowing execution.
        // Blocks stolen certificates, revoked certs, and high-risk anomalies.
        try {
            auto& dsv = Security::DigitalSignatureValidator::Instance();
            auto sigAnalysis = dsv.ValidateProcessImage(
                event.processId, event.parentProcessId, event.imagePath);

            // Stolen cert or critical risk → block immediately
            if (sigAnalysis.isStolenCert || sigAnalysis.riskScore >= 90) {
                SS_LOG_ERROR(L"ProcessCreationMonitor",
                    L"BLOCKED process with APT signature: PID=%u Path=%ls riskScore=%u",
                    event.processId, event.imagePath.c_str(), sigAnalysis.riskScore);
                return ProcessVerdict::Block;
            }

            // Revoked certificate → block
            if (sigAnalysis.signatureInfo.result ==
                Security::SignatureValidationResult::Revoked) {
                SS_LOG_WARN(L"ProcessCreationMonitor",
                    L"BLOCKED process with revoked certificate: PID=%u Path=%ls",
                    event.processId, event.imagePath.c_str());
                return ProcessVerdict::Block;
            }

            // Valid trusted signature with no anomalies → allow (skip heavy scan)
            if (sigAnalysis.signatureInfo.isValid &&
                sigAnalysis.signatureInfo.isMicrosoftSigned &&
                sigAnalysis.riskScore == 0) {
                return ProcessVerdict::Allow;
            }
        } catch (const std::exception& ex) {
            SS_LOG_ERROR(L"ProcessCreationMonitor",
                L"DSV exception in pre-exec gate PID=%u: %hs",
                event.processId, ex.what());
        } catch (...) {
            SS_LOG_ERROR(L"ProcessCreationMonitor",
                L"DSV unknown exception in pre-exec gate PID=%u",
                event.processId);
        }

        // ================================================================
        // CONTENT-BASED SCAN via ScanEngine
        // ================================================================
        if (!localScanEngine) return ProcessVerdict::Allow;

        try {
            auto scanResult = localScanEngine->QuickScanFile(event.imagePath);

            if (scanResult.verdict == Core::Engine::ScanVerdict::Infected) {
                SS_LOG_ERROR(L"ProcessCreationMonitor",
                    L"BLOCKED malware image: PID=%u Path=%ls Threat=%hs Score=%.1f",
                    event.processId, event.imagePath.c_str(),
                    scanResult.threatName.c_str(), scanResult.threatScore);
                return ProcessVerdict::Block;
            }

            if (scanResult.verdict == Core::Engine::ScanVerdict::Suspicious) {
                SS_LOG_WARN(L"ProcessCreationMonitor",
                    L"Suspicious image detected: PID=%u Path=%ls Threat=%hs Score=%.1f",
                    event.processId, event.imagePath.c_str(),
                    scanResult.threatName.c_str(), scanResult.threatScore);
                return ProcessVerdict::AllowMonitored;
            }

            if (scanResult.verdict == Core::Engine::ScanVerdict::Timeout) {
                stats.scanTimeouts.fetch_add(1, std::memory_order_relaxed);
                SS_LOG_WARN(L"ProcessCreationMonitor",
                    L"Pre-execution scan timeout: PID=%u Path=%ls",
                    event.processId, event.imagePath.c_str());
                ProcessMonitorConfig cfgSnap;
                {
                    std::shared_lock cl(configMutex);
                    cfgSnap = config;
                }
                return cfgSnap.blockOnTimeout ? ProcessVerdict::Block : ProcessVerdict::Allow;
            }
        } catch (const std::exception& ex) {
            SS_LOG_ERROR(L"ProcessCreationMonitor",
                L"ScanEngine exception in pre-exec scan PID=%u: %hs",
                event.processId, ex.what());
        } catch (...) {
            SS_LOG_ERROR(L"ProcessCreationMonitor",
                L"ScanEngine unknown exception in pre-exec scan PID=%u",
                event.processId);
        }

        // ================================================================
        // PhantomCortex AI/ML zero-day detection (additive — never downgrades)
        // ================================================================
        if (ShadowStrike::AI::PhantomCortex::Instance().IsOperational()) {
            try {
                std::ifstream ifs(event.imagePath, std::ios::binary | std::ios::ate);
                if (ifs.is_open()) {
                    const auto fileSize = ifs.tellg();
                    if (fileSize > 0 &&
                        static_cast<size_t>(fileSize) <= ShadowStrike::AI::CortexConstants::MAX_PE_FILE_SIZE) {
                        ifs.seekg(0, std::ios::beg);
                        std::vector<uint8_t> fileBytes(static_cast<size_t>(fileSize));
                        if (ifs.read(reinterpret_cast<char*>(fileBytes.data()),
                                     static_cast<std::streamsize>(fileSize))) {
                            auto mlVerdict = ShadowStrike::AI::PhantomCortex::Instance().AnalyzeFile(
                                std::span<const uint8_t>(fileBytes));

                            if (mlVerdict.verdict == ShadowStrike::AI::ThreatVerdict::Malicious) {
                                SS_LOG_ERROR(L"ProcessCreationMonitor",
                                    L"PhantomCortex ML BLOCKED zero-day threat: PID=%u Path=%ls confidence=%.2f",
                                    event.processId, event.imagePath.c_str(), mlVerdict.confidence);
                                return ProcessVerdict::Block;
                            }

                            if (mlVerdict.verdict == ShadowStrike::AI::ThreatVerdict::Suspicious) {
                                SS_LOG_WARN(L"ProcessCreationMonitor",
                                    L"PhantomCortex ML flagged suspicious process: PID=%u Path=%ls confidence=%.2f",
                                    event.processId, event.imagePath.c_str(), mlVerdict.confidence);
                                return ProcessVerdict::AllowMonitored;
                            }
                        }
                    }
                }
            } catch (const std::exception& ex) {
                SS_LOG_ERROR(L"ProcessCreationMonitor",
                    L"PhantomCortex ML analysis failed PID=%u: %hs",
                    event.processId, ex.what());
            } catch (...) {
                SS_LOG_ERROR(L"ProcessCreationMonitor",
                    L"PhantomCortex ML unknown exception PID=%u",
                    event.processId);
            }
        }

        return ProcessVerdict::Allow;
#endif
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

        // Local config snapshot
        ProcessMonitorConfig cfg;
        {
            std::shared_lock cfgLock(configMutex);
            cfg = config;
        }

        // Parent-Child Analysis
        if (cfg.detectSuspiciousParentChild && cfg.trackParentChild) {
            std::shared_lock lock(processMutex);
            auto parentIt = activeProcesses.find(event.parentProcessId);
            if (parentIt != activeProcesses.end()) {
                auto pcPatterns = CheckParentChild(parentIt->second, event);
                if (!pcPatterns.empty()) {
                    patterns.insert(patterns.end(), pcPatterns.begin(), pcPatterns.end());
                    score += ProcessMonitorConstants::SUSPICIOUS_PARENT_CHILD_SCORE * pcPatterns.size();
                    stats.parentChildDetections.fetch_add(1, std::memory_order_relaxed);
                }
            }
        }

        // LOLBAS
        if (cfg.detectLOLBAS) {
            LOLBASType type = ClassifyLOLBAS(event.imageFileName);
            if (type != LOLBASType::None) {
                // Check if arguments look malicious for this LOLBAS
                if (cmd.hasURLs || cmd.hasEncodedContent || !cmd.suspiciousKeywords.empty()) {
                    score += ProcessMonitorConstants::LOLBAS_ABUSE_SCORE;
                    stats.lolbasDetections.fetch_add(1, std::memory_order_relaxed);
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
            if (cfg.blockFromNetwork) score += 100.0;
        }

        // Masquerading check: system binary in wrong path
        if (cfg.detectMasquerading) {
            static const std::pair<const wchar_t*, const wchar_t*> kSystemBinaries[] = {
                { L"svchost.exe",  L"\\Windows\\System32\\" },
                { L"lsass.exe",    L"\\Windows\\System32\\" },
                { L"csrss.exe",    L"\\Windows\\System32\\" },
                { L"winlogon.exe", L"\\Windows\\System32\\" },
                { L"explorer.exe", L"\\Windows\\" },
            };
            for (const auto& [name, expectedPath] : kSystemBinaries) {
                if (Utils::StringUtils::IEquals(event.imageFileName, name)) {
                    if (!Utils::StringUtils::IContains(event.imagePath, expectedPath)) {
                        patterns.push_back(SuspiciousPattern::ProcessMasquerading);
                        score += 60.0;
                        stats.masqueradingDetections.fetch_add(1, std::memory_order_relaxed);
                        SS_LOG_WARN(L"ProcessCreationMonitor",
                            L"Process masquerading detected: PID=%u Image=%ls Path=%ls",
                            event.processId, event.imageFileName.c_str(),
                            event.imagePath.c_str());
                    }
                    break;
                }
            }
        }

        // Signature
        if (!event.isImageSigned) {
            score += ProcessMonitorConstants::UNSIGNED_EXECUTABLE_SCORE;
            if (cfg.blockUnsigned) score += 100.0;
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
        if (Utils::StringUtils::IEquals(parent.imageName, L"services.exe")) {
             if (ClassifyLOLBAS(child.imageFileName) == LOLBASType::Cmd ||
                ClassifyLOLBAS(child.imageFileName) == LOLBASType::PowerShell) {
                patterns.push_back(SuspiciousPattern::ServicesSpawnsShell);
            }
        }

        // 3. Svchost -> Non-Service
        if (Utils::StringUtils::IEquals(parent.imageName, L"svchost.exe")) {
            // Svchost normally spawns other system services or COM providers
            // Spawning cmd.exe is very suspicious
            if (ClassifyLOLBAS(child.imageFileName) != LOLBASType::None) {
                patterns.push_back(SuspiciousPattern::SvchostSpawnsUnexpected);
            }
        }

        // 4. WMI provider -> shell / scripting host
        if (Utils::StringUtils::IEquals(parent.imageName, L"wmiprvse.exe")) {
            if (ClassifyLOLBAS(child.imageFileName) == LOLBASType::Cmd ||
                ClassifyLOLBAS(child.imageFileName) == LOLBASType::PowerShell ||
                IsScriptInterpreter(child.imageFileName)) {
                patterns.push_back(SuspiciousPattern::WmiSpawnsProcess);
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
        const std::wstring leafName =
            std::filesystem::path(imageName).filename().wstring().empty()
                ? imageName
                : std::filesystem::path(imageName).filename().wstring();

        if (Utils::StringUtils::IEquals(leafName, L"cmd.exe"))         return LOLBASType::Cmd;
        if (Utils::StringUtils::IEquals(leafName, L"powershell.exe"))  return LOLBASType::PowerShell;
        if (Utils::StringUtils::IEquals(leafName, L"pwsh.exe"))        return LOLBASType::PowerShell;
        if (Utils::StringUtils::IEquals(leafName, L"wscript.exe"))     return LOLBASType::WSH;
        if (Utils::StringUtils::IEquals(leafName, L"cscript.exe"))     return LOLBASType::WSH;
        if (Utils::StringUtils::IEquals(leafName, L"mshta.exe"))       return LOLBASType::Mshta;
        if (Utils::StringUtils::IEquals(leafName, L"regsvr32.exe"))    return LOLBASType::Regsvr32;
        if (Utils::StringUtils::IEquals(leafName, L"rundll32.exe"))    return LOLBASType::Rundll32;
        if (Utils::StringUtils::IEquals(leafName, L"certutil.exe"))    return LOLBASType::Certutil;
        if (Utils::StringUtils::IEquals(leafName, L"bitsadmin.exe"))   return LOLBASType::Bitsadmin;
        if (Utils::StringUtils::IEquals(leafName, L"wmic.exe"))        return LOLBASType::Wmic;
        if (Utils::StringUtils::IEquals(leafName, L"msiexec.exe"))     return LOLBASType::Msiexec;
        if (Utils::StringUtils::IEquals(leafName, L"expand.exe"))      return LOLBASType::Expand;
        if (Utils::StringUtils::IEquals(leafName, L"esentutl.exe"))    return LOLBASType::Esentutl;
        if (Utils::StringUtils::IEquals(leafName, L"installutil.exe")) return LOLBASType::InstallUtil;
        if (Utils::StringUtils::IEquals(leafName, L"msbuild.exe"))     return LOLBASType::MSBuild;
        if (Utils::StringUtils::IEquals(leafName, L"odbcconf.exe"))    return LOLBASType::ODBCConf;
        if (Utils::StringUtils::IEquals(leafName, L"regasm.exe"))      return LOLBASType::RegAsm;
        if (Utils::StringUtils::IEquals(leafName, L"regsvcs.exe"))     return LOLBASType::RegSvcs;
        if (Utils::StringUtils::IEquals(leafName, L"xwizard.exe"))     return LOLBASType::XWizard;
        if (Utils::StringUtils::IEquals(leafName, L"forfiles.exe"))    return LOLBASType::ForFiles;
        if (Utils::StringUtils::IEquals(leafName, L"pcalua.exe"))      return LOLBASType::PcaLua;
        if (Utils::StringUtils::IEquals(leafName, L"cmstp.exe"))       return LOLBASType::Cmstp;
        if (Utils::StringUtils::IEquals(leafName, L"bash.exe"))        return LOLBASType::WSL;
        if (Utils::StringUtils::IEquals(leafName, L"wsl.exe"))         return LOLBASType::WSL;
        return LOLBASType::None;
    }

    bool IsScriptInterpreter(const std::wstring& imageName) const {
        LOLBASType type = ClassifyLOLBAS(imageName);
        return type == LOLBASType::PowerShell || type == LOLBASType::WSH || type == LOLBASType::Mshta || type == LOLBASType::Cmd;
    }

    bool IsOfficeApplication(const std::wstring& imageName) const {
        return Utils::StringUtils::IEquals(imageName, L"winword.exe")  ||
               Utils::StringUtils::IEquals(imageName, L"excel.exe")    ||
               Utils::StringUtils::IEquals(imageName, L"powerpnt.exe") ||
               Utils::StringUtils::IEquals(imageName, L"outlook.exe")  ||
               Utils::StringUtils::IEquals(imageName, L"onenote.exe")  ||
               Utils::StringUtils::IEquals(imageName, L"access.exe")   ||
               Utils::StringUtils::IEquals(imageName, L"msaccess.exe") ||
               Utils::StringUtils::IEquals(imageName, L"mspub.exe");
    }

    bool IsBrowser(const std::wstring& imageName) const {
        return Utils::StringUtils::IEquals(imageName, L"chrome.exe")    ||
               Utils::StringUtils::IEquals(imageName, L"firefox.exe")   ||
               Utils::StringUtils::IEquals(imageName, L"msedge.exe")    ||
               Utils::StringUtils::IEquals(imageName, L"iexplore.exe")  ||
               Utils::StringUtils::IEquals(imageName, L"opera.exe")     ||
               Utils::StringUtils::IEquals(imageName, L"brave.exe");
    }

    ProcessType ClassifyProcessType(const ProcessInfo& info) const {
        if (info.isScriptInterpreter) return ProcessType::ScriptInterpreter;
        if (info.isBrowser)           return ProcessType::Browser;
        if (info.isOfficeApp)         return ProcessType::Office;
        if (Utils::StringUtils::IEquals(info.imageName, L"svchost.exe"))  return ProcessType::Service;
        if (Utils::StringUtils::IEquals(info.imageName, L"services.exe")) return ProcessType::Service;
        if (Utils::StringUtils::IEquals(info.imageName, L"lsass.exe"))    return ProcessType::System;
        if (Utils::StringUtils::IEquals(info.imageName, L"csrss.exe"))    return ProcessType::System;
        if (Utils::StringUtils::IEquals(info.imageName, L"wininit.exe"))  return ProcessType::System;
        if (Utils::StringUtils::IEquals(info.imageName, L"winlogon.exe")) return ProcessType::System;
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
    std::unique_lock lock(m_impl->configMutex);
    m_impl->config = config;
}

ProcessMonitorConfig ProcessCreationMonitor::GetConfig() const {
    std::shared_lock lock(m_impl->configMutex);
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
    if (pid == 0) {
        return std::nullopt;
    }
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
        if (Utils::StringUtils::IEquals(info.userName, userName)) {
            result.push_back(info);
        }
    }
    return result;
}

std::vector<ProcessInfo> ProcessCreationMonitor::GetProcessesByImage(const std::wstring& imageName) const {
    std::vector<ProcessInfo> result;
    std::shared_lock lock(m_impl->processMutex);
    for (const auto& [pid, info] : m_impl->activeProcesses) {
        if (Utils::StringUtils::IEquals(info.imageName, imageName)) {
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
    // Base64 decode: input is a wide string of Base64-ASCII chars
    static constexpr std::string_view kB64Chars =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    std::string narrow;
    narrow.reserve(content.size());
    for (wchar_t wc : content) {
        if (wc < 0x7F && wc > 0x20) narrow.push_back(static_cast<char>(wc));
    }

    // Remove padding
    while (!narrow.empty() && narrow.back() == '=') narrow.pop_back();

    std::vector<uint8_t> decoded;
    decoded.reserve((narrow.size() * 3) / 4);

    uint32_t val = 0;
    int      valb = -8;
    for (char c : narrow) {
        size_t pos = kB64Chars.find(c);
        if (pos == std::string_view::npos) continue;
        val = (val << 6) | static_cast<uint32_t>(pos);
        valb += 6;
        if (valb >= 0) {
            decoded.push_back(static_cast<uint8_t>((val >> valb) & 0xFF));
            valb -= 8;
        }
    }

    // Interpret decoded bytes as UTF-16LE (common for PowerShell -EncodedCommand)
    if (decoded.size() >= 2 && decoded.size() % 2 == 0) {
        std::wstring result;
        result.reserve(decoded.size() / 2);
        for (size_t i = 0; i + 1 < decoded.size(); i += 2) {
            wchar_t wc = static_cast<wchar_t>(
                static_cast<uint16_t>(decoded[i]) |
                (static_cast<uint16_t>(decoded[i + 1]) << 8));
            result.push_back(wc);
        }
        return result;
    }

    // Fall back: interpret as UTF-8
    return Utils::StringUtils::ToWide(
        std::string(decoded.begin(), decoded.end()));
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
    try {
        std::ifstream file(filePath);
        if (!file.is_open()) {
            SS_LOG_ERROR(L"ProcessCreationMonitor",
                L"Failed to open rules file for reading: %ls", filePath.c_str());
            return false;
        }

        nlohmann::json j;
        file >> j;

        if (!j.is_array()) {
            SS_LOG_ERROR(L"ProcessCreationMonitor",
                L"Rules file root must be a JSON array: %ls", filePath.c_str());
            return false;
        }

        std::vector<ProcessPolicyRule> loaded;
        loaded.reserve(j.size());

        for (const auto& item : j) {
            if (!item.is_object()) continue;

            ProcessPolicyRule rule;
            rule.ruleId   = item.value("ruleId",   std::string{});
            rule.name     = Utils::StringUtils::ToWide(item.value("name",    std::string{}));
            rule.enabled  = item.value("enabled",  true);
            rule.priority = item.value("priority", 0u);

            const std::string action = item.value("action", "Block");
            if      (action == "Allow")      rule.action = ProcessVerdict::Allow;
            else if (action == "Monitor")    rule.action = ProcessVerdict::AllowMonitored;
            else if (action == "Suspicious") rule.action = ProcessVerdict::AllowSuspicious;
            else                             rule.action = ProcessVerdict::Block;

            if (item.contains("imagePathPattern") && item["imagePathPattern"].is_string())
                rule.imagePathPattern = Utils::StringUtils::ToWide(item["imagePathPattern"].get<std::string>());
            if (item.contains("imageHash") && item["imageHash"].is_string())
                rule.imageHash = item["imageHash"].get<std::string>();
            if (item.contains("imageNamePattern") && item["imageNamePattern"].is_string())
                rule.imageNamePattern = Utils::StringUtils::ToWide(item["imageNamePattern"].get<std::string>());
            if (item.contains("commandLinePattern") && item["commandLinePattern"].is_string())
                rule.commandLinePattern = Utils::StringUtils::ToWide(item["commandLinePattern"].get<std::string>());

            if (!rule.ruleId.empty())
                loaded.push_back(std::move(rule));
        }

        {
            std::unique_lock lock(m_impl->rulesMutex);
            m_impl->rules = std::move(loaded);
            std::sort(m_impl->rules.begin(), m_impl->rules.end(),
                [](const auto& a, const auto& b) { return a.priority > b.priority; });
        }

        SS_LOG_INFO(L"ProcessCreationMonitor",
            L"Loaded %zu policy rules from: %ls",
            m_impl->rules.size(), filePath.c_str());
        return true;

    } catch (const nlohmann::json::exception& ex) {
        SS_LOG_ERROR(L"ProcessCreationMonitor",
            L"JSON parse error loading rules from %ls: %hs", filePath.c_str(), ex.what());
        return false;
    } catch (const std::exception& ex) {
        SS_LOG_ERROR(L"ProcessCreationMonitor",
            L"Exception loading rules from %ls: %hs", filePath.c_str(), ex.what());
        return false;
    }
}

bool ProcessCreationMonitor::SaveRulesToFile(const std::wstring& filePath) const {
    try {
        nlohmann::json j = nlohmann::json::array();

        {
            std::shared_lock lock(m_impl->rulesMutex);
            for (const auto& rule : m_impl->rules) {
                std::string action;
                switch (rule.action) {
                    case ProcessVerdict::Allow:           action = "Allow";      break;
                    case ProcessVerdict::AllowMonitored:  action = "Monitor";    break;
                    case ProcessVerdict::AllowSuspicious: action = "Suspicious"; break;
                    default:                              action = "Block";      break;
                }
                nlohmann::json item;
                item["ruleId"]   = rule.ruleId;
                item["name"]     = Utils::StringUtils::ToNarrow(rule.name);
                item["enabled"]  = rule.enabled;
                item["priority"] = rule.priority;
                item["action"]   = action;

                if (rule.imagePathPattern)
                    item["imagePathPattern"]   = Utils::StringUtils::ToNarrow(*rule.imagePathPattern);
                if (rule.imageHash)
                    item["imageHash"]          = *rule.imageHash;
                if (rule.imageNamePattern)
                    item["imageNamePattern"]   = Utils::StringUtils::ToNarrow(*rule.imageNamePattern);
                if (rule.commandLinePattern)
                    item["commandLinePattern"] = Utils::StringUtils::ToNarrow(*rule.commandLinePattern);

                j.push_back(std::move(item));
            }
        }

        std::ofstream file(filePath);
        if (!file.is_open()) {
            SS_LOG_ERROR(L"ProcessCreationMonitor",
                L"Failed to open rules file for writing: %ls", filePath.c_str());
            return false;
        }
        file << j.dump(2);

        SS_LOG_INFO(L"ProcessCreationMonitor",
            L"Saved %zu policy rules to: %ls",
            m_impl->rules.size(), filePath.c_str());
        return true;

    } catch (const std::exception& ex) {
        SS_LOG_ERROR(L"ProcessCreationMonitor",
            L"Exception saving rules to %ls: %hs", filePath.c_str(), ex.what());
        return false;
    }
}

// Stats
ProcessMonitorStats ProcessCreationMonitor::GetStats() const {
    return m_impl->stats.Snapshot();
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
    std::unique_lock lock(m_impl->integrationMutex);
    m_impl->scanEngine = engine;
}

void ProcessCreationMonitor::SetThreatDetector(Core::Engine::ThreatDetector* detector) {
    std::unique_lock lock(m_impl->integrationMutex);
    m_impl->threatDetector = detector;
}

void ProcessCreationMonitor::SetBehaviorAnalyzer(Core::Engine::BehaviorAnalyzer* analyzer) {
    std::unique_lock lock(m_impl->integrationMutex);
    m_impl->behaviorAnalyzer = analyzer;
}

void ProcessCreationMonitor::SetWhitelistStore(Whitelist::WhitelistStore* store) {
    std::unique_lock lock(m_impl->integrationMutex);
    m_impl->whitelistStore = store;
}

void ProcessCreationMonitor::SetHashStore(HashStore::HashStore* store) {
    std::unique_lock lock(m_impl->integrationMutex);
    m_impl->hashStore = store;
}

void ProcessCreationMonitor::SetThreatIntelIndex(ThreatIntel::ThreatIntelIndex* index) {
    std::unique_lock lock(m_impl->integrationMutex);
    m_impl->threatIntelIndex = index;
}

// Utility Implementations
std::wstring GetProcessImageName(const std::wstring& imagePath) noexcept {
    try {
        std::filesystem::path p(imagePath);
        return p.filename().wstring();
    } catch (...) {
        return {};
    }
}

bool IsScriptInterpreter(const std::wstring& imageName) noexcept {
    LOLBASType t = ProcessCreationMonitor::Instance().ClassifyLOLBAS(imageName);
    return t == LOLBASType::PowerShell || t == LOLBASType::WSH ||
           t == LOLBASType::Mshta      || t == LOLBASType::Cmd;
}

bool IsBrowser(const std::wstring& imageName) noexcept {
    return Utils::StringUtils::IEquals(imageName, L"chrome.exe")   ||
           Utils::StringUtils::IEquals(imageName, L"firefox.exe")  ||
           Utils::StringUtils::IEquals(imageName, L"msedge.exe")   ||
           Utils::StringUtils::IEquals(imageName, L"iexplore.exe") ||
           Utils::StringUtils::IEquals(imageName, L"brave.exe")    ||
           Utils::StringUtils::IEquals(imageName, L"opera.exe");
}

bool IsOfficeApplication(const std::wstring& imageName) noexcept {
    return Utils::StringUtils::IEquals(imageName, L"winword.exe")  ||
           Utils::StringUtils::IEquals(imageName, L"excel.exe")    ||
           Utils::StringUtils::IEquals(imageName, L"powerpnt.exe") ||
           Utils::StringUtils::IEquals(imageName, L"outlook.exe")  ||
           Utils::StringUtils::IEquals(imageName, L"onenote.exe");
}

bool IsInTempFolder(const std::wstring& path) noexcept {
    return ContainsCaseInsensitive(path, L"\\AppData\\Local\\Temp") ||
           ContainsCaseInsensitive(path, L"\\Windows\\Temp")        ||
           ContainsCaseInsensitive(path, L"\\Temp\\")               ||
           ContainsCaseInsensitive(path, L"/tmp/");
}

bool IsInDownloadsFolder(const std::wstring& path) noexcept {
    return ContainsCaseInsensitive(path, L"\\Downloads\\");
}

bool IsNetworkPath(const std::wstring& path) noexcept {
    return path.starts_with(L"\\\\") || path.starts_with(L"//");
}

bool ContainsBase64(const std::wstring& str) noexcept {
    return ContainsBase64Blob(str);
}

std::vector<std::string> ExtractURLsFromCommandLine(const std::wstring& cmdLine) noexcept {
    return ExtractURLsFromCmdLine(cmdLine);
}

// GetProcessChainString implementation
std::wstring ProcessTreeNode::GetProcessChainString() const {
    std::wstring result;
    result.reserve(ancestorPath.size() * 10 + 32);
    for (uint32_t pid : ancestorPath) {
        result += std::to_wstring(pid);
        result += L" -> ";
    }
    result += std::to_wstring(process.processId);
    if (!process.imageName.empty()) {
        result += L" (";
        result += process.imageName;
        result += L")";
    }
    return result;
}

// Pause / Resume
void ProcessCreationMonitor::Pause() {
    const bool wasRunning = m_impl->isRunning.exchange(false, std::memory_order_acq_rel);
    if (wasRunning) {
        SS_LOG_INFO(L"ProcessCreationMonitor", L"Monitoring paused");
    }
}

void ProcessCreationMonitor::Resume() {
    if (!m_impl->isInitialized.load(std::memory_order_acquire)) return;
    const bool wasPaused = !m_impl->isRunning.exchange(true, std::memory_order_acq_rel);
    if (wasPaused) {
        SS_LOG_INFO(L"ProcessCreationMonitor", L"Monitoring resumed");
    }
}

} // namespace RealTime
} // namespace ShadowStrike
