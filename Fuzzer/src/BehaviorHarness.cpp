/*
 * ShadowStrike behavior-analysis fuzz harness.
 */

#include "ShadowStrike/Fuzzer/Harnesses/BehaviorHarness.hpp"

#include "ShadowStrike/Fuzzer/Core/FuzzLoop.hpp"

#include "Core/Engine/BehaviorAnalyzer.hpp"
#include "Core/Process/ProcessInjectionDetector.hpp"
#include "Core/Registry/PersistenceDetector.hpp"
#include "RansomwareProtection/RansomwareDetector.hpp"
#include "RealTime/BehaviorBlocker.hpp"
#include "ThreatIntel/ThreatIntelIndex.hpp"
#include "Whitelist/WhiteListStore.hpp"

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
#include <iomanip>
#include <iostream>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace ShadowStrike::Fuzzer {
namespace {

namespace SSBehavior = ShadowStrike::Core::Engine;
namespace SSBlocker = ShadowStrike::RealTime;

constexpr size_t kMaxInputBytes = 4096;
constexpr uint32_t kFuzzPid = 4242;
constexpr uint32_t kParentPid = 401;
constexpr uint32_t kTargetPid = 504;
std::atomic<uint64_t> g_tempRuleSequence{0};
constexpr unsigned long kSehSuccess = 0UL;
constexpr unsigned long kSehInvalidParameter = 0xC000000DUL;

SRWLOCK& HarnessLock() noexcept {
    static SRWLOCK lock = SRWLOCK_INIT;
    return lock;
}

void ResetBehaviorTargetsNoexcept() noexcept {
    try {
        auto& blocker = SSBlocker::BehaviorBlocker::Instance();
        blocker.Stop();
        blocker.Shutdown();
    }
    catch (...) {
    }

    try {
        SSBehavior::BehaviorAnalyzer::Instance().Shutdown();
    }
    catch (...) {
    }
}

std::string ExceptionCodeToStringInternal(const DWORD code) {
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

void CaptureFirstIssue(HarnessResult& result, std::string_view message) {
    if (result.errorMessage.empty()) {
        result.errorMessage.assign(message.data(), message.size());
    }
}

void RecordValidationIssue(HarnessResult& result, std::string_view message) {
    ++result.validationIssueCount;
    CaptureFirstIssue(result, message);
}

void RecordAnomaly(HarnessResult& result, std::string_view message) {
    ++result.anomalyCount;
    CaptureFirstIssue(result, message);
}

void FinalizeLaneResult(HarnessResult& result) {
    result.parsedOk = (result.validationIssueCount == 0);
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

[[nodiscard]] uint16_t ReadU16(std::span<const uint8_t> input, size_t offset, uint16_t fallback) noexcept {
    if (offset + sizeof(uint16_t) > input.size()) {
        return fallback;
    }

    return static_cast<uint16_t>(
        (static_cast<uint16_t>(input[offset]) << 8) |
        static_cast<uint16_t>(input[offset + 1]));
}

[[nodiscard]] uint32_t ReadU32(std::span<const uint8_t> input, size_t offset, uint32_t fallback) noexcept {
    if (offset + sizeof(uint32_t) > input.size()) {
        return fallback;
    }

    return (static_cast<uint32_t>(input[offset]) << 24) |
           (static_cast<uint32_t>(input[offset + 1]) << 16) |
           (static_cast<uint32_t>(input[offset + 2]) << 8) |
           static_cast<uint32_t>(input[offset + 3]);
}

[[nodiscard]] std::string SanitizedAscii(std::span<const uint8_t> input, std::string_view fallback) {
    std::string value;
    value.reserve(std::min<size_t>(input.size(), 32));

    for (const uint8_t byte : input) {
        const char ch = static_cast<char>(byte & 0x7F);
        if ((ch >= 'a' && ch <= 'z') ||
            (ch >= 'A' && ch <= 'Z') ||
            (ch >= '0' && ch <= '9')) {
            value.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(ch))));
        } else if (ch == '-' || ch == '_' || ch == '.') {
            value.push_back(ch == '_' ? '-' : ch);
        }

        if (value.size() == 32) {
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

[[nodiscard]] std::wstring WidePathFromBytes(
    std::span<const uint8_t> input,
    std::wstring_view baseName,
    std::wstring_view extension)
{
    std::wstring suffix;
    suffix.reserve(std::min<size_t>(input.size(), 12));

    for (const uint8_t byte : input) {
        const wchar_t ch = static_cast<wchar_t>(L'a' + (byte % 26u));
        suffix.push_back(ch);
        if (suffix.size() == 12) {
            break;
        }
    }

    if (suffix.empty()) {
        suffix = L"default";
    }

    std::wstring path = L"C:\\Users\\Public\\";
    path.append(baseName);
    path.push_back(L'_');
    path.append(suffix);
    path.append(extension);
    return path;
}

[[nodiscard]] std::string DomainFromBytes(std::span<const uint8_t> input, std::string_view fallbackLabel) {
    std::string label = SanitizedAscii(input, fallbackLabel);
    label.erase(std::remove(label.begin(), label.end(), '.'), label.end());
    if (label.empty()) {
        label = "shadow";
    }

    return label + ".example";
}

SSBehavior::BehaviorEvent FinalizeEvent(
    SSBehavior::BehaviorEvent event,
    std::wstring_view processName) noexcept
{
    if (event.processId == 0) {
        event.processId = kFuzzPid;
    }

    event.parentProcessId = kParentPid;
    if (event.processName.empty()) {
        event.processName.assign(processName);
    }
    if (event.processPath.empty()) {
        event.processPath = L"C:\\Users\\Public\\payload.exe";
    }
    if (event.commandLine.empty()) {
        event.commandLine = L"payload.exe /fuzz";
    }
    if (event.userSid.empty()) {
        event.userSid = L"S-1-5-21-1234";
    }
    if (event.timestamp == std::chrono::steady_clock::time_point{}) {
        event.timestamp = std::chrono::steady_clock::now();
    }
    if (event.systemTime == std::chrono::system_clock::time_point{}) {
        event.systemTime = std::chrono::system_clock::now();
    }
    event.success = true;
    return event;
}

[[nodiscard]] SSBehavior::BehaviorAnalyzerConfig BuildAnalyzerConfig(std::span<const uint8_t> input) {
    SSBehavior::BehaviorAnalyzerConfig config = SSBehavior::BehaviorAnalyzerConfig::CreateHighSensitivity();
    config.autoTerminateOnCritical = true;
    config.autoSuspendOnBlock = true;
    config.logAllEvents = false;
    config.verboseLogging = false;
    config.maxTrackedProcesses = 64;
    config.maxEventsPerProcess = 64;
    config.canaryFilePaths = {
        WidePathFromBytes(TailBytes(input, 0), L"shadow_canary", L".docx"),
        WidePathFromBytes(TailBytes(input, 8), L"shadow_decoy", L".xlsx")
    };
    return config;
}

[[nodiscard]] bool PrepareAnalyzer(std::span<const uint8_t> input, HarnessResult& result) {
    auto& analyzer = SSBehavior::BehaviorAnalyzer::Instance();
    analyzer.Shutdown();

    const auto config = BuildAnalyzerConfig(input);
    if (!analyzer.Initialize({}, config, nullptr, nullptr)) {
        RecordValidationIssue(result, "BehaviorAnalyzer initialization failed.");
        return false;
    }

    static ShadowStrike::ThreatIntel::ThreatIntelIndex threatIntelIndex;
    static ShadowStrike::Whitelist::WhitelistStore whitelistStore;

    analyzer.SetThreatIntelIndex(&threatIntelIndex);
    analyzer.SetWhitelistStore(&whitelistStore);
    analyzer.SetSignatureStore(nullptr);
    analyzer.SetRansomwareDetector(&ShadowStrike::Ransomware::RansomwareDetector::Instance());
    analyzer.SetInjectionDetector(&ShadowStrike::Core::Process::ProcessInjectionDetector::Instance());
    analyzer.SetPersistenceDetector(&ShadowStrike::Core::Registry::PersistenceDetector::Instance());
    analyzer.SetTerminationCallback([](uint32_t, const std::wstring&) { return true; });
    analyzer.ResetStats();
    analyzer.ClearAllStates();
    return true;
}

[[nodiscard]] SSBlocker::BehaviorBlockerConfig BuildBlockerConfig() {
    SSBlocker::BehaviorBlockerConfig config = SSBlocker::BehaviorBlockerConfig::CreateDefault();
    config.maxRules = 128;
    config.maxExclusions = 64;
    config.maxHistoryEvents = 256;
    config.regexMaxInputLength = 1024;
    return config;
}

[[nodiscard]] bool PrepareBlocker(HarnessResult& result) {
    auto& blocker = SSBlocker::BehaviorBlocker::Instance();
    blocker.Shutdown();

    if (!blocker.Initialize(BuildBlockerConfig())) {
        RecordValidationIssue(result, "BehaviorBlocker initialization failed.");
        return false;
    }

    if (!blocker.Start()) {
        RecordValidationIssue(result, "BehaviorBlocker start failed.");
        blocker.Shutdown();
        return false;
    }

    return true;
}

bool ExerciseAnalyzerRansomware(
    const std::span<const uint8_t> input,
    HarnessResult& result)
{
    if (!PrepareAnalyzer(input, result)) {
        return false;
    }
    auto& analyzer = SSBehavior::BehaviorAnalyzer::Instance();

    uint32_t verdictCallbacks = 0;
    uint32_t chainCallbacks = 0;
    const uint64_t verdictCallbackId = analyzer.RegisterVerdictCallback(
        [&verdictCallbacks](const SSBehavior::BehaviorVerdict&) { ++verdictCallbacks; });
    const uint64_t chainCallbackId = analyzer.RegisterAttackChainCallback(
        [&chainCallbacks](const SSBehavior::BehaviorAttackChain&) { ++chainCallbacks; });

    const auto seedA = TailBytes(input, 1);
    const auto seedB = TailBytes(input, 9);
    const std::wstring canaryPath = analyzer.GetCanaryFiles().empty()
        ? WidePathFromBytes(seedA, L"shadow_canary", L".docx")
        : analyzer.GetCanaryFiles().front();

    auto fileWrite = FinalizeEvent(
        SSBehavior::CreateFileEvent(
            SSBehavior::BehaviorEventType::FileWrite,
            kFuzzPid,
            WidePathFromBytes(seedA, L"finance", L".docx"),
            true),
        L"payload.exe");
    fileWrite.fileEntropy = 7.95;
    fileWrite.fileSize = 8192 + ReadU16(seedA, 0, 0);
    fileWrite.scoreContribution = 18.0;
    (void)analyzer.ProcessEvent(fileWrite);

    auto rename = FinalizeEvent(
        SSBehavior::CreateFileEvent(
            SSBehavior::BehaviorEventType::FileRename,
            kFuzzPid,
            WidePathFromBytes(seedB, L"finance", L".locked"),
            true),
        L"payload.exe");
    rename.previousPath = fileWrite.targetPath;
    rename.fileEntropy = 7.8;
    rename.scoreContribution = 24.0;
    (void)analyzer.ProcessEvent(rename);

    auto canaryTouch = FinalizeEvent(
        SSBehavior::CreateFileEvent(
            SSBehavior::BehaviorEventType::FileWrite,
            kFuzzPid,
            canaryPath,
            true),
        L"payload.exe");
    canaryTouch.fileEntropy = 7.7;
    canaryTouch.scoreContribution = 30.0;
    const auto verdict = analyzer.ProcessEvent(canaryTouch);

    auto cleanupEvent = FinalizeEvent(
        SSBehavior::CreateProcessEvent(
            SSBehavior::BehaviorEventType::ProcessTerminate,
            kFuzzPid),
        L"payload.exe");
    (void)analyzer.ProcessEvent(cleanupEvent);

    const auto tracked = analyzer.GetTrackedProcessIds();
    const auto thresholdHits = analyzer.GetProcessesAboveThreshold(10.0);
    const auto chains = analyzer.GetAttackChainsForProcess(kFuzzPid);
    const auto state = analyzer.GetProcessState(kFuzzPid);
    const auto stats = analyzer.GetStats();

    analyzer.UnregisterVerdictCallback(verdictCallbackId);
    analyzer.UnregisterAttackChainCallback(chainCallbackId);

    if (tracked.size() > 8) {
        RecordAnomaly(result, "BehaviorAnalyzer tracked too many processes in ransomware lane.");
    }
    if (state.processId != 0 && state.processId != kFuzzPid) {
        RecordAnomaly(result, "BehaviorAnalyzer returned unexpected process state.");
    }
    if (!verdict.has_value() && verdictCallbacks == 0 && thresholdHits.empty() && chains.empty()) {
        RecordValidationIssue(result, "BehaviorAnalyzer ransomware lane produced no observable state transition.");
    }
    if (stats.totalEventsProcessed == 0) {
        RecordValidationIssue(result, "BehaviorAnalyzer statistics were not updated.");
    }

    FinalizeLaneResult(result);
    return true;
}

bool ExerciseAnalyzerNetworkAndInjection(
    const std::span<const uint8_t> input,
    HarnessResult& result)
{
    if (!PrepareAnalyzer(input, result)) {
        return false;
    }
    auto& analyzer = SSBehavior::BehaviorAnalyzer::Instance();

    analyzer.SetProcessScoreModifier(kFuzzPid, static_cast<double>(input.empty() ? 0 : (input[0] % 12u)));
    analyzer.WhitelistProcess(9001);
    analyzer.UnwhitelistProcess(9001);

    std::vector<SSBehavior::BehaviorEvent> batch;
    batch.reserve(4);

    auto network = FinalizeEvent(
        SSBehavior::CreateNetworkEvent(
            SSBehavior::BehaviorEventType::NetworkUpload,
            kFuzzPid,
            DomainFromBytes(TailBytes(input, 2), "beacon"),
            static_cast<uint16_t>(443u + (ReadU16(input, 0, 0) % 2048u)),
            "HTTPS"),
        L"powershell.exe");
    network.bytesSent = 512 * 1024 + ReadU32(input, 4, 0);
    network.bytesReceived = ReadU16(input, 10, 0);
    network.commandLine = L"powershell.exe -enc ZmFrZQ==";
    batch.push_back(network);

    auto dns = FinalizeEvent(network, L"powershell.exe");
    dns.eventType = SSBehavior::BehaviorEventType::NetworkDNSQuery;
    dns.remotePort = 53;
    dns.protocol = "DNS";
    dns.bytesSent = 96;
    dns.bytesReceived = 128;
    batch.push_back(dns);

    SSBehavior::BehaviorEvent inject = FinalizeEvent(
        SSBehavior::CreateProcessEvent(
            SSBehavior::BehaviorEventType::ProcessInject,
            kFuzzPid,
            kTargetPid),
        L"powershell.exe");
    inject.commandLine = L"powershell.exe -nop -w hidden";
    inject.targetAddress = 0x100000 + ReadU32(input, 8, 0);
    inject.targetSize = 4096 + (ReadU16(input, 12, 0) % 4096u);
    inject.accessMask = 0x1FFFFFu;
    batch.push_back(inject);

    SSBehavior::BehaviorEvent remoteWrite = FinalizeEvent(inject, L"powershell.exe");
    remoteWrite.category = SSBehavior::BehaviorEventCategory::Memory;
    remoteWrite.eventType = SSBehavior::BehaviorEventType::MemoryRemoteWrite;
    remoteWrite.targetProcessId = kTargetPid;
    remoteWrite.targetSize = 2048;
    batch.push_back(remoteWrite);

    const auto verdicts = analyzer.ProcessEventBatch(batch);
    const auto eval = analyzer.EvaluateProcess(kFuzzPid);
    const auto state = analyzer.GetProcessState(kFuzzPid);
    const auto activeChains = analyzer.GetActiveAttackChains();

    if (state.processId != 0 && state.processId != kFuzzPid) {
        RecordAnomaly(result, "BehaviorAnalyzer injection lane returned mismatched process state.");
    }
    if (state.targetedProcessIds.size() > 16) {
        RecordAnomaly(result, "BehaviorAnalyzer recorded an unexpectedly large target set.");
    }
    if (verdicts.empty() && eval.maliceScore <= 0.0 && activeChains.empty()) {
        RecordValidationIssue(result, "BehaviorAnalyzer network/injection lane produced no analyzable output.");
    }

    FinalizeLaneResult(result);
    return true;
}

bool ExerciseAnalyzerLifecycle(
    const std::span<const uint8_t> input,
    HarnessResult& result)
{
    if (!PrepareAnalyzer(input, result)) {
        return false;
    }
    auto& analyzer = SSBehavior::BehaviorAnalyzer::Instance();

    uint32_t verdictCallbacks = 0;
    const uint64_t verdictCallbackId = analyzer.RegisterVerdictCallback(
        [&verdictCallbacks](const SSBehavior::BehaviorVerdict&) { ++verdictCallbacks; });

    analyzer.AddCanaryFile(WidePathFromBytes(TailBytes(input, 3), L"api_canary", L".txt"));
    const auto canaries = analyzer.GetCanaryFiles();
    if (canaries.empty()) {
        RecordValidationIssue(result, "BehaviorAnalyzer failed to retain canary path.");
    }

    auto persistence = FinalizeEvent(
        SSBehavior::CreateRegistryEvent(
            SSBehavior::BehaviorEventType::RegistrySetValue,
            kFuzzPid,
            L"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            L"ShadowStrike",
            true),
        L"regsvr32.exe");
    persistence.commandLine = L"regsvr32.exe /s payload.dll";
    persistence.targetPath = L"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\ShadowStrike";
    persistence.valueType = REG_SZ;
    persistence.valueData = {
        static_cast<uint8_t>('C'), 0u,
        static_cast<uint8_t>(':'), 0u,
        static_cast<uint8_t>('\\'), 0u,
        static_cast<uint8_t>('T'), 0u,
        static_cast<uint8_t>('e'), 0u,
        static_cast<uint8_t>('m'), 0u,
        static_cast<uint8_t>('p'), 0u,
        0u, 0u
    };
    (void)analyzer.ProcessEvent(persistence);

    const bool asyncAccepted = analyzer.ProcessEventAsync(persistence);
    if (asyncAccepted) {
        RecordAnomaly(result, "BehaviorAnalyzer accepted async processing without a thread pool.");
    }

    const auto preResetState = analyzer.GetProcessState(kFuzzPid);
    const auto preResetStats = analyzer.GetStats();
    if (preResetState.maliceScore <= 0.0 &&
        preResetState.persistenceLocations.empty() &&
        preResetStats.persistenceDetections == 0)
    {
        RecordValidationIssue(result, "BehaviorAnalyzer persistence lane produced no persistence-specific artifacts.");
    }

    analyzer.ResetProcessState(kFuzzPid);
    analyzer.ClearAllStates();
    analyzer.ResetStats();
    analyzer.RemoveCanaryFile(canaries.empty() ? L"" : canaries.front());
    analyzer.UnregisterVerdictCallback(verdictCallbackId);

    if (analyzer.IsProcessTracked(kFuzzPid)) {
        RecordAnomaly(result, "BehaviorAnalyzer retained process state after reset.");
    }
    if (analyzer.GetStats().totalEventsProcessed != 0) {
        RecordAnomaly(result, "BehaviorAnalyzer statistics failed to reset.");
    }
    if (verdictCallbacks > 32) {
        RecordAnomaly(result, "BehaviorAnalyzer emitted an excessive callback volume.");
    }

    FinalizeLaneResult(result);
    return true;
}

[[nodiscard]] SSBlocker::ProcessBehavior BuildBehavior(
    std::span<const uint8_t> input,
    const SSBlocker::BehaviorType type,
    const std::wstring& target,
    const SSBlocker::RiskLevel risk)
{
    SSBlocker::ProcessBehavior behavior;
    behavior.processId = kFuzzPid;
    behavior.parentPid = kParentPid;
    behavior.processPath = L"C:\\Users\\Public\\payload.exe";
    behavior.commandLine = L"payload.exe /behavior";
    behavior.type = type;
    behavior.target = target;
    behavior.risk = risk;
    behavior.sessionId = 1;
    behavior.integrityLevel = 0x2000;
    behavior.correlationId = SanitizedAscii(TailBytes(input, 0), "chain");
    behavior.timestamp = static_cast<int64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count());
    return behavior;
}

[[nodiscard]] SSBlocker::BehaviorRule BuildRule(std::span<const uint8_t> input) {
    SSBlocker::BehaviorRule rule;
    rule.ruleId = "fuzz-rule-" + SanitizedAscii(TailBytes(input, 1), "behavior");
    rule.description = "Fuzzer-generated behavior rule";
    rule.targetType = SSBlocker::BehaviorType::ScriptExecution;
    rule.targetPattern = ".*(powershell|pwsh|wscript|cmd).*";
    rule.minRiskLevel = SSBlocker::RiskLevel::Medium;
    rule.action = (input.size() > 2 && (input[2] & 1u) != 0u)
        ? SSBlocker::BlockAction::SuspendProcess
        : SSBlocker::BlockAction::AlertOnly;
    rule.priority = 60 + static_cast<int32_t>(input.empty() ? 0 : (input[0] % 20u));
    rule.mitreAttackId = "T1059";
    return rule;
}

[[nodiscard]] SSBlocker::BehaviorExclusion BuildExclusion(std::span<const uint8_t> input) {
    SSBlocker::BehaviorExclusion exclusion;
    exclusion.exclusionId = "fuzz-exclusion-" + SanitizedAscii(TailBytes(input, 4), "trusted");
    exclusion.processPathPattern = R"(C:\\Windows\\System32\\.*)";
    exclusion.commandLinePattern = ".*trusted.*";
    exclusion.targetPattern = ".*allowed.*";
    exclusion.description = "Fuzzer-generated exclusion";
    exclusion.behaviorType = SSBlocker::BehaviorType::ScriptExecution;
    return exclusion;
}

bool ExerciseBlockerRuleFlow(
    const std::span<const uint8_t> input,
    HarnessResult& result)
{
    if (!PrepareBlocker(result)) {
        return false;
    }
    auto& blocker = SSBlocker::BehaviorBlocker::Instance();

    uint32_t callbacks = 0;
    const uint64_t callbackId = blocker.RegisterBlockCallback(
        [&callbacks](const SSBlocker::BlockEvent&) { ++callbacks; });

    const auto rule = BuildRule(input);
    const auto exclusion = BuildExclusion(input);
    (void)blocker.AddRule(rule);
    (void)blocker.AddExclusion(exclusion);

    SSBlocker::ProcessBehavior blocked = BuildBehavior(
        input,
        SSBlocker::BehaviorType::ScriptExecution,
        L"powershell.exe -enc AAAA",
        SSBlocker::RiskLevel::High);
    blocked.commandLine = L"powershell.exe -enc AAAA";
    const auto action = blocker.AnalyzeBehavior(blocked);

    blocker.Pause();
    const auto pausedAction = blocker.AnalyzeBehavior(blocked);
    blocker.Resume();

    const auto history = blocker.GetRecentEvents(8);
    const auto stats = blocker.GetStatistics();
    const auto statsJson = blocker.GetStatisticsJson();

    blocker.UnregisterBlockCallback(callbackId);
    (void)blocker.RemoveRule(rule.ruleId);
    (void)blocker.RemoveExclusion(exclusion.exclusionId);

    if (pausedAction != SSBlocker::BlockAction::Allow) {
        RecordAnomaly(result, "BehaviorBlocker did not preserve allow-by-default behavior while paused.");
    }
    if (stats.activeRuleCount > 130 || stats.activeExclusionCount > 65) {
        RecordAnomaly(result, "BehaviorBlocker statistics exceeded configured test bounds.");
    }
    if (statsJson.empty()) {
        RecordValidationIssue(result, "BehaviorBlocker statistics JSON was empty.");
    }
    if (action == SSBlocker::BlockAction::Allow && history.empty() && callbacks == 0) {
        RecordValidationIssue(result, "BehaviorBlocker rule lane produced no observable evaluation artifacts.");
    }

    FinalizeLaneResult(result);
    return true;
}

bool ExerciseBlockerKernelAndControl(
    const std::span<const uint8_t> input,
    HarnessResult& result)
{
    if (!PrepareBlocker(result)) {
        return false;
    }
    auto& blocker = SSBlocker::BehaviorBlocker::Instance();

    uint32_t callbacks = 0;
    const uint64_t callbackId = blocker.RegisterBlockCallback(
        [&callbacks](const SSBlocker::BlockEvent&) { ++callbacks; });

    const uint64_t tempSequence = g_tempRuleSequence.fetch_add(1, std::memory_order_relaxed);
    const auto tempPath = std::filesystem::temp_directory_path() /
        std::filesystem::path(
            "shadowstrike_behavior_rule_" +
            std::to_string(::GetCurrentProcessId()) + "_" +
            std::to_string(tempSequence) + "_" +
            SanitizedAscii(TailBytes(input, 6), "seed") +
            ".json");
    {
        std::ofstream stream(tempPath, std::ios::binary | std::ios::trunc);
        if (!stream) {
            RecordValidationIssue(result, "Failed to create temporary behavior rule file.");
            return false;
        }

        stream << "[{\"ruleId\":\"FUZZ_FILE_1\",\"description\":\"json rule\","
               << "\"targetType\":" << static_cast<unsigned>(SSBlocker::BehaviorType::RegistryModification) << ','
               << "\"targetPattern\":\".*Run.*\","
               << "\"minRiskLevel\":" << static_cast<unsigned>(SSBlocker::RiskLevel::Medium) << ','
               << "\"action\":" << static_cast<unsigned>(SSBlocker::BlockAction::BlockOperation) << ','
               << "\"priority\":55,"
               << "\"enabled\":true,"
               << "\"mitreAttackId\":\"T1547.001\"}]";
    }

    const bool loaded = blocker.LoadRulesFromFile(tempPath);
    std::error_code removeEc;
    std::filesystem::remove(tempPath, removeEc);
    if (removeEc) {
        RecordAnomaly(result, "BehaviorBlocker temporary rule file cleanup failed.");
    }

    std::array<std::byte, sizeof(uint32_t) * 3> payload{};
    const uint32_t pid = kFuzzPid;
    const uint32_t parentPid = kParentPid;
    const uint32_t type = static_cast<uint32_t>(SSBlocker::BehaviorType::ProcessInjection);
    std::memcpy(payload.data(), &pid, sizeof(pid));
    std::memcpy(payload.data() + sizeof(uint32_t), &parentPid, sizeof(parentPid));
    std::memcpy(payload.data() + sizeof(uint32_t) * 2, &type, sizeof(type));
    const auto historyBefore = blocker.GetRecentEvents(16).size();
    blocker.OnKernelBehavioralAlert(1u, payload);
    const auto historyAfter = blocker.GetRecentEvents(16).size();

    const bool pushResult = blocker.PushRulesToKernel();
    const bool manualBlock = blocker.BlockProcess(kFuzzPid + 11u, L"fuzz manual block");
    const bool suspend = blocker.SuspendProcess(kFuzzPid + 12u);
    const bool suspendFailure = blocker.SuspendProcess(kFuzzPid + 13u);
    const bool terminate = blocker.TerminateProcess(kFuzzPid + 13u);
    const bool terminateFailure = blocker.TerminateProcess(kFuzzPid + 12u);
    const bool selfTest = blocker.SelfTest();
    blocker.UnregisterBlockCallback(callbackId);

    if (!loaded) {
        RecordValidationIssue(result, "BehaviorBlocker JSON rule load path rejected harness seed.");
    }
    if (!pushResult) {
        RecordValidationIssue(result, "BehaviorBlocker kernel push path reported failure.");
    }
    if (historyAfter <= historyBefore && callbacks == 0) {
        RecordValidationIssue(result, "BehaviorBlocker kernel-alert path produced no observable rule action.");
    }
    if (!manualBlock || !suspend || !terminate || !selfTest) {
        RecordAnomaly(result, "BehaviorBlocker control success path returned an unexpected failure.");
    }
    if (suspendFailure || terminateFailure) {
        RecordValidationIssue(result, "BehaviorBlocker control failure path did not propagate the expected denial.");
    }

    FinalizeLaneResult(result);
    return true;
}

bool ExerciseBehaviorEndToEnd(
    const std::span<const uint8_t> input,
    HarnessResult& result)
{
    if (!ExerciseAnalyzerRansomware(input, result)) {
        return false;
    }
    if (!ExerciseBlockerRuleFlow(TailBytes(input, 5), result)) {
        return false;
    }
    return true;
}

[[nodiscard]] bool WriteSeed(const std::filesystem::path& path, std::span<const uint8_t> bytes) {
    std::ofstream stream(path, std::ios::binary | std::ios::trunc);
    if (!stream) {
        return false;
    }

    if (!bytes.empty()) {
        stream.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    }
    return stream.good();
}

void EnsureSeedCorpus(const std::filesystem::path& corpusDir) {
    static constexpr std::array<std::pair<std::string_view, std::array<uint8_t, 12>>, 5> seeds{{
        {"seed-analyzer-ransom.bin", {0x00u, 0x91u, 0x23u, 0x41u, 0x52u, 0x63u, 0x74u, 0x85u, 0x96u, 0xA7u, 0xB8u, 0xC9u}},
        {"seed-analyzer-network.bin", {0x01u, 0x10u, 'b', 'e', 'a', 'c', 'o', 'n', 0x44u, 0x55u, 0x66u, 0x77u}},
        {"seed-analyzer-lifecycle.bin", {0x02u, 0x20u, 'r', 'u', 'n', 0x33u, 0x44u, 0x55u, 0x66u, 0x77u, 0x88u, 0x99u}},
        {"seed-blocker-rule.bin", {0x03u, 0x30u, 'p', 's', '1', 0xAAu, 0xBBu, 0xCCu, 0xDDu, 0xEEu, 0x12u, 0x34u}},
        {"seed-blocker-kernel.bin", {0x04u, 0x40u, 'r', 'e', 'g', 0x01u, 0x02u, 0x03u, 0x04u, 0x05u, 0x06u, 0x07u}},
    }};

    for (const auto& [fileName, bytes] : seeds) {
        const auto path = corpusDir / fileName;
        if (std::filesystem::exists(path)) {
            continue;
        }

        (void)WriteSeed(path, bytes);
    }
}

[[nodiscard]] std::optional<std::vector<uint8_t>> ReadFileBytes(const std::filesystem::path& path) {
    std::ifstream stream(path, std::ios::binary);
    if (!stream) {
        return std::nullopt;
    }

    stream.seekg(0, std::ios::end);
    const auto size = stream.tellg();
    if (size < 0) {
        return std::nullopt;
    }

    std::vector<uint8_t> bytes(static_cast<size_t>(size));
    stream.seekg(0, std::ios::beg);
    if (!bytes.empty() &&
        !stream.read(reinterpret_cast<char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()))) {
        return std::nullopt;
    }

    return bytes;
}

}  // namespace

unsigned long BehaviorHarness::SEHCallBehavior(
    const uint8_t* data,
    const size_t size,
    HarnessResult* result) noexcept
{
    if (result == nullptr) {
        return kSehInvalidParameter;
    }

    bool lockHeld = false;
    AcquireSRWLockExclusive(&HarnessLock());
    lockHeld = true;

    __try {
        __try {
            if (!ExerciseBehaviorImpl(data, size, *result)) {
                if (!result->crashed && result->errorMessage.empty()) {
                    result->errorMessage = "Behavior harness reported failure.";
                }
            }
            return kSehSuccess;
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            return static_cast<unsigned long>(GetExceptionCode());
        }
    }
    __finally {
        ResetBehaviorTargetsNoexcept();
        if (lockHeld) {
            ReleaseSRWLockExclusive(&HarnessLock());
        }
    }
}

bool BehaviorHarness::ExerciseBehaviorImpl(
    const uint8_t* data,
    const size_t size,
    HarnessResult& result)
{
    const std::span<const uint8_t> input(
        (data == nullptr || size == 0u) ? nullptr : data,
        (data == nullptr) ? 0u : size);

    const uint8_t selector = input.empty() ? 0u : input[0];

    switch (selector % 5u) {
    case 0u:
        return ExerciseAnalyzerRansomware(input, result);
    case 1u:
        return ExerciseAnalyzerNetworkAndInjection(input, result);
    case 2u:
        return ExerciseAnalyzerLifecycle(input, result);
    case 3u:
        return ExerciseBlockerRuleFlow(input, result);
    default:
        return ExerciseBlockerKernelAndControl(input, result);
    }
}

HarnessResult BehaviorHarness::Run(std::span<const uint8_t> input) noexcept {
    HarnessResult result;

    try {
        const unsigned long sehCode = SEHCallBehavior(
            input.empty() ? nullptr : input.data(),
            std::min(input.size(), kMaxInputBytes),
            &result);
        if (sehCode != kSehSuccess) {
            result.crashed = true;
            result.crashSignal = ExceptionCodeToStringInternal(sehCode);
            if (result.errorMessage.empty()) {
                result.errorMessage = "Behavior harness terminated with a structured exception.";
            }
        }
    }
    catch (const std::exception& ex) {
        result.crashed = true;
        result.crashSignal = "CPP_EXCEPTION";
        result.errorMessage = ex.what();
    }
    catch (...) {
        result.crashed = true;
        result.crashSignal = "CPP_UNKNOWN_EXCEPTION";
    }

    return result;
}

HarnessFunction BehaviorHarness::GetHarnessFunction() noexcept {
    return [](std::span<const uint8_t> input) -> HarnessResult {
        return Run(input);
    };
}

std::string_view BehaviorHarness::GetName() noexcept {
    return "behavior";
}

std::string_view BehaviorHarness::GetDescription() noexcept {
    return "BehaviorAnalyzer and BehaviorBlocker fuzz harness";
}

std::string BehaviorHarness::ExceptionCodeToString(const unsigned long code) {
    return ExceptionCodeToStringInternal(code);
}

int RunBehaviorFuzzer(
    const std::filesystem::path& workspaceDir,
    const FuzzLoopConfig& config) noexcept
{
    if (!InstallCtrlCHandler()) {
        std::cerr << "[BehaviorFuzzer] Warning: Failed to install Ctrl+C handler\n";
    }

    const auto corpusDir = workspaceDir / "corpora" / "behavior";
    const auto crashDir = workspaceDir / "crashes" / "behavior";

    std::error_code ec;
    std::filesystem::create_directories(corpusDir, ec);
    if (ec) {
        std::cerr << "[BehaviorFuzzer] Failed to create corpus directory: " << corpusDir << '\n';
        return 1;
    }

    ec.clear();
    std::filesystem::create_directories(crashDir, ec);
    if (ec) {
        std::cerr << "[BehaviorFuzzer] Failed to create crash directory: " << crashDir << '\n';
        return 1;
    }

    EnsureSeedCorpus(corpusDir);

    static constexpr std::array<std::string_view, 5> kSanitySeeds{
        "seed-analyzer-ransom.bin",
        "seed-analyzer-network.bin",
        "seed-analyzer-lifecycle.bin",
        "seed-blocker-rule.bin",
        "seed-blocker-kernel.bin",
    };

    for (const auto seedName : kSanitySeeds) {
        const auto seedBytes = ReadFileBytes(corpusDir / seedName);
        if (!seedBytes.has_value()) {
            std::cerr << "[BehaviorFuzzer] Failed to read sanity seed: " << seedName << '\n';
            return 1;
        }

        const HarnessResult sanity = BehaviorHarness::Run(*seedBytes);
        if (sanity.crashed || !sanity.parsedOk) {
            std::cerr << "[BehaviorFuzzer] Sanity check failed for " << seedName;
            if (!sanity.errorMessage.empty()) {
                std::cerr << ": " << sanity.errorMessage;
            }
            if (!sanity.crashSignal.empty()) {
                std::cerr << " (" << sanity.crashSignal << ')';
            }
            std::cerr << '\n';
            return 1;
        }
    }

    FuzzLoopConfig loopConfig = config;
    loopConfig.targetName = std::string(BehaviorHarness::GetName());

    std::cout << "[BehaviorFuzzer] Starting behavior-analysis fuzzing...\n";
    std::cout << "[BehaviorFuzzer] Corpus: " << corpusDir << '\n';
    std::cout << "[BehaviorFuzzer] Crashes: " << crashDir << '\n';

    FuzzLoop loop(corpusDir, crashDir, BehaviorHarness::GetHarnessFunction(), loopConfig);
    const bool success = loop.Run();
    const auto& stats = loop.GetStatistics();

    std::cout << "\n[BehaviorFuzzer] Final Results:\n";
    std::cout << "  Total iterations: " << stats.totalIterations << '\n';
    std::cout << "  Unique crashes:   " << stats.uniqueCrashes << '\n';
    std::cout << "  Total crashes:    " << stats.crashesFound << '\n';
    std::cout << "  Final corpus:     " << stats.corpusSize << '\n';
    std::cout << "  Parse success:    " << stats.parseSuccesses << '\n';
    std::cout << "  Parse failure:    " << stats.parseFailures << '\n';
    std::cout << "  Duration:         " << (stats.durationMs / 1000) << "s\n";
    std::cout << "  Speed:            " << std::fixed << std::setprecision(1)
              << stats.iterationsPerSecond << " iter/s\n";

    return success ? 0 : 1;
}

}  // namespace ShadowStrike::Fuzzer
