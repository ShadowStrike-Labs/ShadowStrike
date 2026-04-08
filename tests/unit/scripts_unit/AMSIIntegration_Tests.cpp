/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * Unit coverage for deterministic AMSIIntegration contracts.
 *
 * Focus:
 *   - helper-name and malicious-classification contracts
 *   - JSON/state serialization for public DTOs
 *   - configuration/statistics guardrails
 *   - pre-initialization behavior that must fail safely
 */

#include "pch.h"

#include <gtest/gtest.h>

#include <chrono>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

#include "../../../src/Shared_modules/Scripts/AMSIIntegration.hpp"

namespace ShadowStrike::Scripts::Test {
namespace {

using nlohmann::json;

class AMSIIntegrationTest : public ::testing::Test {
protected:
    void SetUp() override {
        AMSIIntegration::Instance().Shutdown();
    }

    void TearDown() override {
        AMSIIntegration::Instance().Shutdown();
    }
};

}  // namespace

TEST_F(AMSIIntegrationTest, HelperNamesAndMaliciousClassificationRemainStable) {
    EXPECT_EQ(GetAmsiResultName(AmsiResult::Clean), "Clean");
    EXPECT_EQ(GetAmsiContentTypeName(AmsiContentType::PowerShell), "PowerShell");
    EXPECT_EQ(GetAmsiBypassTechniqueName(AmsiBypassTechnique::MemoryProtectionChange),
              "MemoryProtectionChange");
    EXPECT_EQ(GetAmsiIntegrityStatusName(AmsiIntegrityStatus::Repaired), "Repaired");
    EXPECT_EQ(GetAmsiResultName(static_cast<AmsiResult>(0x12345678)), "Unknown");
    EXPECT_EQ(GetAmsiContentTypeName(static_cast<AmsiContentType>(0x12345678)), "Unknown");
    EXPECT_EQ(GetAmsiBypassTechniqueName(static_cast<AmsiBypassTechnique>(0x12345678)),
              "Unknown");
    EXPECT_EQ(GetAmsiIntegrityStatusName(static_cast<AmsiIntegrityStatus>(0x12345678)),
              "Unknown");

    EXPECT_FALSE(IsAmsiResultMalicious(AmsiResult::Clean));
    EXPECT_FALSE(IsAmsiResultMalicious(AmsiResult::BlockedByAdminStart));
    EXPECT_TRUE(IsAmsiResultMalicious(AmsiResult::Detected));
}

TEST_F(AMSIIntegrationTest, ConfigurationValidationAndDtoSerializationStayActionable) {
    AMSIConfiguration config;
    EXPECT_TRUE(config.IsValid());

    config.maxContentSize = 0;
    EXPECT_FALSE(config.IsValid());

    config = {};
    config.maxContentSize = AMSIConstants::MAX_SCAN_CONTENT_SIZE + 1;
    EXPECT_FALSE(config.IsValid());

    config = {};
    config.integrityCheckIntervalMs = 999;
    EXPECT_FALSE(config.IsValid());

    config = {};
    config.maxContentSize = AMSIConstants::MAX_SCAN_CONTENT_SIZE;
    EXPECT_TRUE(config.IsValid());

    config = {};
    config.integrityCheckIntervalMs = 1000;
    EXPECT_TRUE(config.IsValid());

    const auto now = std::chrono::system_clock::now();

    AmsiSessionInfo session;
    session.sessionId = 42;
    session.sessionHandle = 0x1234;
    session.processId = 1337;
    session.applicationName = L"PowerShell \"Host\"";
    session.contentType = AmsiContentType::PowerShell;
    session.scanCount = 5;
    session.detectionCount = 2;
    session.startTime = now;
    session.lastActivityTime = now;
    session.isActive = false;

    const json sessionJson = json::parse(session.ToJson());
    EXPECT_EQ(sessionJson.at("sessionId"), 42);
    EXPECT_EQ(sessionJson.at("processId"), 1337);
    EXPECT_EQ(sessionJson.at("applicationName"), "PowerShell \"Host\"");
    EXPECT_FALSE(sessionJson.at("isActive").get<bool>());

    AmsiScanResponse response;
    response.result = AmsiResult::Detected;
    response.isMalicious = true;
    response.threatName = "AMSI.Test";
    response.riskScore = 97.5;
    response.matchedSignatures = {"sig-a", "sig-b"};
    response.contentHash = "deadbeef";
    response.scanDuration = std::chrono::microseconds(250);
    response.timestamp = now;

    const json responseJson = json::parse(response.ToJson());
    EXPECT_EQ(responseJson.at("result"), static_cast<uint32_t>(AmsiResult::Detected));
    EXPECT_TRUE(responseJson.at("isMalicious").get<bool>());
    EXPECT_EQ(responseJson.at("matchedSignatures").size(), 2u);
    EXPECT_EQ(responseJson.at("contentHash"), "deadbeef");

    AmsiBypassEvent bypass;
    bypass.eventId = "evt-1";
    bypass.processId = 5150;
    bypass.threadId = 12;
    bypass.processName = L"powershell.exe";
    bypass.processPath = LR"(C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe)";
    bypass.techniques = AmsiBypassTechnique::ReflectionBypass | AmsiBypassTechnique::DLLHijacking;
    bypass.targetFunction = "AmsiScanBuffer";
    bypass.targetAddress = 0x1000;
    bypass.originalBytes = {0x90, 0xC3};
    bypass.patchedBytes = {0x31, 0xC0};
    bypass.wasRepaired = true;
    bypass.repairSuccessful = false;
    bypass.details = "tamper attempt";
    bypass.timestamp = now;

    const json bypassJson = json::parse(bypass.ToJson());
    EXPECT_EQ(bypassJson.at("eventId"), "evt-1");
    EXPECT_EQ(bypassJson.at("processName"), "powershell.exe");
    EXPECT_EQ(bypassJson.at("targetFunction"), "AmsiScanBuffer");
    EXPECT_EQ(bypassJson.at("originalBytes"), "90c3");
    EXPECT_TRUE(bypassJson.at("wasRepaired").get<bool>());
    EXPECT_FALSE(bypassJson.at("repairSuccessful").get<bool>());

    AmsiIntegrityReport report;
    report.processId = 2024;
    report.status = AmsiIntegrityStatus::Tampered;
    report.amsiDllBase = 0x70000000;
    report.amsiDllSize = 4096;
    report.amsiDllHash = "actual";
    report.expectedHash = "expected";
    report.detectedBypasses = AmsiBypassTechnique::AmsiScanBufferPatch;
    report.timestamp = now;
    report.functionStates.push_back({
        "AmsiScanBuffer",
        0x70000100,
        false,
        {0x31, 0xC0},
        {0x4C, 0x8B}
    });

    const json reportJson = json::parse(report.ToJson());
    ASSERT_EQ(reportJson.at("functionStates").size(), 1u);
    EXPECT_EQ(reportJson.at("status"), static_cast<int>(AmsiIntegrityStatus::Tampered));
    EXPECT_EQ(reportJson.at("functionStates")[0].at("functionName"), "AmsiScanBuffer");
    EXPECT_FALSE(reportJson.at("functionStates")[0].at("isIntact").get<bool>());
}

TEST_F(AMSIIntegrationTest, StatisticsResetAndSnapshotJsonClearCounters) {
    AMSIStatistics stats;
    stats.totalScans.store(10);
    stats.maliciousDetected.store(4);
    stats.cleanResults.store(6);
    stats.sessionsCreated.store(3);
    stats.bypassAttemptsDetected.store(2);
    stats.bypassesRepaired.store(1);
    stats.integrityChecks.store(8);
    stats.integrityFailures.store(2);
    stats.totalBytesScanned.store(4096);
    stats.cacheHits.store(7);
    stats.cacheMisses.store(5);
    stats.byContentType[static_cast<size_t>(AmsiContentType::PowerShell)].store(9);

    stats.Reset();

    EXPECT_EQ(stats.totalScans.load(), 0u);
    EXPECT_EQ(stats.maliciousDetected.load(), 0u);
    EXPECT_EQ(stats.cleanResults.load(), 0u);
    EXPECT_EQ(stats.sessionsCreated.load(), 0u);
    EXPECT_EQ(stats.bypassAttemptsDetected.load(), 0u);
    EXPECT_EQ(stats.totalBytesScanned.load(), 0u);
    EXPECT_EQ(stats.byContentType[static_cast<size_t>(AmsiContentType::PowerShell)].load(), 0u);

    AMSIStatisticsSnapshot snapshot;
    snapshot.totalScans = 11;
    snapshot.maliciousDetected = 2;
    snapshot.cleanResults = 9;
    snapshot.sessionsCreated = 3;
    snapshot.bypassAttemptsDetected = 1;
    snapshot.bypassesRepaired = 1;
    snapshot.integrityChecks = 7;
    snapshot.integrityFailures = 1;
    snapshot.totalBytesScanned = 8192;
    snapshot.cacheHits = 4;
    snapshot.cacheMisses = 6;
    snapshot.startTime = Clock::now() - std::chrono::milliseconds(25);

    const json snapshotJson = json::parse(snapshot.ToJson());
    EXPECT_EQ(snapshotJson.at("totalScans"), 11);
    EXPECT_EQ(snapshotJson.at("cacheMisses"), 6);
    EXPECT_GE(snapshotJson.at("uptimeMs").get<int64_t>(), 0);
}

TEST_F(AMSIIntegrationTest, InvalidInitializationAndPreInitOperationsFailSafely) {
    auto& amsi = AMSIIntegration::Instance();

    AMSIConfiguration invalidConfig;
    invalidConfig.maxContentSize = 0;
    EXPECT_FALSE(amsi.Initialize(invalidConfig));
    EXPECT_FALSE(amsi.IsInitialized());

    EXPECT_FALSE(amsi.UpdateConfiguration(invalidConfig));
    EXPECT_EQ(amsi.GetStatus(), ModuleStatus::Stopped);
    EXPECT_EQ(amsi.GetProviderStatus(), ProviderStatus::Unregistered);
    EXPECT_EQ(amsi.ScanString(L"Write-Host 'hello'", L"sample.ps1", AmsiContentType::PowerShell),
              AmsiResult::Unknown);
    EXPECT_EQ(amsi.OpenSession(L"PowerShell", 9001), 0u);
    EXPECT_TRUE(amsi.GetSessionInfo(1).has_value() == false);
    EXPECT_TRUE(amsi.GetActiveSessions().empty());
    EXPECT_TRUE(amsi.GetRecentBypassEvents(0).empty());
    EXPECT_TRUE(amsi.GetRecentBypassEvents(5).empty());

    amsi.ResetStatistics();
    const auto snapshot = amsi.GetStatistics();
    EXPECT_EQ(snapshot.totalScans, 0u);
    EXPECT_EQ(snapshot.sessionsCreated, 0u);
}

}  // namespace ShadowStrike::Scripts::Test
