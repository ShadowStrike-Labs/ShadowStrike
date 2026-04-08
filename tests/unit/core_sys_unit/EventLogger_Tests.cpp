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
 * @file EventLogger_Tests.cpp
 * @brief Comprehensive GTest coverage for Core::System::EventLogger.
 *
 * Coverage focus:
 * - configuration presets and integrity-focused statistics reset behavior
 * - initialization validation, pause/resume control, and callback registration
 * - threat/audit helper logging through the public API surface
 * - forensic capture, retrieval, and path-validation enforcement
 */

#include "pch.h"

#include "CoreSystem_TestUtils.hpp"
#include "../../../src/Shared_modules/Core/System/EventLogger.hpp"

#include <chrono>
#include <future>

namespace {

using namespace std::chrono_literals;
using namespace ShadowStrike::Core::System;
using namespace ShadowStrike::Tests::CoreSystem;
using ::testing::HasSubstr;

class EventLoggerTest : public TempDirectoryFixture {
protected:
    void SetUp() override {
        TempDirectoryFixture::SetUp();
        auto& logger = EventLogger::Instance();
        logger.Resume();
        logger.Shutdown();
    }

    void TearDown() override {
        EventLogger::Instance().Resume();
        EventLogger::Instance().Shutdown();
        TempDirectoryFixture::TearDown();
    }

    [[nodiscard]] EventLoggerConfig MakeEphemeralConfig() const {
        auto config = EventLoggerConfig::CreateDefault();
        config.destinations = static_cast<uint8_t>(LogDestination::None);
        config.allowedLogDirectory = testRoot_.wstring();
        config.enableForensicCapture = true;
        config.forensicBufferSize = 16;
        config.forensicBufferMaxMemoryMB = 8;
        config.workerThreads = 1;
        config.asyncQueueSize = 256;
        config.criticalQueueReserve = 32;
        return config;
    }
};

TEST(EventLoggerValueTests, ConfigFactoriesAndStatisticsResetReflectSecurityPosture) {
    const auto defaults = EventLoggerConfig::CreateDefault();
    const auto enterprise = EventLoggerConfig::CreateEnterprise();
    const auto minimal = EventLoggerConfig::CreateMinimal();

    EXPECT_EQ(defaults.hmacKey.size(), 32u);
    EXPECT_TRUE(defaults.enableTamperProtection);
    EXPECT_TRUE(defaults.enableHashChain);

    EXPECT_EQ(enterprise.destinations, static_cast<uint8_t>(LogDestination::All));
    EXPECT_EQ(enterprise.minimumSeverity, EventSeverity::Debug);
    EXPECT_TRUE(enterprise.siem.enabled);
    EXPECT_TRUE(enterprise.secureDeleteRotatedLogs);
    EXPECT_EQ(enterprise.workerThreads, 4u);
    EXPECT_EQ(enterprise.hmacKey.size(), 32u);

    EXPECT_EQ(minimal.minimumSeverity, EventSeverity::Warning);
    EXPECT_FALSE(minimal.enableForensicCapture);
    EXPECT_FALSE(minimal.enableHashChain);
    EXPECT_FALSE(minimal.enableCrashSafeLogging);
    EXPECT_EQ(minimal.workerThreads, 1u);
    EXPECT_EQ(minimal.hmacKey.size(), 32u);

    EventLoggerStatistics stats;
    stats.eventsLogged.store(4, std::memory_order_relaxed);
    stats.eventsDropped.store(1, std::memory_order_relaxed);
    stats.criticalEventsDropped.store(1, std::memory_order_relaxed);
    stats.windowsEventsWritten.store(2, std::memory_order_relaxed);
    stats.syslogEventsForwarded.store(2, std::memory_order_relaxed);
    stats.siemEventsForwarded.store(2, std::memory_order_relaxed);
    stats.dbEventsWritten.store(2, std::memory_order_relaxed);
    stats.auditEventsLogged.store(3, std::memory_order_relaxed);
    stats.forensicEventsCaptures.store(2, std::memory_order_relaxed);
    stats.logRotations.store(1, std::memory_order_relaxed);
    stats.integritySignaturesGenerated.store(5, std::memory_order_relaxed);
    stats.crashSafeFlushes.store(1, std::memory_order_relaxed);
    stats.callbackTimeouts.store(1, std::memory_order_relaxed);
    stats.sanitizationApplied.store(1, std::memory_order_relaxed);
    stats.pathTraversalBlocked.store(1, std::memory_order_relaxed);
    stats.queueHighWaterMark.store(7, std::memory_order_relaxed);
    stats.forensicBufferMemoryBytes.store(256, std::memory_order_relaxed);
    stats.Reset();

    EXPECT_EQ(stats.eventsLogged.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.eventsDropped.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.criticalEventsDropped.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.windowsEventsWritten.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.syslogEventsForwarded.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.siemEventsForwarded.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.dbEventsWritten.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.auditEventsLogged.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.forensicEventsCaptures.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.logRotations.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.integritySignaturesGenerated.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.crashSafeFlushes.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.callbackTimeouts.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.sanitizationApplied.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.pathTraversalBlocked.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.queueHighWaterMark.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.forensicBufferMemoryBytes.load(std::memory_order_relaxed), 0u);
}

TEST_F(EventLoggerTest, InitializeValidatesHmacKeyAndPauseResumeIsStable) {
    auto& logger = EventLogger::Instance();

    auto invalid = MakeEphemeralConfig();
    invalid.hmacKey.assign(8, 0x2A);
    EXPECT_FALSE(logger.Initialize(invalid));

    auto config = MakeEphemeralConfig();
    ASSERT_TRUE(logger.Initialize(config));
    EXPECT_FALSE(logger.IsPaused());

    logger.Pause();
    EXPECT_TRUE(logger.IsPaused());

    logger.Resume();
    EXPECT_FALSE(logger.IsPaused());
}

TEST_F(EventLoggerTest, LoggingHelpersInvokeCallbacksAndUpdateCounters) {
    auto& logger = EventLogger::Instance();
    ASSERT_TRUE(logger.Initialize(MakeEphemeralConfig()));

    EXPECT_EQ(logger.RegisterEventCallback(EventCallback{}), 0u);
    EXPECT_EQ(logger.RegisterAuditCallback(AuditCallback{}), 0u);

    std::promise<SecurityEvent> eventPromise;
    auto eventFuture = eventPromise.get_future();
    std::atomic<bool> eventSeen{ false };

    std::promise<AuditEvent> auditPromise;
    auto auditFuture = auditPromise.get_future();
    std::atomic<bool> auditSeen{ false };

    const auto eventCallbackId = logger.RegisterEventCallback([&](const SecurityEvent& event) {
        if (!eventSeen.exchange(true)) {
            eventPromise.set_value(event);
        }
    });
    const auto auditCallbackId = logger.RegisterAuditCallback([&](const AuditEvent& event) {
        if (!auditSeen.exchange(true)) {
            auditPromise.set_value(event);
        }
    });

    ASSERT_NE(eventCallbackId, 0u);
    ASSERT_NE(auditCallbackId, 0u);
    EXPECT_NE(eventCallbackId, auditCallbackId);

    logger.LogThreatDetection(
        L"UnitTest.Eicar",
        L"TestSignature",
        L"C:\\Temp\\eicar.bin",
        std::string(64, 'a'),
        L"Blocked",
        EventSeverity::Critical);
    logger.LogPolicyChange(L"RealtimeProtection", L"Enabled", L"Disabled", L"unit-test");

    ASSERT_EQ(eventFuture.wait_for(5s), std::future_status::ready);
    const auto event = eventFuture.get();
    EXPECT_EQ(event.category, EventCategory::ThreatDetection);
    EXPECT_EQ(event.severity, EventSeverity::Critical);
    EXPECT_EQ(event.threatName, L"UnitTest.Eicar");
    EXPECT_EQ(event.action, L"Blocked");
    EXPECT_EQ(event.windowsEventId, 1001u);

    ASSERT_EQ(auditFuture.wait_for(5s), std::future_status::ready);
    const auto audit = auditFuture.get();
    EXPECT_EQ(audit.action, L"PolicyChanged");
    EXPECT_EQ(audit.targetObject, L"RealtimeProtection");
    EXPECT_EQ(audit.oldValue, L"Enabled");
    EXPECT_EQ(audit.newValue, L"Disabled");
    EXPECT_TRUE(audit.success);

    logger.UnregisterEventCallback(eventCallbackId);
    logger.UnregisterAuditCallback(auditCallbackId);
    logger.Flush();

    const auto& stats = logger.GetStatistics();
    EXPECT_GE(stats.eventsLogged.load(std::memory_order_relaxed), 1u);
    EXPECT_GE(stats.auditEventsLogged.load(std::memory_order_relaxed), 1u);
}

TEST_F(EventLoggerTest, ForensicCaptureAndFlushRespectAllowedDirectory) {
    auto& logger = EventLogger::Instance();
    ASSERT_TRUE(logger.Initialize(MakeEphemeralConfig()));

    logger.CaptureForensicEvent(L"UnitTestForensic", { { L"Artifact", L"ShadowStrike" } });
    const auto recent = logger.GetRecentForensicEvents(10);
    ASSERT_EQ(recent.size(), 1u);
    EXPECT_EQ(recent.front().eventType, L"UnitTestForensic");
    EXPECT_EQ(recent.front().data.at(L"Artifact"), L"ShadowStrike");

    const auto validPath = MakePath(L"forensic-buffer.json");
    logger.FlushForensicBuffer(validPath.wstring());
    EXPECT_TRUE(std::filesystem::exists(validPath));
    EXPECT_THAT(ReadTextFile(validPath), HasSubstr("\"eventType\":\"UnitTestForensic\""));

    const auto blockedPath = testRoot_.parent_path() / L"blocked-forensic.json";
    logger.FlushForensicBuffer(blockedPath.wstring());
    EXPECT_FALSE(std::filesystem::exists(blockedPath));
    EXPECT_EQ(logger.GetStatistics().pathTraversalBlocked.load(std::memory_order_relaxed), 1u);
}

}  // namespace
