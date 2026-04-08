#include "../../../src/pch.h"

#include <gtest/gtest.h>

#include "../../../src/Shared_modules/Communication/TelemetryCollector.hpp"

#include <algorithm>
#include <chrono>
#include <string>

namespace Telemetry = ShadowStrike::Communication;

namespace {

using SystemClock = std::chrono::system_clock;

SystemClock::time_point FixedTime() {
    return SystemClock::from_time_t(1'700'000'000);
}

bool IsHexString(const std::string& value) {
    return std::all_of(value.begin(), value.end(), [](unsigned char c) {
        return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
    });
}

} // namespace

/*
 * ============================================================================
 * ShadowStrike TelemetryCollector - ENTERPRISE-GRADE UNIT TESTS
 * ============================================================================
 *
 * Coverage focus:
 * - Privacy-preserving scrubbing and hashing helpers
 * - DTO/configuration serialization and validation
 * - Statistics snapshot integrity
 *
 * ============================================================================
 */

TEST(TelemetryCollectorTest, ScrubPIIRedactsSensitiveFieldsWhilePreservingUsefulSignal) {
    const std::string input =
        "alice@example.com connected from 192.168.10.25 "
        "under C:\\Users\\alice\\Desktop with SID S-1-5-21-111-222-333-444";

    const std::string scrubbed = Telemetry::ScrubPII(input);

    EXPECT_EQ(scrubbed.find("alice@example.com"), std::string::npos);
    EXPECT_NE(scrubbed.find("[EMAIL_REDACTED]"), std::string::npos);
    EXPECT_NE(scrubbed.find("192.168.x.x"), std::string::npos);
    EXPECT_NE(scrubbed.find("C:\\Users\\[USER]\\Desktop"), std::string::npos);
    EXPECT_NE(scrubbed.find("[SID_REDACTED]"), std::string::npos);
}

TEST(TelemetryCollectorTest, ScrubPIILeavesBenignTelemetryUntouched) {
    const std::string input = "engine=healthy queueDepth=4 mode=active";
    EXPECT_EQ(Telemetry::ScrubPII(input), input);
}

TEST(TelemetryCollectorTest, HashSensitiveDataIsDeterministicSha256Hex) {
    const std::string first = Telemetry::HashSensitiveData("sensitive-artifact");
    const std::string second = Telemetry::HashSensitiveData("sensitive-artifact");
    const std::string different = Telemetry::HashSensitiveData("different-artifact");

    ASSERT_EQ(first.size(), 64u);
    EXPECT_TRUE(IsHexString(first));
    EXPECT_EQ(first, second);
    EXPECT_NE(first, different);
}

TEST(TelemetryCollectorTest, TelemetryEventAndBatchSerializationExposeOperationalFields) {
    Telemetry::TelemetryEvent event{};
    event.eventId = "evt-1";
    event.eventType = Telemetry::TelemetryEventType::Detection;
    event.subtype = "runtime";
    event.payloadJson = R"({"score":99})";
    event.timestamp = 123456789;
    event.systemTime = FixedTime();
    event.machineId = "anon-machine";
    event.productVersion = "3.0.0";
    event.osVersion = "Windows 11";
    event.isAnonymized = true;
    event.anonymizationLevel = Telemetry::AnonymizationLevel::Strict;
    event.status = Telemetry::SubmissionStatus::Pending;
    event.retryCount = 2;

    const std::string eventJson = event.ToJson();
    EXPECT_NE(eventJson.find("\"eventId\":\"evt-1\""), std::string::npos);
    EXPECT_NE(eventJson.find("\"eventType\":\"Detection\""), std::string::npos);
    EXPECT_NE(eventJson.find("\"payload\":{\"score\":99}"), std::string::npos);

    Telemetry::TelemetryBatch batch{};
    batch.batchId = "batch-1";
    batch.createdTime = FixedTime();
    batch.submittedTime = FixedTime();
    batch.status = Telemetry::SubmissionStatus::Submitted;
    batch.retryCount = 1;
    batch.totalSize = 2048;
    batch.compressedSize = 512;
    batch.events.push_back(event);

    const std::string batchJson = batch.ToJson();
    EXPECT_NE(batchJson.find("\"batchId\":\"batch-1\""), std::string::npos);
    EXPECT_NE(batchJson.find("\"status\":\"Submitted\""), std::string::npos);
    EXPECT_NE(batchJson.find("\"eventCount\":1"), std::string::npos);
}

TEST(TelemetryCollectorTest, TelemetryPayloadStructuresSerializeRepresentativeData) {
    Telemetry::DetectionEventData detection{};
    detection.threatName = "Trojan.Test";
    detection.threatType = "Trojan";
    detection.fileHash = "abc123";
    detection.fileSize = 4096;
    detection.detectionMethod = "Behavioral";
    detection.actionTaken = "Blocked";
    detection.detectionTime = 999;
    detection.signatureVersion = "2026.04.08";
    detection.fpProbability = 0.125;
    EXPECT_NE(detection.ToJson().find("\"actionTaken\":\"Blocked\""), std::string::npos);

    Telemetry::HealthEventData health{};
    health.cpuUsage = 18.5;
    health.memoryUsageMB = 256;
    health.diskUsageMB = 1024;
    health.uptimeSeconds = 60;
    health.scanQueueSize = 3;
    health.activeScans = 1;
    health.errorCount = 2;
    health.moduleHealth["RealTime"] = "Healthy";
    const std::string healthJson = health.ToJson();
    EXPECT_NE(healthJson.find("\"cpuUsage\":18.500000"), std::string::npos);
    EXPECT_NE(healthJson.find("\"RealTime\":\"Healthy\""), std::string::npos);

    Telemetry::PerformanceEventData perf{};
    perf.metricName = "Latency";
    perf.value = 1.25;
    perf.unit = "ms";
    perf.durationMs = 7;
    perf.context["stage"] = "dispatch";
    const std::string perfJson = perf.ToJson();
    EXPECT_NE(perfJson.find("\"metricName\":\"Latency\""), std::string::npos);
    EXPECT_NE(perfJson.find("\"stage\":\"dispatch\""), std::string::npos);

    Telemetry::CrashEventData crash{};
    crash.exceptionType = "std::runtime_error";
    crash.exceptionMessage = "failure";
    crash.stackTrace = "main->worker";
    crash.moduleName = "TelemetryCollector";
    crash.functionName = "SubmitImmediate";
    crash.threadId = 42;
    crash.isCritical = true;
    crash.minidumpHash = "deadbeef";
    const std::string crashJson = crash.ToJson();
    EXPECT_NE(crashJson.find("\"isCritical\":true"), std::string::npos);
    EXPECT_NE(crashJson.find("\"threadId\":42"), std::string::npos);
}

TEST(TelemetryCollectorTest, TelemetryConfigurationValidatesQueueAndEndpointSafetyLimits) {
    Telemetry::TelemetryConfiguration config{};
    EXPECT_TRUE(config.IsValid());

    config.batchSize = 1000;
    config.maxQueueSize = 100'000;
    config.flushIntervalHours = 168;
    config.maxRetryAttempts = 20;
    config.endpoint = "https://telemetry.shadowstrike.io/collect";
    EXPECT_TRUE(config.IsValid());

    config = {};
    config.batchSize = 0;
    EXPECT_FALSE(config.IsValid());

    config = {};
    config.batchSize = 1001;
    EXPECT_FALSE(config.IsValid());

    config = {};
    config.maxQueueSize = 100'001;
    EXPECT_FALSE(config.IsValid());

    config = {};
    config.flushIntervalHours = 0;
    EXPECT_FALSE(config.IsValid());

    config = {};
    config.maxRetryAttempts = 21;
    EXPECT_FALSE(config.IsValid());

    config = {};
    config.endpoint = "telemetry.shadowstrike.io";
    EXPECT_FALSE(config.IsValid());

    config = {};
    config.endpoint = "https://telemetry.shadowstrike.io/../collect";
    EXPECT_FALSE(config.IsValid());
}

TEST(TelemetryCollectorTest, TelemetryStatisticsResetAndJsonSnapshotStayConsistent) {
    Telemetry::TelemetryStatistics stats{};
    stats.eventsRecorded.store(44, std::memory_order_relaxed);
    stats.eventsSubmitted.store(40, std::memory_order_relaxed);
    stats.eventsFailed.store(2, std::memory_order_relaxed);
    stats.eventsDropped.store(1, std::memory_order_relaxed);
    stats.batchesSubmitted.store(3, std::memory_order_relaxed);
    stats.batchesFailed.store(1, std::memory_order_relaxed);
    stats.bytesSubmitted.store(8192, std::memory_order_relaxed);
    stats.retryAttempts.store(5, std::memory_order_relaxed);
    stats.anonymizationTime.store(222, std::memory_order_relaxed);
    stats.byEventType[static_cast<size_t>(Telemetry::TelemetryEventType::Detection)]
        .store(9, std::memory_order_relaxed);

    Telemetry::TelemetryStatisticsSnapshot snapshot = stats.TakeSnapshot();
    EXPECT_EQ(snapshot.eventsRecorded, 44u);
    EXPECT_EQ(snapshot.bytesSubmitted, 8192u);
    EXPECT_EQ(snapshot.byEventType[static_cast<size_t>(Telemetry::TelemetryEventType::Detection)], 9u);
    EXPECT_NE(snapshot.ToJson().find("\"anonymizationTimeUs\":222"), std::string::npos);

    stats.Reset();
    snapshot = stats.TakeSnapshot();
    EXPECT_EQ(snapshot.eventsRecorded, 0u);
    EXPECT_EQ(snapshot.retryAttempts, 0u);
    EXPECT_EQ(snapshot.byEventType[static_cast<size_t>(Telemetry::TelemetryEventType::Detection)], 0u);
}
