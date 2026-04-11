#include "../../../src/pch.h"

#include <gtest/gtest.h>

#include "../../../src/PhantomCore/Communication/AlertSystem.hpp"

#include <chrono>
#include <string>

namespace Alerting = ShadowStrike::Communication;

namespace {

using SystemClock = std::chrono::system_clock;
using namespace std::chrono_literals;

SystemClock::time_point FixedTime() {
    return SystemClock::from_time_t(1'700'000'000);
}

} // namespace

/*
 * ============================================================================
 * ShadowStrike AlertSystem - ENTERPRISE-GRADE UNIT TESTS
 * ============================================================================
 *
 * Coverage focus:
 * - Channel/config validation
 * - Escalation and suppression DTO serialization
 * - Expiry logic and statistics snapshots
 *
 * ============================================================================
 */

TEST(AlertSystemTest, DeliveryConfigurationsValidateRequiredFieldsAndReasonableLimits) {
    Alerting::SMTPConfiguration smtp{};
    smtp.server = "smtp.shadowstrike.test";
    smtp.port = 587;
    smtp.fromAddress = "alerts@shadowstrike.test";
    EXPECT_TRUE(smtp.IsValid());

    smtp.server.clear();
    EXPECT_FALSE(smtp.IsValid());

    smtp.server = "smtp.shadowstrike.test";
    smtp.port = 0;
    EXPECT_FALSE(smtp.IsValid());

    Alerting::WebhookConfiguration webhook{};
    webhook.webhookId = "teams-prod";
    webhook.url = "https://hooks.shadowstrike.test/alerts";
    EXPECT_TRUE(webhook.IsValid());

    webhook.url.assign(2047, 'a');
    EXPECT_TRUE(webhook.IsValid());

    webhook.url.assign(2048, 'a');
    EXPECT_FALSE(webhook.IsValid());
}

TEST(AlertSystemTest, SuppressionRuleExpiryCoversPermanentDerivedAndExplicitEndTimes) {
    Alerting::SuppressionRule permanent{};
    permanent.duration = std::chrono::minutes{0};
    permanent.startTime = FixedTime() - 24h;
    EXPECT_FALSE(permanent.IsExpired());

    Alerting::SuppressionRule derived{};
    derived.duration = 10min;
    derived.startTime = SystemClock::now() - 30min;
    EXPECT_TRUE(derived.IsExpired());

    Alerting::SuppressionRule explicitEnd{};
    explicitEnd.duration = 10min;
    explicitEnd.startTime = SystemClock::now();
    explicitEnd.endTime = SystemClock::now() + 5min;
    EXPECT_FALSE(explicitEnd.IsExpired());

    explicitEnd.endTime = SystemClock::now() - 1min;
    EXPECT_TRUE(explicitEnd.IsExpired());
}

TEST(AlertSystemTest, AlertConfigurationRejectsUnsafeRateLimitAndRetrySettings) {
    Alerting::AlertConfiguration config{};
    EXPECT_TRUE(config.IsValid());

    config.rateLimitPerMinute = 0;
    EXPECT_FALSE(config.IsValid());

    config = {};
    config.maxRetryAttempts = 10;
    EXPECT_TRUE(config.IsValid());

    config = {};
    config.maxRetryAttempts = 11;
    EXPECT_FALSE(config.IsValid());
}

TEST(AlertSystemTest, AlertModelsSerializeEscalationDeliveryAndCorrelationData) {
    Alerting::AlertRecipient recipient{};
    recipient.recipientId = "secops-1";
    recipient.name = "SecOps Primary";
    recipient.email = "secops@shadowstrike.test";
    recipient.level = Alerting::EscalationLevel::Level2;
    recipient.enabled = true;
    const std::string recipientJson = recipient.ToJson();
    EXPECT_NE(recipientJson.find("\"recipientId\":\"secops-1\""), std::string::npos);
    EXPECT_NE(recipientJson.find("\"enabled\":true"), std::string::npos);

    Alerting::Alert alert{};
    alert.alertId = "alert-1";
    alert.severity = Alerting::AlertSeverity::Critical;
    alert.type = Alerting::AlertType::ThreatDetection;
    alert.subject = "Threat blocked";
    alert.details = "Malware execution prevented";
    alert.source = "BehaviorBlocker";
    alert.hostname = "endpoint-01";
    alert.status = Alerting::AlertStatus::Sent;
    alert.escalationLevel = Alerting::EscalationLevel::Level3;
    alert.createdTime = FixedTime();
    alert.retryCount = 1;
    alert.correlationId = "corr-42";
    alert.metadata = "{\"ioc\":\"hash\"}";
    alert.errorMessage = "smtp timeout";
    const std::string alertJson = alert.ToJson();
    EXPECT_NE(alertJson.find("\"alertId\":\"alert-1\""), std::string::npos);
    EXPECT_NE(alertJson.find("\"correlationId\":\"corr-42\""), std::string::npos);
    EXPECT_NE(alertJson.find("\"errorMessage\":\"smtp timeout\""), std::string::npos);

    Alerting::EscalationRule escalation{};
    escalation.ruleId = "esc-1";
    escalation.name = "Critical auto escalation";
    escalation.minSeverity = Alerting::AlertSeverity::High;
    escalation.timeoutMinutes = 5;
    escalation.enabled = true;
    const std::string escalationJson = escalation.ToJson();
    EXPECT_NE(escalationJson.find("\"timeoutMinutes\":5"), std::string::npos);

    Alerting::SuppressionRule suppression{};
    suppression.ruleId = "sup-1";
    suppression.name = "Maintenance";
    suppression.duration = 60min;
    suppression.reason = "Patch window";
    suppression.active = true;
    const std::string suppressionJson = suppression.ToJson();
    EXPECT_NE(suppressionJson.find("\"reason\":\"Patch window\""), std::string::npos);

    Alerting::DeliveryResult delivery{};
    delivery.alertId = "alert-1";
    delivery.channel = Alerting::DeliveryChannel::Webhook;
    delivery.success = true;
    delivery.responseCode = 200;
    delivery.responseMessage = "Accepted";
    delivery.durationMs = 87;
    const std::string deliveryJson = delivery.ToJson();
    EXPECT_NE(deliveryJson.find("\"responseCode\":200"), std::string::npos);
    EXPECT_NE(deliveryJson.find("\"responseMessage\":\"Accepted\""), std::string::npos);
}

TEST(AlertSystemTest, AlertStatisticsResetProducesDeterministicSnapshotAndJson) {
    Alerting::AlertStatistics stats{};
    stats.totalAlerts.store(10, std::memory_order_relaxed);
    stats.alertsSent.store(8, std::memory_order_relaxed);
    stats.alertsFailed.store(1, std::memory_order_relaxed);
    stats.alertsSuppressed.store(2, std::memory_order_relaxed);
    stats.alertsAcknowledged.store(3, std::memory_order_relaxed);
    stats.alertsEscalated.store(4, std::memory_order_relaxed);
    stats.emailsSent.store(5, std::memory_order_relaxed);
    stats.webhooksSent.store(6, std::memory_order_relaxed);
    stats.smsSent.store(7, std::memory_order_relaxed);
    stats.rateLimitHits.store(9, std::memory_order_relaxed);
    stats.bySeverity[1].store(11, std::memory_order_relaxed);
    stats.byChannel[2].store(12, std::memory_order_relaxed);

    Alerting::AlertStatisticsSnapshot snapshot = stats.TakeSnapshot();
    EXPECT_EQ(snapshot.totalAlerts, 10u);
    EXPECT_EQ(snapshot.rateLimitHits, 9u);
    EXPECT_EQ(snapshot.bySeverity[1], 11u);
    EXPECT_EQ(snapshot.byChannel[2], 12u);
    EXPECT_NE(snapshot.ToJson().find("\"webhooksSent\":6"), std::string::npos);

    stats.Reset();
    snapshot = stats.TakeSnapshot();
    EXPECT_EQ(snapshot.totalAlerts, 0u);
    EXPECT_EQ(snapshot.alertsSent, 0u);
    EXPECT_EQ(snapshot.byChannel[2], 0u);
}
