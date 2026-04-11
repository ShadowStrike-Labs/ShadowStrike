#include "../../../src/pch.h"

#include <gtest/gtest.h>

#include "../../../src/PhantomCore/Communication/ServiceCommunication.hpp"

#include <chrono>
#include <string>

namespace ServiceComm = ShadowStrike::Communication;

namespace {

using SystemClock = std::chrono::system_clock;

SystemClock::time_point FixedTime() {
    return SystemClock::from_time_t(1'700'000'000);
}

} // namespace

/*
 * ============================================================================
 * ShadowStrike ServiceCommunication - ENTERPRISE-GRADE UNIT TESTS
 * ============================================================================
 *
 * Coverage focus:
 * - Public DTO/state serialization
 * - Payload helpers and move semantics
 * - Configuration validation and statistics snapshots
 *
 * ============================================================================
 */

TEST(ServiceCommunicationTest, ClientSessionMoveOperationsPreserveObservableState) {
    ServiceComm::ClientSession source{};
    source.sessionId = "session-alpha";
    source.clientType = ServiceComm::ClientType::GUI;
    source.processId = 404;
    source.pipeHandle = reinterpret_cast<HANDLE>(static_cast<uintptr_t>(0x1234));
    source.state = ServiceComm::ConnectionState::Connected;
    source.connectedTime = FixedTime();
    source.messagesSent = 11;
    source.messagesReceived = 22;
    source.sequence.store(7, std::memory_order_relaxed);
    source.isAuthenticated = true;
    source.capabilities = 0x55AA;

    ServiceComm::ClientSession moved(std::move(source));
    EXPECT_EQ(moved.sessionId, "session-alpha");
    EXPECT_EQ(moved.processId, 404u);
    EXPECT_EQ(moved.sequence.load(std::memory_order_relaxed), 7u);
    EXPECT_TRUE(moved.isAuthenticated);

    ServiceComm::ClientSession assigned{};
    assigned = std::move(moved);
    EXPECT_EQ(assigned.sessionId, "session-alpha");
    EXPECT_EQ(assigned.messagesSent, 11u);
    EXPECT_EQ(assigned.messagesReceived, 22u);
    EXPECT_EQ(assigned.sequence.load(std::memory_order_relaxed), 7u);
}

TEST(ServiceCommunicationTest, ClientSessionToJsonIncludesConnectionMetadata) {
    ServiceComm::ClientSession session{};
    session.sessionId = "session-01";
    session.clientType = ServiceComm::ClientType::GUI;
    session.processId = 8080;
    session.state = ServiceComm::ConnectionState::Connected;
    session.messagesSent = 9;
    session.messagesReceived = 12;
    session.isAuthenticated = true;

    const std::string json = session.ToJson();
    EXPECT_NE(json.find("\"sessionId\":\"session-01\""), std::string::npos);
    EXPECT_NE(json.find("\"clientType\":\"GUI\""), std::string::npos);
    EXPECT_NE(json.find("\"state\":\"Connected\""), std::string::npos);
    EXPECT_NE(json.find("\"authenticated\":true"), std::string::npos);
}

TEST(ServiceCommunicationTest, ServiceMessagePayloadHelpersRoundTripBinarySafeStrings) {
    ServiceComm::ServiceMessage message{};
    EXPECT_TRUE(message.GetPayloadString().empty());

    const std::string binaryPayload{"abc\0def", 7};
    message.SetPayloadString(binaryPayload);
    EXPECT_EQ(message.GetPayloadString(), binaryPayload);
    ASSERT_EQ(message.payload.size(), binaryPayload.size());
    EXPECT_EQ(message.payload[3], 0u);

    message.SetPayloadString({});
    EXPECT_TRUE(message.GetPayloadString().empty());
    EXPECT_TRUE(message.payload.empty());
}

TEST(ServiceCommunicationTest, ServiceCommunicationConfigurationRejectsUnsafeValues) {
    ServiceComm::ServiceCommConfiguration config{};
    EXPECT_TRUE(config.IsValid());

    config.pipeName.clear();
    EXPECT_FALSE(config.IsValid());

    config = {};
    config.maxClients = 0;
    EXPECT_FALSE(config.IsValid());

    config = {};
    config.maxClients = 256;
    EXPECT_TRUE(config.IsValid());

    config = {};
    config.maxClients = 257;
    EXPECT_FALSE(config.IsValid());

    config = {};
    config.maxMessagesPerSecond = 0;
    EXPECT_FALSE(config.IsValid());
}

TEST(ServiceCommunicationTest, ServiceCommunicationStatisticsResetProducesCleanSnapshot) {
    ServiceComm::ServiceCommStatistics stats{};
    stats.messagesReceived.store(14, std::memory_order_relaxed);
    stats.messagesSent.store(15, std::memory_order_relaxed);
    stats.bytesReceived.store(1024, std::memory_order_relaxed);
    stats.bytesSent.store(2048, std::memory_order_relaxed);
    stats.connectionsTotal.store(3, std::memory_order_relaxed);
    stats.connectionsFailed.store(1, std::memory_order_relaxed);
    stats.authFailures.store(2, std::memory_order_relaxed);
    stats.errors.store(4, std::memory_order_relaxed);
    stats.byMessageType[5].store(8, std::memory_order_relaxed);

    ServiceComm::ServiceCommStatisticsSnapshot snapshot = stats.TakeSnapshot();
    EXPECT_EQ(snapshot.messagesReceived, 14u);
    EXPECT_EQ(snapshot.bytesSent, 2048u);
    EXPECT_EQ(snapshot.byMessageType[5], 8u);
    EXPECT_NE(snapshot.ToJson().find("\"authFailures\":2"), std::string::npos);

    stats.Reset();
    snapshot = stats.TakeSnapshot();
    EXPECT_EQ(snapshot.messagesReceived, 0u);
    EXPECT_EQ(snapshot.connectionsTotal, 0u);
    EXPECT_EQ(snapshot.byMessageType[5], 0u);
}
