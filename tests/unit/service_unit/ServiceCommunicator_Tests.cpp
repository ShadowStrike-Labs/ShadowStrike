/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * Unit coverage for ServiceCommunicator.cpp.
 *
 * Coverage focus:
 * - message and statistics serialization
 * - copy/reset semantics for CommunicatorStats
 * - safe singleton lifecycle and broadcast behavior without connected clients
 * - explicit self-test and version surfaces
 */

#include "pch.h"

#include <gtest/gtest.h>

#include <string>
#include <vector>

#include "../../../src/Shared_modules/Service/ServiceCommunicator.hpp"

namespace SSS = ShadowStrike::Service;

namespace ShadowStrike::Service::Test {
namespace {

class ServiceCommunicatorTest : public ::testing::Test {
protected:
    ServiceCommunicator& communicator = ServiceCommunicator::Instance();

    void SetUp() override {
        communicator.Stop();
        communicator.ResetStats();
    }

    void TearDown() override {
        communicator.Stop();
        communicator.ResetStats();
    }
};

TEST_F(ServiceCommunicatorTest, StatsCopyAssignmentResetAndJsonStayConsistent) {
    SSS::CommunicatorStats stats;
    stats.messagesReceived = 11;
    stats.messagesSent = 22;
    stats.bytesReceived = 33;
    stats.bytesSent = 44;
    stats.connectionAttempts = 55;
    stats.activeConnections = 66;
    stats.droppedPackets = 77;
    stats.authFailures = 88;

    const SSS::CommunicatorStats copied(stats);
    EXPECT_EQ(copied.messagesReceived.load(), 11u);
    EXPECT_EQ(copied.authFailures.load(), 88u);

    SSS::CommunicatorStats assigned;
    assigned = stats;
    EXPECT_EQ(assigned.messagesSent.load(), 22u);
    EXPECT_EQ(assigned.bytesSent.load(), 44u);

    const std::string json = assigned.ToJson();
    EXPECT_NE(json.find("\"messagesReceived\":11"), std::string::npos);
    EXPECT_NE(json.find("\"activeConnections\":66"), std::string::npos);
    EXPECT_NE(json.find("\"authFailures\":88"), std::string::npos);

    assigned.Reset();
    EXPECT_EQ(assigned.messagesReceived.load(), 0u);
    EXPECT_EQ(assigned.messagesSent.load(), 0u);
    EXPECT_EQ(assigned.bytesReceived.load(), 0u);
    EXPECT_EQ(assigned.bytesSent.load(), 0u);
    EXPECT_EQ(assigned.connectionAttempts.load(), 0u);
    EXPECT_EQ(assigned.activeConnections.load(), 0u);
    EXPECT_EQ(assigned.droppedPackets.load(), 0u);
    EXPECT_EQ(assigned.authFailures.load(), 0u);
}

TEST_F(ServiceCommunicatorTest, IpcMessageJsonIncludesTypeSizeAndTimestamp) {
    SSS::IpcMessage message;
    message.type = SSS::CommandType::UpdateConfig;
    message.payloadSize = 123;
    message.timestamp = 456789;
    message.payload = {1, 2, 3, 4};

    const std::string json = message.ToJson();
    EXPECT_NE(json.find("\"type\":30"), std::string::npos);
    EXPECT_NE(json.find("\"size\":123"), std::string::npos);
    EXPECT_NE(json.find("\"timestamp\":456789"), std::string::npos);
    EXPECT_EQ(json.find("\"magic\""), std::string::npos);
    EXPECT_EQ(json.find("\"payload\""), std::string::npos);
}

TEST_F(ServiceCommunicatorTest, DefaultsAndStatsAccessorsAreSafeWithoutClients) {
    EXPECT_FALSE(communicator.IsRunning());
    EXPECT_EQ(SSS::ServiceCommunicator::GetVersionString(), "3.0.0");

    communicator.RegisterHandler(SSS::CommandType::GetStatus,
        [](SSS::CommandType, const std::vector<uint8_t>&, std::vector<uint8_t>& response) {
            response = {'o', 'k'};
            return true;
        });

    EXPECT_EQ(communicator.Broadcast(SSS::CommandType::ThreatAlert, std::string("payload")), 0u);
    EXPECT_EQ(communicator.Broadcast(SSS::CommandType::ThreatAlert, std::vector<uint8_t>{1, 2, 3}), 0u);

    const SSS::CommunicatorStats stats = communicator.GetStats();
    EXPECT_EQ(stats.messagesReceived.load(), 0u);
    EXPECT_EQ(stats.messagesSent.load(), 0u);
    EXPECT_EQ(stats.activeConnections.load(), 0u);
}

TEST_F(ServiceCommunicatorTest, InitializeStartStopAndSelfTestSucceed) {
    ASSERT_TRUE(communicator.Initialize());
    ASSERT_TRUE(communicator.Start());
    EXPECT_TRUE(communicator.IsRunning());

    communicator.Stop();
    EXPECT_FALSE(communicator.IsRunning());

    EXPECT_TRUE(communicator.SelfTest());
}

TEST_F(ServiceCommunicatorTest, ResetStatsDoesNotAffectRunningStateOrClientlessBroadcastSemantics) {
    ASSERT_TRUE(communicator.Start());
    EXPECT_TRUE(communicator.IsRunning());

    EXPECT_EQ(communicator.Broadcast(SSS::CommandType::ThreatAlert, std::string("status")), 0u);
    EXPECT_EQ(communicator.Broadcast(SSS::CommandType::ThreatAlert, std::vector<uint8_t>{9, 8, 7}), 0u);

    communicator.ResetStats();

    const SSS::CommunicatorStats stats = communicator.GetStats();
    EXPECT_TRUE(communicator.IsRunning());
    EXPECT_EQ(stats.messagesSent.load(), 0u);
    EXPECT_EQ(stats.bytesSent.load(), 0u);
    EXPECT_EQ(stats.connectionAttempts.load(), 0u);

    communicator.Stop();
    EXPECT_FALSE(communicator.IsRunning());
}

}  // namespace
}  // namespace ShadowStrike::Service::Test
