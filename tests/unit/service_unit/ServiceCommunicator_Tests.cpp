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

#include <cstddef>
#include <string>
#include <vector>

#include "../../../src/PhantomCore/Service/ServiceCommunicator.hpp"

namespace SSS = ShadowStrike::Service;

namespace ShadowStrike::Service::Test {
namespace {

// ServiceCommunicator::Start() publishes the PRODUCTION IPC endpoint
// (\\.\pipe\ShadowStrikeServicePipe) using the service's own security descriptor,
// whose OWNER is SYSTEM:
//
//   O:SYG:SYD:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;IU)(A;;GRGW;;;AU)S:(ML;;NW;;;LW)
//   - ServiceCommunicator.cpp, CreatePipeSecurityDescriptor()
//
// CreateNamedPipeW applies that descriptor, and a caller may only set an owner SID
// it actually holds (or hold SeRestorePrivilege enabled). An ordinary interactive
// user therefore cannot publish this pipe: the call fails with ERROR_INVALID_OWNER
// (1307). Measured on this machine as a non-elevated user - the product's exact
// SDDL fails with 1307, and the identical descriptor with the "O:SYG:SY" prefix
// removed succeeds - so Start() == false here is the product behaving as designed
// for a SYSTEM service, not a defect.
//
// The cases below therefore assert the state machine rather than the privileged
// outcome, and still REQUIRE success when the suite runs as LocalSystem, which is
// the account the service itself runs under.
[[nodiscard]] bool RunningAsLocalSystem() {
    HANDLE token = nullptr;
    if (::OpenProcessToken(::GetCurrentProcess(), TOKEN_QUERY, &token) == FALSE) {
        return false;
    }

    DWORD required = 0;
    ::GetTokenInformation(token, TokenUser, nullptr, 0, &required);
    if (required == 0) {
        ::CloseHandle(token);
        return false;
    }

    std::vector<std::byte> buffer(required);
    bool isLocalSystem = false;
    if (::GetTokenInformation(token, TokenUser, buffer.data(), required, &required) != FALSE) {
        SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
        PSID localSystemSid = nullptr;
        if (::AllocateAndInitializeSid(&ntAuthority, 1, SECURITY_LOCAL_SYSTEM_RID,
                                       0, 0, 0, 0, 0, 0, 0, &localSystemSid) != FALSE) {
            const auto* tokenUser = reinterpret_cast<const TOKEN_USER*>(buffer.data());
            isLocalSystem = ::EqualSid(tokenUser->User.Sid, localSystemSid) != FALSE;
            ::FreeSid(localSystemSid);
        }
    }

    ::CloseHandle(token);
    return isLocalSystem;
}

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

TEST_F(ServiceCommunicatorTest, DefaultMessageAndInitializationSurfacesRemainStable) {
    const SSS::IpcMessage message;
    EXPECT_EQ(message.magic, SSS::CommunicationConstants::PROTOCOL_MAGIC);
    EXPECT_EQ(message.type, SSS::CommandType::Unknown);
    EXPECT_EQ(message.payloadSize, 0u);
    EXPECT_TRUE(message.payload.empty());

    const std::string json = message.ToJson();
    EXPECT_NE(json.find("\"type\":0"), std::string::npos);
    EXPECT_NE(json.find("\"size\":0"), std::string::npos);
    EXPECT_NE(json.find("\"timestamp\":0"), std::string::npos);

    ASSERT_TRUE(communicator.Initialize());
    EXPECT_TRUE(communicator.Initialize());
    EXPECT_FALSE(communicator.IsRunning());
    EXPECT_TRUE(communicator.SelfTest());
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

    // See RunningAsLocalSystem() above for why Start() cannot be required to succeed
    // in an unprivileged process. What is required unconditionally is that the
    // lifecycle never lands in a half-started state: IsRunning() must agree with what
    // Start() reported, Stop() must be safe either way, and SelfTest() - which only
    // rebuilds the security descriptor and registers a handler - must hold regardless.
    const bool started = communicator.Start();
    if (RunningAsLocalSystem()) {
        EXPECT_TRUE(started)
            << "running as LocalSystem, so publishing the SYSTEM-owned IPC pipe must succeed";
    }
    EXPECT_EQ(communicator.IsRunning(), started);

    communicator.Stop();
    EXPECT_FALSE(communicator.IsRunning());

    EXPECT_TRUE(communicator.SelfTest());
}

TEST_F(ServiceCommunicatorTest, ResetStatsDoesNotAffectRunningStateOrClientlessBroadcastSemantics) {
    // The subject here is ResetStats() and clientless Broadcast(), both of which are
    // observable whether or not the pipe could be published (see RunningAsLocalSystem
    // above). Start() is still called - and still required to succeed when the suite
    // runs as LocalSystem - so that the "does not affect running state" part is
    // exercised against a genuinely running server wherever that is possible.
    const bool started = communicator.Start();
    if (RunningAsLocalSystem()) {
        EXPECT_TRUE(started)
            << "running as LocalSystem, so publishing the SYSTEM-owned IPC pipe must succeed";
    }
    ASSERT_EQ(communicator.IsRunning(), started);

    EXPECT_EQ(communicator.Broadcast(SSS::CommandType::ThreatAlert, std::string{}), 0u);
    EXPECT_EQ(communicator.Broadcast(SSS::CommandType::ThreatAlert, std::vector<uint8_t>{}), 0u);
    EXPECT_EQ(communicator.Broadcast(SSS::CommandType::ThreatAlert, std::string("status")), 0u);
    EXPECT_EQ(communicator.Broadcast(SSS::CommandType::ThreatAlert, std::vector<uint8_t>{9, 8, 7}), 0u);

    communicator.ResetStats();

    const SSS::CommunicatorStats stats = communicator.GetStats();
    EXPECT_EQ(communicator.IsRunning(), started);
    EXPECT_EQ(stats.messagesSent.load(), 0u);
    EXPECT_EQ(stats.bytesSent.load(), 0u);
    EXPECT_EQ(stats.connectionAttempts.load(), 0u);

    communicator.Stop();
    EXPECT_FALSE(communicator.IsRunning());
}

}  // namespace
}  // namespace ShadowStrike::Service::Test
