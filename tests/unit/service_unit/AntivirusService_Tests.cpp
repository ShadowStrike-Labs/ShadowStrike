/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * Unit coverage for AntivirusService.cpp.
 *
 * Coverage focus:
 * - singleton identity
 * - safe status-report surface before service startup
 * - control-handler return values for non-destructive control codes
 */

#include "pch.h"

#include <gtest/gtest.h>

#include <string>

#include "../../../src/Shared_modules/Service/AntivirusService.hpp"

namespace SSS = ShadowStrike::Service;

namespace ShadowStrike::Service::Test {
namespace {

TEST(AntivirusServiceTest, InstanceIsStableAcrossCalls) {
    SSS::AntivirusService& first = SSS::AntivirusService::Instance();
    SSS::AntivirusService& second = SSS::AntivirusService::Instance();
    EXPECT_EQ(&first, &second);
}

TEST(AntivirusServiceTest, StatusReportExposesUninitializedServiceShape) {
    const std::string report = SSS::AntivirusService::Instance().GetStatusReport();
    EXPECT_NE(report.find("\"service\":\"ShadowStrike\""), std::string::npos);
    EXPECT_NE(report.find("\"status\":\"uninitialized\""), std::string::npos);
    EXPECT_NE(report.find("\"health\":{"), std::string::npos);
    EXPECT_NE(report.find("\"modules\":{"), std::string::npos);
    EXPECT_NE(report.find("\"threatIntel\":false"), std::string::npos);
    EXPECT_NE(report.find("\"cryptoManager\":false"), std::string::npos);
    EXPECT_NE(report.find("\"tamperProtection\":false"), std::string::npos);
    EXPECT_NE(report.find("\"realTimeProtection\":{\"active\":false}"), std::string::npos);
    EXPECT_NE(report.find("\"selfDefense\":false"), std::string::npos);
    EXPECT_NE(report.find("\"ipcManager\":false"), std::string::npos);
    EXPECT_NE(report.find("\"serviceCommunication\":false"), std::string::npos);
    EXPECT_FALSE(SSS::AntivirusService::Instance().IsHealthy());
}

TEST(AntivirusServiceTest, ControlHandlerReturnsExpectedCodesForSafeCommands) {
    EXPECT_EQ(SSS::AntivirusService::ServiceCtrlHandler(
        SERVICE_CONTROL_INTERROGATE, 0, nullptr, nullptr), static_cast<DWORD>(NO_ERROR));
    EXPECT_EQ(SSS::AntivirusService::ServiceCtrlHandler(
        SERVICE_CONTROL_SESSIONCHANGE, WTS_SESSION_LOCK, nullptr, nullptr), static_cast<DWORD>(NO_ERROR));
    EXPECT_EQ(SSS::AntivirusService::ServiceCtrlHandler(
        SERVICE_CONTROL_POWEREVENT, 0xFFFFFFFFu, nullptr, nullptr), static_cast<DWORD>(NO_ERROR));
    EXPECT_EQ(SSS::AntivirusService::ServiceCtrlHandler(
        0xFFFFFFFFu, 0, nullptr, nullptr), static_cast<DWORD>(ERROR_CALL_NOT_IMPLEMENTED));
}

}  // namespace
}  // namespace ShadowStrike::Service::Test
