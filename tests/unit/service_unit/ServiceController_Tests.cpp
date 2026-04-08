/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * Unit coverage for ServiceController.cpp.
 *
 * Coverage focus:
 * - singleton identity and safe default public API behavior
 * - control-handler return codes
 * - status-report serialization shape
 * - recovery and stop request guard paths
 */

#include "pch.h"

#include <gtest/gtest.h>

#include <string>

#include "../../../src/Shared_modules/Service/ServiceController.hpp"

namespace SSS = ShadowStrike::Service;

namespace ShadowStrike::Service::Test {
namespace {

TEST(ServiceControllerTest, InstanceIsStableAndInitializationSurfaceIsSafe) {
    SSS::ServiceController& first = SSS::ServiceController::Instance();
    SSS::ServiceController& second = SSS::ServiceController::Instance();

    EXPECT_EQ(&first, &second);
    EXPECT_TRUE(first.Initialize());

    first.SignalStop();
}

TEST(ServiceControllerTest, ControlHandlerRejectsNullContextAndAcceptsInterrogate) {
    EXPECT_EQ(SSS::ServiceController::ServiceCtrlHandler(
        SERVICE_CONTROL_STOP, 0, nullptr, nullptr), static_cast<DWORD>(ERROR_INVALID_PARAMETER));

    SSS::ServiceController& controller = SSS::ServiceController::Instance();
    EXPECT_EQ(SSS::ServiceController::ServiceCtrlHandler(
        SERVICE_CONTROL_INTERROGATE, 0, nullptr, &controller), static_cast<DWORD>(NO_ERROR));
}

TEST(ServiceControllerTest, StatusReportAndRecoveryExposeCurrentPublicBehavior) {
    SSS::ServiceController& controller = SSS::ServiceController::Instance();

    const std::string report = controller.GetStatusReport();
    EXPECT_NE(report.find("\"service\": \"ShadowStrike\""), std::string::npos);
    EXPECT_NE(report.find("\"status\": \"stopped\""), std::string::npos);
    EXPECT_NE(report.find("\"components\": {"), std::string::npos);

    EXPECT_TRUE(controller.RequestRecovery("telemetry"));
}

}  // namespace
}  // namespace ShadowStrike::Service::Test
