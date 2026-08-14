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

#include "../../../src/PhantomCore/Service/ServiceController.hpp"

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
    EXPECT_NE(report.find("\"uptime_seconds\": 0,\"components\": {"), std::string::npos);

    EXPECT_FALSE(controller.IsRunning());
    EXPECT_TRUE(controller.RequestRecovery("telemetry"));

    // WAS: EXPECT_TRUE(controller.RequestRecovery("")).
    // RecoverComponent() now rejects an empty component id and logs it as an error
    // (ServiceController.cpp) instead of returning success for a request that names
    // nothing. Recovery is a "restart this component" instruction: with no id there is
    // no component to restart, so answering true meant reporting a repair that could
    // not have happened. Whatever asked for the recovery - a health check, the
    // management API, an operator - would mark the fault handled and stop escalating,
    // which is how a silently dead subsystem stays dead. Rejecting the malformed
    // request lets the caller see that nothing was done and retry with a real id.
    // If someone reverts this to EXPECT_TRUE: it fails against the current product,
    // and satisfying it would mean deleting the empty-id guard and going back to an
    // unconditional success that carries no information.
    EXPECT_FALSE(controller.RequestRecovery(""));
}

TEST(ServiceControllerTest, StopAndUnknownControlCodesPreserveCurrentSimplifiedContracts) {
    SSS::ServiceController& controller = SSS::ServiceController::Instance();

    EXPECT_EQ(SSS::ServiceController::ServiceCtrlHandler(
        SERVICE_CONTROL_STOP, 0, nullptr, &controller), static_cast<DWORD>(NO_ERROR));
    EXPECT_EQ(SSS::ServiceController::ServiceCtrlHandler(
        0xFFFFFFFFu, 0, nullptr, &controller), static_cast<DWORD>(ERROR_CALL_NOT_IMPLEMENTED));

    const std::string report = controller.GetStatusReport();
    EXPECT_NE(report.find("\"status\": \"stopped\""), std::string::npos);
    EXPECT_FALSE(controller.IsRunning());
}

TEST(ServiceControllerTest, ShutdownAndSessionControlsReturnNoErrorForBoundControllerContext) {
    SSS::ServiceController& controller = SSS::ServiceController::Instance();

    EXPECT_EQ(SSS::ServiceController::ServiceCtrlHandler(
        SERVICE_CONTROL_SHUTDOWN, 0, nullptr, &controller), static_cast<DWORD>(NO_ERROR));
    EXPECT_EQ(SSS::ServiceController::ServiceCtrlHandler(
        SERVICE_CONTROL_SESSIONCHANGE, WTS_SESSION_LOCK, nullptr, &controller), static_cast<DWORD>(NO_ERROR));
}

}  // namespace
}  // namespace ShadowStrike::Service::Test
