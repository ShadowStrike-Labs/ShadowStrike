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

#include "../../../src/PhantomCore/Service/AntivirusService.hpp"

namespace SSS = ShadowStrike::Service;

namespace ShadowStrike::Service::Test {
namespace {

// GetStatusReport() renders the module block from process-global singleton state.
// Three of those fields - cryptoManager, tamperProtection, ipcManager - are rendered
// from HasInstance() alone, and HasInstance() is a one-way latch set the first time
// Instance() is ever called and never cleared:
//
//   IPCManager.cpp     s_instanceCreated{false} ... HasInstance() -> load(); ctor -> store(true)
//   CryptoManager.cpp  s_instanceCreated{false} ... same shape
//
// So "the service is uninitialized" does not imply those fields are false: it implies
// only that nothing in the PROCESS has ever constructed the singleton. Reproduced
// minimally - phantom-tests --gtest_filter=AntivirusServiceTest.StatusReportExposes*
// passes on its own, and fails on "ipcManager":false when PowerShellScannerTest.* runs
// first, because PowerShellScanner reaches Communication::IPCManager::Instance().
// Nothing about the service under test changed between those two runs.
//
// This case therefore asserts the report SHAPE plus the service's own state, and
// asserts each module field is PRESENT with a boolean value rather than pinning a
// value that a sibling suite can flip.
[[nodiscard]] bool HasBooleanField(const std::string& report, const std::string& name) {
    const std::string key = "\"" + name + "\":";
    return report.find(key + "true") != std::string::npos ||
           report.find(key + "false") != std::string::npos;
}

TEST(AntivirusServiceTest, InstanceIsStableAcrossCalls) {
    SSS::AntivirusService& first = SSS::AntivirusService::Instance();
    SSS::AntivirusService& second = SSS::AntivirusService::Instance();
    EXPECT_EQ(&first, &second);
}

TEST(AntivirusServiceTest, StatusReportExposesUninitializedServiceShape) {
    const std::string report = SSS::AntivirusService::Instance().GetStatusReport();

    // Service-owned state: these depend only on AntivirusService, so they are pinned.
    EXPECT_NE(report.find("\"service\":\"ShadowStrike\""), std::string::npos) << report;
    EXPECT_NE(report.find("\"status\":\"uninitialized\""), std::string::npos) << report;
    EXPECT_NE(report.find("\"health\":{"), std::string::npos) << report;
    EXPECT_NE(report.find("\"modules\":{"), std::string::npos) << report;
    EXPECT_FALSE(SSS::AntivirusService::Instance().IsHealthy());

    // Module block shape: every field must be present and boolean-valued. A dropped or
    // renamed field still fails here; a sibling suite touching a singleton does not.
    EXPECT_TRUE(HasBooleanField(report, "threatIntel")) << report;
    EXPECT_TRUE(HasBooleanField(report, "cryptoManager")) << report;
    EXPECT_TRUE(HasBooleanField(report, "tamperProtection")) << report;
    EXPECT_TRUE(HasBooleanField(report, "selfDefense")) << report;
    EXPECT_TRUE(HasBooleanField(report, "ipcManager")) << report;
    EXPECT_TRUE(HasBooleanField(report, "serviceCommunication")) << report;
    EXPECT_NE(report.find("\"realTimeProtection\":{\"active\":"), std::string::npos) << report;
}

TEST(AntivirusServiceTest, ServiceConstantsPreserveScmIdentityAndDependencyFormatting) {
    EXPECT_STREQ(SSS::ServiceConstants::SERVICE_NAME, L"ShadowStrikePhantomService");
    EXPECT_STREQ(SSS::ServiceConstants::DISPLAY_NAME, L"ShadowStrike Phantom Service");
    EXPECT_GT(SSS::ServiceConstants::SHUTDOWN_TIMEOUT_MS, 0u);

    const std::wstring dependencies(SSS::ServiceConstants::DEPENDENCIES,
                                    SSS::ServiceConstants::DEPENDENCIES + 22);
    EXPECT_EQ(dependencies, std::wstring(L"RpcSs\0Winmgmt\0FltMgr\0\0", 22));
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
