/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Boot-time service start watchdog (task 334).
 *
 * SCM applies no failure action when a start misses its 30 s connect window, so a
 * SYSTEM task re-runs the start once per boot. The task runs as LocalSystem; these
 * cases pin that its definition can only ever run the installed DriverResume binary
 * with a constant argument, and that only a timed-out start is retried.
 */

#include "pch.h"

#include <gtest/gtest.h>
#include <string>

#include "Products/Community/PhantomHome/Installer/DriverResume/ServiceStartWatchdog.hpp"

namespace {

using ShadowStrike::Installer::BuildServiceWatchdogTaskXml;
using ShadowStrike::Installer::IsRetryableServiceStartFailure;
using ShadowStrike::Installer::ServiceWatchdogRemainingWaitMs;
using ShadowStrike::Installer::kServiceWatchdogMinUptimeMs;

const std::wstring kExe = L"C:\\Program Files\\ShadowStrike\\Phantom\\ShadowStrikeDriverResume.exe";

TEST(ServiceStartWatchdog, TheTaskRunsTheInstalledBinaryAsSystemAtBoot) {
    const std::wstring xml = BuildServiceWatchdogTaskXml(kExe);
    ASSERT_FALSE(xml.empty());
    EXPECT_NE(std::wstring::npos, xml.find(L"<Command>" + kExe + L"</Command>"));
    EXPECT_NE(std::wstring::npos, xml.find(L"<Arguments>--service-watchdog</Arguments>"));
    EXPECT_NE(std::wstring::npos, xml.find(L"<UserId>S-1-5-18</UserId>")) << "LocalSystem by SID";
    EXPECT_NE(std::wstring::npos, xml.find(L"<BootTrigger>"));
    EXPECT_EQ(std::wstring::npos, xml.find(L"<Delay>"))
        << "the wait lives in the watchdog, measured from boot; a trigger delay would add to "
           "it when Stage 2 starts the task late in the first boot";
    EXPECT_NE(std::wstring::npos, xml.find(L"<ExecutionTimeLimit>PT15M</ExecutionTimeLimit>"))
        << "bounded: a 4 min wait plus 3 attempts x (30 s + 60 s) fits inside";
    EXPECT_NE(std::wstring::npos, xml.find(L"<MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>"));
}

TEST(ServiceStartWatchdog, APathThatCouldMeanAnotherCommandIsRefused) {
    for (const wchar_t* bad : {
             L"",
             L"ShadowStrikeDriverResume.exe",                                 // relative: PATH search
             L"\\\\server\\share\\ShadowStrikeDriverResume.exe",              // UNC
             L"C:\\Program Files\\ShadowStrike\\x\" --evil \"y.exe",           // quote injection, still ends .exe
             L"%ProgramFiles%\\ShadowStrike\\ShadowStrikeDriverResume.exe",   // expansion
             L"C:\\Program Files\\ShadowStrike\\*.exe",                       // wildcard
             L"C:\\Program Files\\ShadowStrike\\a.exe|calc.exe",              // pipe
             L"C:\\Program Files\\ShadowStrike\\script.cmd",                  // not an executable
         }) {
        EXPECT_TRUE(BuildServiceWatchdogTaskXml(bad).empty()) << bad;
    }
}

TEST(ServiceStartWatchdog, XmlSpecialCharactersInThePathAreEscaped) {
    const std::wstring xml = BuildServiceWatchdogTaskXml(L"C:\\R&D\\ShadowStrikeDriverResume.exe");
    ASSERT_FALSE(xml.empty());
    EXPECT_NE(std::wstring::npos, xml.find(L"<Command>C:\\R&amp;D\\ShadowStrikeDriverResume.exe</Command>"));
    EXPECT_EQ(std::wstring::npos, xml.find(L"R&D")) << "a raw ampersand makes the task XML invalid";
}

TEST(ServiceStartWatchdog, ItWaitsOnlyUntilTheDelayedStartWindowHasPassed) {
    EXPECT_EQ(kServiceWatchdogMinUptimeMs, ServiceWatchdogRemainingWaitMs(0));
    EXPECT_EQ(kServiceWatchdogMinUptimeMs - 60'000, ServiceWatchdogRemainingWaitMs(60'000));
    EXPECT_EQ(0u, ServiceWatchdogRemainingWaitMs(kServiceWatchdogMinUptimeMs))
        << "Stage 2 starts the task minutes into the first boot; it must not wait again";
    EXPECT_EQ(0u, ServiceWatchdogRemainingWaitMs(86'400'000ULL));
}

TEST(ServiceStartWatchdog, OnlyATimedOutStartIsRetried) {
    EXPECT_TRUE(IsRetryableServiceStartFailure(ERROR_SERVICE_REQUEST_TIMEOUT)) << "1053, the 7009 case";
    EXPECT_TRUE(IsRetryableServiceStartFailure(WAIT_TIMEOUT));
    for (const DWORD fatal : { static_cast<DWORD>(ERROR_SERVICE_DISABLED), static_cast<DWORD>(ERROR_SERVICE_MARKED_FOR_DELETE),
                               static_cast<DWORD>(ERROR_FILE_NOT_FOUND), static_cast<DWORD>(ERROR_ACCESS_DENIED),
                               static_cast<DWORD>(ERROR_SERVICE_DOES_NOT_EXIST), static_cast<DWORD>(ERROR_SUCCESS) }) {
        EXPECT_FALSE(IsRetryableServiceStartFailure(fatal)) << fatal;
    }
}

} // namespace