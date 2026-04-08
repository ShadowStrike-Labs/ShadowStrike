/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * Unit coverage for ServiceInstaller.cpp.
 *
 * Coverage focus:
 * - deterministic dependency multi-string formatting helper
 * - empty and multi-entry dependency edge cases
 *
 * The actual install/start/stop public APIs are SCM-bound and intentionally left
 * to higher-level integration coverage. This suite verifies the core pure helper
 * logic without mutating host service state.
 */

#include "pch.h"

#include <gtest/gtest.h>

#include <string>
#include <vector>

#define private public
#include "../../../src/Shared_modules/Service/ServiceInstaller.hpp"
#undef private

namespace SSS = ShadowStrike::Service;

namespace ShadowStrike::Service::Test {
namespace {

TEST(ServiceInstallerTest, FormatDependenciesReturnsEmptyStringForNoDependencies) {
    EXPECT_TRUE(SSS::ServiceInstaller::FormatDependencies({}).empty());
}

TEST(ServiceInstallerTest, FormatDependenciesBuildsDoubleNullTerminatedMultiString) {
    const std::vector<std::wstring> dependencies = {L"RpcSs", L"Winmgmt", L"W32Time"};
    const std::wstring formatted = SSS::ServiceInstaller::FormatDependencies(dependencies);

    std::wstring expected = L"RpcSs";
    expected.push_back(L'\0');
    expected += L"Winmgmt";
    expected.push_back(L'\0');
    expected += L"W32Time";
    expected.push_back(L'\0');
    expected.push_back(L'\0');

    EXPECT_EQ(formatted, expected);
    EXPECT_EQ(formatted.back(), L'\0');
    EXPECT_EQ(formatted[formatted.size() - 2], L'\0');
}

TEST(ServiceInstallerTest, FormatDependenciesPreservesEmptyEntriesAsExplicitSeparators) {
    const std::wstring formatted = SSS::ServiceInstaller::FormatDependencies({L""});

    ASSERT_EQ(formatted.size(), 2U);
    EXPECT_EQ(formatted[0], L'\0');
    EXPECT_EQ(formatted[1], L'\0');
}

}  // namespace
}  // namespace ShadowStrike::Service::Test
