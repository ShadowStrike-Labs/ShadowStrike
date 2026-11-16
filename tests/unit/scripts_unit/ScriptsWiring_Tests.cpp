/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * Unit coverage for Scripts\ScriptsWiring kernel-event fan-out (task 177).
 *
 * The size static_assert in ScriptsWiring.cpp checks only the COUNT of each
 * fan-out table. These cases check the actual COVERAGE, which is what catches a
 * table that duplicates one module and drops another: the count stays six while
 * a module goes missing. Together they enforce "adding one module cannot
 * silently drop another."
 */

#include "pch.h"

#include <gtest/gtest.h>

#include "../../../src/PhantomCore/Scripts/ScriptsWiring.hpp"

namespace ShadowStrike::Scripts::Wiring::Tests {

TEST(ScriptsWiringFanOut, ModuleCountAndFullMaskAreConsistent) {
    EXPECT_EQ(6u, Detail::kScriptFanOutModuleCount);
    // Bits 0..5 set: the mask a complete fan-out must produce.
    EXPECT_EQ(0x3Fu, Detail::kScriptFanOutCoverageAll);
}

TEST(ScriptsWiringFanOut, ProcessNotifyReachesEveryModuleExactlyOnce) {
    EXPECT_EQ(Detail::kScriptFanOutCoverageAll, ProcessNotifyFanOutCoverage());
}

TEST(ScriptsWiringFanOut, ImageLoadReachesEveryModuleExactlyOnce) {
    EXPECT_EQ(Detail::kScriptFanOutCoverageAll, ImageLoadFanOutCoverage());
}

}  // namespace ShadowStrike::Scripts::Wiring::Tests
