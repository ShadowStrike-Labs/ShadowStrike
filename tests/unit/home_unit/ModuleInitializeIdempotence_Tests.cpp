/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/**
 * @file ModuleInitializeIdempotence_Tests.cpp
 * @brief A second Initialize on a running PhantomHome module is success (task 288).
 *
 * Twelve modules answered false when already initialised - indistinguishable from a real failure for
 * a caller writing `if (!X.Initialize()) bail;` - and SpamDetector and OutlookScanner had no guard
 * at all, so a second call silently rebuilt their state. ModuleSelfTest_Tests.cpp asserts the same
 * property for every module it covers; this file covers the modules without a SelfTest there.
 *
 * LocationPrivacy starts two threads in Initialize, and the IoT IPLeakProtection is not linked into
 * this binary; both are held by the contract guard InitializeIsIdempotentTests instead.
 */

#include "pch.h"

#include <gtest/gtest.h>

#include "Products/Community/PhantomHome/Privacy/CookieManager.hpp"
#include "Products/Community/PhantomHome/Privacy/DNSLeakProtection.hpp"
#include "Products/Community/PhantomHome/Privacy/IPLeakProtection.hpp"
#include "Products/Community/PhantomHome/Email/SpamDetector.hpp"
#include "Products/Community/PhantomHome/Email/OutlookScanner.hpp"
#include "Products/Community/PhantomHome/GameMode/PerformanceOptimizer.hpp"

namespace {

template <typename T>
void ExpectIdempotentInitialize(const char* moduleName, T& instance) {
    if (!instance.IsInitialized()) {
        (void)instance.Initialize();
    }
    ASSERT_TRUE(instance.IsInitialized()) << moduleName << " could not be initialised at all";
    EXPECT_TRUE(instance.Initialize())
        << moduleName << "::Initialize returned false on an already-initialised module";
    EXPECT_TRUE(instance.IsInitialized()) << moduleName << " stopped being initialised";
}

TEST(ModuleInitialize, PrivacyModulesAcceptASecondInitialize) {
    ExpectIdempotentInitialize("CookieManager", ::ShadowStrike::Privacy::CookieManager::Instance());
    ExpectIdempotentInitialize("DNSLeakProtection", ::ShadowStrike::Privacy::DNSLeakProtection::Instance());
    ExpectIdempotentInitialize("IPLeakProtection", ::ShadowStrike::Privacy::IPLeakProtection::Instance());
}

TEST(ModuleInitialize, EmailModulesAcceptASecondInitialize) {
    ExpectIdempotentInitialize("SpamDetector", ::ShadowStrike::Email::SpamDetector::Instance());
    ExpectIdempotentInitialize("OutlookScanner", ::ShadowStrike::Email::OutlookScanner::Instance());
}

TEST(ModuleInitialize, ASecondInitializeKeepsWhatTheSpamFilterLearned) {
    // The defect behind the missing guard: Initialize rebuilt the Bayesian classifier.
    auto& spam = ::ShadowStrike::Email::SpamDetector::Instance();
    if (!spam.IsInitialized()) {
        (void)spam.Initialize();
    }
    ASSERT_TRUE(spam.IsInitialized());
    const auto before = spam.GetCorpusSize();
    spam.MarkAsSpam("task288 idempotence probe cheap pills winner");
    const auto trained = spam.GetCorpusSize();
    ASSERT_TRUE(spam.Initialize());
    EXPECT_EQ(trained, spam.GetCorpusSize()) << "a second Initialize discarded the training";
    EXPECT_NE(before, trained) << "anti-vacuity: training must have changed the counts";
}

TEST(ModuleInitialize, GameModeOptimizerAcceptsASecondInitialize) {
    ExpectIdempotentInitialize("PerformanceOptimizer",
                               ::ShadowStrike::GameMode::PerformanceOptimizer::Instance());
}

}  // namespace
