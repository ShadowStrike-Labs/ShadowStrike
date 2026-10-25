/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/**
 * @file ModuleSelfTestRemaining_Tests.cpp
 * @brief Runs the SelfTest of every PhantomHome module ModuleSelfTest_Tests.cpp does not (task 314).
 *
 * Banking, Backup, Privacy, Email and the rest of IoT could not share a translation unit until the
 * type collisions were consolidated (291, 302, 305). Each SelfTest was read before being added here:
 * several CHANGED LIVE STATE - unmuting a globally muted microphone, unblocking a blocked camera,
 * training the user's spam model, adding a phantom chunk to the persisted dedup index, writing a
 * fixed-name file in the shared temp directory - and were corrected first (task 341). A self-test
 * reads live state and never changes it; that is what makes it safe to run here and in the service.
 */

#include "pch.h"

#include <gtest/gtest.h>

#include "Products/Community/PhantomHome/Backup/BackupManager.hpp"
#include "Products/Community/PhantomHome/Backup/BackupScheduler.hpp"
#include "Products/Community/PhantomHome/Backup/IncrementalBackup.hpp"
#include "Products/Community/PhantomHome/Backup/RestoreManager.hpp"
#include "Products/Community/PhantomHome/Banking/CertificatePinning.hpp"
#include "Products/Community/PhantomHome/Banking/KeyloggerProtection.hpp"
#include "Products/Community/PhantomHome/Banking/SecureBrowser.hpp"
#include "Products/Community/PhantomHome/Banking/TransactionMonitor.hpp"
#include "Products/Community/PhantomHome/Email/EmailProtection.hpp"
#include "Products/Community/PhantomHome/Email/OutlookScanner.hpp"
#include "Products/Community/PhantomHome/Email/PhishingEmailDetector.hpp"
#include "Products/Community/PhantomHome/Email/SpamDetector.hpp"
#include "Products/Community/PhantomHome/Email/ThunderbirdScanner.hpp"
#include "Products/Community/PhantomHome/GameMode/PerformanceOptimizer.hpp"
#include "Products/Community/PhantomHome/IoT/RouterSecurityChecker.hpp"
#include "Products/Community/PhantomHome/IoT/WiFiSecurityAnalyzer.hpp"
#include "Products/Community/PhantomHome/Privacy/CookieManager.hpp"
#include "Products/Community/PhantomHome/Privacy/DNSLeakProtection.hpp"
#include "Products/Community/PhantomHome/Privacy/DataLeakProtection.hpp"
#include "Products/Community/PhantomHome/Privacy/IPLeakProtection.hpp"
#include "Products/Community/PhantomHome/Privacy/LocationPrivacy.hpp"
#include "Products/Community/PhantomHome/Privacy/MicrophoneGuard.hpp"
#include "Products/Community/PhantomHome/Privacy/PrivacyCleaner.hpp"
#include "Products/Community/PhantomHome/Privacy/WebCamProtector.hpp"

namespace {

template <typename T>
void ExpectSelfTestPasses(const char* moduleName, T& instance) {
    if (!instance.IsInitialized()) {
        (void)instance.Initialize();
    }
    ASSERT_TRUE(instance.IsInitialized()) << moduleName << " could not be initialised";
    EXPECT_TRUE(instance.SelfTest()) << moduleName << "::SelfTest returned false - read its error log line";
    EXPECT_TRUE(instance.IsInitialized()) << moduleName << "::SelfTest left the module uninitialised";
}

TEST(ModuleSelfTestRemaining, BankingModulesPassTheirOwnChecks) {
    ExpectSelfTestPasses("CertificatePinning", ::ShadowStrike::Banking::CertificatePinning::Instance());
    ExpectSelfTestPasses("KeyloggerProtection", ::ShadowStrike::Banking::KeyloggerProtection::Instance());
    ExpectSelfTestPasses("SecureBrowser", ::ShadowStrike::Banking::SecureBrowser::Instance());
    ExpectSelfTestPasses("TransactionMonitor", ::ShadowStrike::Banking::TransactionMonitor::Instance());
}

TEST(ModuleSelfTestRemaining, EmailModulesPassTheirOwnChecks) {
    ExpectSelfTestPasses("PhishingEmailDetector", ::ShadowStrike::Email::PhishingEmailDetector::Instance());
    ExpectSelfTestPasses("SpamDetector", ::ShadowStrike::Email::SpamDetector::Instance());
    ExpectSelfTestPasses("ThunderbirdScanner", ::ShadowStrike::Email::ThunderbirdScanner::Instance());
    ExpectSelfTestPasses("OutlookScanner", ::ShadowStrike::Email::OutlookScanner::Instance());
    ExpectSelfTestPasses("EmailProtection", ::ShadowStrike::Email::EmailProtection::Instance());
}

TEST(ModuleSelfTestRemaining, ASpamSelfTestDoesNotTrainTheLiveModel) {
    auto& spam = ::ShadowStrike::Email::SpamDetector::Instance();
    if (!spam.IsInitialized()) (void)spam.Initialize();
    const auto before = spam.GetCorpusSize();
    ASSERT_TRUE(spam.SelfTest());
    EXPECT_EQ(before, spam.GetCorpusSize()) << "SelfTest trained the user's spam model";
}

TEST(ModuleSelfTestRemaining, PrivacyModulesPassTheirOwnChecks) {
    ExpectSelfTestPasses("CookieManager", ::ShadowStrike::Privacy::CookieManager::Instance());
    ExpectSelfTestPasses("DNSLeakProtection", ::ShadowStrike::Privacy::DNSLeakProtection::Instance());
    ExpectSelfTestPasses("IPLeakProtection", ::ShadowStrike::Privacy::IPLeakProtection::Instance());
    ExpectSelfTestPasses("DataLeakProtection", ::ShadowStrike::Privacy::DataLeakProtection::Instance());
    ExpectSelfTestPasses("LocationPrivacy", ::ShadowStrike::Privacy::LocationPrivacy::Instance());
    ExpectSelfTestPasses("PrivacyCleaner", ::ShadowStrike::Privacy::PrivacyCleaner::Instance());
}

TEST(ModuleSelfTestRemaining, CameraAndMicrophoneSelfTestsLeaveTheUsersBlocksInPlace) {
    auto& mic = ::ShadowStrike::Privacy::MicrophoneGuard::Instance();
    auto& cam = ::ShadowStrike::Privacy::WebcamProtector::Instance();
    if (!mic.IsInitialized()) (void)mic.Initialize();
    if (!cam.IsInitialized()) (void)cam.Initialize();
    ASSERT_TRUE(mic.IsInitialized());
    ASSERT_TRUE(cam.IsInitialized());
    ASSERT_TRUE(mic.SetGlobalMute(true));
    ASSERT_TRUE(cam.SetCameraBlocked(true));
    const bool micOk = mic.SelfTest();
    const bool camOk = cam.SelfTest();
    const bool stillMuted = mic.IsGloballyMuted();
    const bool stillBlocked = cam.IsCameraBlocked();
    (void)mic.SetGlobalMute(false);
    (void)cam.SetCameraBlocked(false);
    EXPECT_TRUE(micOk);
    EXPECT_TRUE(camOk);
    EXPECT_TRUE(stillMuted) << "the microphone self-test unmuted a globally muted microphone";
    EXPECT_TRUE(stillBlocked) << "the camera self-test left a blocked camera unblocked";
}

TEST(ModuleSelfTestRemaining, IoTAndGameModeModulesPassTheirOwnChecks) {
    ExpectSelfTestPasses("RouterSecurityChecker", ::ShadowStrike::IoT::RouterSecurityChecker::Instance());
    // Initialize failed outright on a machine without the WLAN service (this build host, every wired
    // desktop) until task 342; it now initialises with nothing to watch.
    ExpectSelfTestPasses("WiFiSecurityAnalyzer", ::ShadowStrike::IoT::WiFiSecurityAnalyzer::Instance());
    ExpectSelfTestPasses("PerformanceOptimizer", ::ShadowStrike::GameMode::PerformanceOptimizer::Instance());
}

TEST(ModuleSelfTestRemaining, BackupModulesPassTheirOwnChecks) {
    ExpectSelfTestPasses("IncrementalBackup", ::ShadowStrike::Backup::IncrementalBackup::Instance());
    ExpectSelfTestPasses("BackupScheduler", ::ShadowStrike::Backup::BackupScheduler::Instance());
}

}  // namespace
