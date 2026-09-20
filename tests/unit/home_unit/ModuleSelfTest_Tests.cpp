// SPDX-License-Identifier: AGPL-3.0-or-later
/*
 * ShadowStrike Phantom - Module self-test guard
 * Copyright (C) 2026 ShadowStrike-Labs
 *
 * This program is free software: you can redistribute it and/or modify it under
 * the terms of the GNU Affero General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option) any
 * later version.
 */

/**
 * @file ModuleSelfTest_Tests.cpp
 * @brief Calls SelfTest on every reachable module, because nothing else in the product did.
 *
 * Each module writes a SelfTest encoding real invariants - AttachmentScanner's checks PE detection,
 * extension classification and high-risk extension detection in three lines - and every one of them was dead
 * weight, because no code anywhere in the tree called any of them. Two of the three examined by hand had been
 * returning false permanently:
 *
 *   FirefoxAddonScanner::SelfTest  the Critical permission tier was unreachable      fixed 111119b7
 *   AttachmentScanner::SelfTest    magic typing could not match a two-byte header    fixed cf530cf6
 *
 * Neither failure was visible, because a self-test nobody runs is a comment. This file runs them.
 *
 * SCOPE. Four namespaces the duplicate-type sweep showed to be collision-free, so their headers can share one
 * translation unit. Banking, Backup and Privacy cannot be added here - Banking has six ModuleStatus
 * declarations and divergent DetectionAction, DetectionCallback and ValidationResult, and Backup has three
 * ModuleStatus declarations and two incompatible callback aliases, so including two headers from either fails
 * to compile. Those are filed; when they are consolidated, their modules belong in this file too.
 *
 * Initialize is not idempotent (filed 288): the second call returns false, indistinguishable from a genuine
 * failure. So state is tested first, initialisation attempted only if needed, and the state re-checked rather
 * than the return value trusted.
 */

#include "pch.h"

#include <gtest/gtest.h>

#include <string>

#include "Products/Community/PhantomHome/WebProtection/AdBlocker.hpp"
#include "Products/Community/PhantomHome/WebProtection/BrowserProtection.hpp"
#include "Products/Community/PhantomHome/WebProtection/ChromeExtensionScanner.hpp"
#include "Products/Community/PhantomHome/WebProtection/FirefoxAddonScanner.hpp"
#include "Products/Community/PhantomHome/WebProtection/MaliciousDownloadBlocker.hpp"
#include "Products/Community/PhantomHome/WebProtection/PhishingDetector.hpp"
#include "Products/Community/PhantomHome/WebProtection/SafeBrowsingAPI.hpp"
#include "Products/Community/PhantomHome/WebProtection/TrackerBlocker.hpp"

#include "Products/Community/PhantomHome/USB_Protection/BadUSBDetector.hpp"
#include "Products/Community/PhantomHome/USB_Protection/DeviceControlManager.hpp"
#include "Products/Community/PhantomHome/USB_Protection/USBAutorunBlocker.hpp"
#include "Products/Community/PhantomHome/USB_Protection/USBDeviceMonitor.hpp"
#include "Products/Community/PhantomHome/USB_Protection/USBScanner.hpp"

#include "Products/Community/PhantomHome/CryptoMinersProtection/BrowserMinerDetector.hpp"
#include "Products/Community/PhantomHome/CryptoMinersProtection/CPUUsageAnalyzer.hpp"
#include "Products/Community/PhantomHome/CryptoMinersProtection/CryptoMinerDetector.hpp"
#include "Products/Community/PhantomHome/CryptoMinersProtection/GPUMiningDetector.hpp"
#include "Products/Community/PhantomHome/CryptoMinersProtection/PoolConnectionDetector.hpp"

#include "Products/Community/PhantomHome/IoT/IoTDeviceScanner.hpp"
#include "Products/Community/PhantomHome/IoT/SmartHomeProtection.hpp"

#include "Products/Community/PhantomHome/GameMode/GameModeManager.hpp"
#include "Products/Community/PhantomHome/GameMode/GameProcessDetector.hpp"
#include "Products/Community/PhantomHome/GameMode/OverlayProtection.hpp"

namespace {

/// @brief Initialise if needed, then run the module's own self-test.
///
/// Every failure message names the module, because a bare false from one of twenty-one is not actionable.
template <typename T>
void ExpectSelfTestPasses(const char* moduleName, T& instance) {
    if (!instance.IsInitialized()) {
        (void)instance.Initialize();
    }
    ASSERT_TRUE(instance.IsInitialized())
        << moduleName << " could not be initialised, so its self-test was not reached";

    EXPECT_TRUE(instance.SelfTest())
        << moduleName << "::SelfTest returned false. Read the module's own error log line - the self-test "
                         "names which of its checks failed, and it is asserting something the module itself "
                         "considers a requirement.";
}

// ============================================================================
// Web protection
// ============================================================================

TEST(ModuleSelfTest, WebProtectionModulesPassTheirOwnChecks) {
    ExpectSelfTestPasses("AdBlocker", ::ShadowStrike::WebBrowser::AdBlocker::Instance());
    ExpectSelfTestPasses("BrowserProtection", ::ShadowStrike::WebBrowser::BrowserProtection::Instance());
    ExpectSelfTestPasses("ChromeExtensionScanner",
                         ::ShadowStrike::WebBrowser::ChromeExtensionScanner::Instance());
    ExpectSelfTestPasses("FirefoxAddonScanner",
                         ::ShadowStrike::WebBrowser::FirefoxAddonScanner::Instance());
    ExpectSelfTestPasses("MaliciousDownloadBlocker",
                         ::ShadowStrike::WebBrowser::MaliciousDownloadBlocker::Instance());
    ExpectSelfTestPasses("PhishingDetector", ::ShadowStrike::WebBrowser::PhishingDetector::Instance());
    ExpectSelfTestPasses("SafeBrowsingAPI", ::ShadowStrike::WebBrowser::SafeBrowsingAPI::Instance());
    ExpectSelfTestPasses("TrackerBlocker", ::ShadowStrike::WebBrowser::TrackerBlocker::Instance());
}

// ============================================================================
// USB protection
// ============================================================================

TEST(ModuleSelfTest, UsbProtectionModulesPassTheirOwnChecks) {
    ExpectSelfTestPasses("BadUSBDetector", ::ShadowStrike::USB::BadUSBDetector::Instance());
    ExpectSelfTestPasses("DeviceControlManager", ::ShadowStrike::USB::DeviceControlManager::Instance());
    ExpectSelfTestPasses("USBAutorunBlocker", ::ShadowStrike::USB::USBAutorunBlocker::Instance());
    ExpectSelfTestPasses("USBDeviceMonitor", ::ShadowStrike::USB::USBDeviceMonitor::Instance());
    ExpectSelfTestPasses("USBScanner", ::ShadowStrike::USB::USBScanner::Instance());
}

// ============================================================================
// Crypto miner protection
// ============================================================================

TEST(ModuleSelfTest, CryptoMinerModulesPassTheirOwnChecks) {
    ExpectSelfTestPasses("BrowserMinerDetector",
                         ::ShadowStrike::CryptoMiners::BrowserMinerDetector::Instance());
    ExpectSelfTestPasses("CPUUsageAnalyzer", ::ShadowStrike::CryptoMiners::CPUUsageAnalyzer::Instance());
    ExpectSelfTestPasses("CryptoMinerDetector",
                         ::ShadowStrike::CryptoMiners::CryptoMinerDetector::Instance());
    ExpectSelfTestPasses("GPUMiningDetector", ::ShadowStrike::CryptoMiners::GPUMiningDetector::Instance());
    ExpectSelfTestPasses("PoolConnectionDetector",
                         ::ShadowStrike::CryptoMiners::PoolConnectionDetector::Instance());
}

// ============================================================================
// Game mode
// ============================================================================

TEST(ModuleSelfTest, GameModeModulesPassTheirOwnChecks) {
    ExpectSelfTestPasses("GameModeManager", ::ShadowStrike::GameMode::GameModeManager::Instance());
    ExpectSelfTestPasses("GameProcessDetector", ::ShadowStrike::GameMode::GameProcessDetector::Instance());
    ExpectSelfTestPasses("OverlayProtection", ::ShadowStrike::GameMode::OverlayProtection::Instance());
}

// ============================================================================
// IoT
//
// The duplicate-type sweep found no divergence in ShadowStrike::IoT, so these headers share this translation
// unit. IoT/IPLeakProtection is NOT here: its source file has the same NAME as Privacy/IPLeakProtection.cpp,
// so MSBuild writes both to IPLeakProtection.obj and one silently overwrites the other - MSB8027, which then
// leaves Privacy::IsPrivateIP unresolved. That needs an ObjectFileName override or, better, the decision
// about which of the two modules survives. Filed.
// ============================================================================

TEST(ModuleSelfTest, IoTModulesPassTheirOwnChecks) {
    ExpectSelfTestPasses("IoT::IoTDeviceScanner", ::ShadowStrike::IoT::IoTDeviceScanner::Instance());
    ExpectSelfTestPasses("IoT::SmartHomeProtection", ::ShadowStrike::IoT::SmartHomeProtection::Instance());
}

}  // namespace
