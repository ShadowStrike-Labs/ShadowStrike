/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Every ShadowStrike::Banking header in ONE translation unit (tasks 291, 305).
 *
 * The namespace used to declare ModuleStatus six times (one copy with different
 * values), DetectionAction twice with Quarantine and Terminate transposed, and
 * DetectionCallback and ValidationResult as different types under one name. No
 * file included a colliding pair, so the compiler never said so; the first code
 * to coordinate two Banking modules would have failed to build, or - had the
 * #ifndef guard been extended - compiled with include-order-dependent meaning.
 *
 * This file compiling IS the test. The assertions pin what the shared types mean.
 */

#include "pch.h"

#include <gtest/gtest.h>
#include <type_traits>

#include "Products/Community/PhantomHome/Banking/BankingTrojanDetector.hpp"
#include "Products/Community/PhantomHome/Banking/CertificatePinning.hpp"
#include "Products/Community/PhantomHome/Banking/KeyloggerProtection.hpp"
#include "Products/Community/PhantomHome/Banking/ScreenshotBlocker.hpp"
#include "Products/Community/PhantomHome/Banking/SecureBrowser.hpp"
#include "Products/Community/PhantomHome/Banking/TransactionMonitor.hpp"

namespace Banking = ShadowStrike::Banking;

static_assert(static_cast<int>(Banking::ModuleStatus::Paused) == 3);
static_assert(static_cast<int>(Banking::ModuleStatus::Stopped) == 5);
static_assert(static_cast<int>(Banking::ModuleStatus::Error) == 6);
static_assert(static_cast<int>(Banking::DetectionAction::Quarantine) == 3);
static_assert(static_cast<int>(Banking::DetectionAction::Terminate) == 4);

TEST(BankingHeaders, AllSixComposeInOneTranslationUnit) {
    SUCCEED() << "compiled with every Banking header included together";
}